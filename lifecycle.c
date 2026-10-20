/* SPDX-License-Identifier: GPL-3.0-or-later
 * Process-exit cleanup for loader-owned mounts. No forced unmounts, game
 * writes, save access, or title-specific rules. Records exist only in RAM.
 */
#include "lifecycle.h"
#include "engine.h"
#include "audit.h"
#ifdef FL_HOST
int fl_lifecycle_busy(void){return 0;}
int fl_lifecycle_phase(void){return 0;}
int fl_lifecycle_begin(const struct fl_game *game){(void)game;return 0;}
int fl_lifecycle_track(const char *source,const char *target){(void)source;(void)target;return 0;}
void fl_lifecycle_dispatched(void){}
#else
#ifdef FL_LIFECYCLE_TEST
#include "tests/lifecycle_fixture.h"
#else
#include "sm_platform.h"
#endif
#include "lifecycle_policy.h"
#include "mount_snapshot.h"
#include <pthread.h>
#include <sys/event.h>
#include <sys/sysctl.h>
#define LAYERS 8
struct layer {char source[FL_PATH],target[FL_PATH];fsid_t fsid;};
static struct {int active,dispatched,queue,phase;char title[10];struct fl_game game;size_t count;struct layer layers[LAYERS];} session;
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static void note(const char *stage,int value){fl_audit("lifecycle","title=%s stage=%s value=%d",session.title,stage,value);FILE *f=fopen("/data/ps4-folder-loader-lifecycle.log","a");if(f){fprintf(f,"title=%s stage=%s value=%d\n",session.title,stage,value);fflush(f);fsync(fileno(f));fclose(f);}}
int fl_lifecycle_busy(void){pthread_mutex_lock(&lock);int active=session.active;pthread_mutex_unlock(&lock);return active;}
int fl_lifecycle_phase(void){pthread_mutex_lock(&lock);int phase=session.phase;pthread_mutex_unlock(&lock);return phase;}
/* Enumerate the title, rather than treating an unrelated PID or reused PID as
 * the game. Any incomplete process snapshot blocks cleanup. */
static int live_title(pid_t *found,uint32_t *app,pid_t exited){
 int mib[4]={CTL_KERN,KERN_PROC,KERN_PROC_PROC,0};size_t bytes=0;*found=0;
 if(sysctl(mib,4,NULL,&bytes,NULL,0)||!bytes)return -1;
 unsigned char *buf=malloc(bytes);if(!buf)return -1;
 if(sysctl(mib,4,buf,&bytes,NULL,0)){free(buf);return -1;}
 size_t at=0;int result=0;
 while(at<bytes){int size;pid_t pid;if(bytes-at<4){result=-1;break;}memcpy(&size,buf+at,4);
  if(size<=447||(size_t)size>bytes-at){result=-1;break;}
  const char *name=(char*)buf+at+447;size_t avail=(size_t)size-447;if(strnlen(name,avail)==avail){result=-1;break;}
  memcpy(&pid,buf+at+72,sizeof(pid));
  if(pid!=exited&&!strcmp(name,"eboot.bin")){app_info_t info={0};if(sceKernelGetAppInfo(pid,&info)){result=-1;break;}
   if(!memcmp(info.title_id,session.title,10)){*found=pid;*app=info.app_id;result=1;break;}}
  at+=(size_t)size;
 }
 free(buf);return result;
}
static int sandboxes(void){DIR *dir=opendir("/mnt/sandbox");if(!dir)return -1;struct dirent *ent;int found=0;errno=0;
 while((ent=readdir(dir)))if(!strncmp(ent->d_name,session.title,9)&&ent->d_name[9]=='_'){found=1;break;}
 int err=!ent&&errno;closedir(dir);return err?-1:found;
}
/* Snapshot mount identities before every operation. A missing exact record is
 * already gone. A replacement/foreign descendant blocks all further cleanup. */
static int release_top(void){
 if(!session.count)return 0;struct layer *owned=&session.layers[session.count-1];
 if(!strncmp(owned->target,"/system_ex/app/",15)&&sandboxes()!=0)return -1;
 struct statfs *mounts=NULL;int n=fl_mount_snapshot(&mounts);if(n<=0)return -1;int present=0;
 for(int i=0;i<n;i++){
  struct statfs *f=&mounts[i];if(!strcmp(f->f_mntonname,owned->target)){
   if(!memcmp(&f->f_fsid,&owned->fsid,sizeof(fsid_t)))present=1;
  }else if(!strncmp(f->f_mntonname,owned->target,strlen(owned->target))&&f->f_mntonname[strlen(owned->target)]=='/'){free(mounts);return -1;}
 }
 free(mounts);
 /* A legacy mount can be hidden beneath ours at the SAME path. Inspect
  * the currently visible layer, and remove only our recorded filesystem. */
 if(present){struct statfs visible;if(statfs(owned->target,&visible)||!fl_mount_matches(visible.f_fstypename,visible.f_mntfromname,visible.f_mntonname,owned->source,owned->target,(visible.f_flags&MNT_RDONLY)!=0,!memcmp(&visible.f_fsid,&owned->fsid,sizeof(fsid_t))))return -1;}
 if(present){fl_audit("unmount","begin source=%s target=%s flags=0",owned->source,owned->target);if(unmount(owned->target,0)){fl_audit("unmount","deferred target=%s errno=%d",owned->target,errno);return -1;}fl_audit("unmount","end target=%s rc=0",owned->target);}
 note(present?"unmounted":"already_absent",0);memset(owned,0,sizeof(*owned));session.count--;return 0;
}
static void *watch(void *unused){
 (void)unused;int kq=session.queue,observed_exit=0;pid_t watched=0,exited=0;
 for(;;){
  pthread_mutex_lock(&lock);int dispatched=session.dispatched;pthread_mutex_unlock(&lock);
  pid_t pid=0;uint32_t app=0;int live=live_title(&pid,&app,exited);
  if(live>0&&pid!=watched&&pid!=exited){
   if(kq<0){note("kqueue_unavailable_cleanup_blocked",errno);}
   else{struct kevent ev;EV_SET(&ev,(uintptr_t)pid,EVFILT_PROC,EV_ADD|EV_ENABLE|EV_ONESHOT,NOTE_EXIT,0,NULL);
    if(!kevent(kq,&ev,1,NULL,0,NULL)){watched=pid;observed_exit=0;pthread_mutex_lock(&lock);session.phase=2;pthread_mutex_unlock(&lock);note("watch_pid",pid);note("app_id",(int)app);}}
  }
  if(kq>=0&&watched){struct kevent ev;struct timespec wait={0,100000000};int got=kevent(kq,NULL,0,&ev,1,&wait);
   if(got==1&&ev.filter==EVFILT_PROC&&ev.ident==(uintptr_t)watched&&(ev.fflags&NOTE_EXIT)&&!(ev.flags&EV_ERROR)){observed_exit=1;exited=watched;pthread_mutex_lock(&lock);session.phase=3;pthread_mutex_unlock(&lock);note("NOTE_EXIT",watched);watched=0;}}
  /* No observed PID/exit: preserve mounts and block a second launch. Never
   * infer exit from an arbitrary timeout after a queued launch. */
  if(dispatched&&observed_exit){
   live=live_title(&pid,&app,exited);
   if(fl_cleanup_allowed(observed_exit,live>0,live>=0,1,0)){
    pthread_mutex_lock(&lock);while(session.count&&!release_top()){}size_t remain=session.count;pthread_mutex_unlock(&lock);
    if(!remain){int sandbox=sandboxes();if(sandbox==0){pthread_mutex_lock(&lock);note("sandbox_gone_session_complete",0);session.active=0;session.phase=0;pthread_mutex_unlock(&lock);break;}}
   }
  }
  /* No mounts were added and dispatch completed: no cleanup debt. */
  pthread_mutex_lock(&lock);int empty=dispatched&&!session.count&&!watched&&!observed_exit;if(empty){note("no_owned_layers",0);session.active=0;session.phase=0;}pthread_mutex_unlock(&lock);if(empty)break;
  usleep(observed_exit?250000:10000);
 }
 if(kq>=0)close(kq);return NULL;
}
int fl_lifecycle_begin(const struct fl_game *game){
 const char *title=game?game->id:"";if(!fl_title_id(title))return -1;pthread_mutex_lock(&lock);if(session.active){pthread_mutex_unlock(&lock);return -1;}
 int probe=kqueue();if(probe<0){pthread_mutex_unlock(&lock);return -1;}
 memset(&session,0,sizeof(session));memcpy(session.title,title,10);session.game=*game;session.active=1;session.phase=1;session.queue=probe;pthread_t thread;
 int rc=pthread_create(&thread,NULL,watch,NULL);if(rc){session.active=0;session.phase=0;close(probe);}else pthread_detach(thread);pthread_mutex_unlock(&lock);return rc?-1:0;
}
int fl_lifecycle_track(const char *source,const char *target){
 pthread_mutex_lock(&lock);int rc=-1;struct statfs fs;char a[FL_PATH],b[FL_PATH];
 snprintf(a,sizeof(a),"/mnt/sandbox/%s_000/app0/",session.title);snprintf(b,sizeof(b),"/system_ex/app/%s",session.title);
 int allowed=!strncmp(target,a,strlen(a))||(!strncmp(target,b,strlen(b))&&(!target[strlen(b)]||target[strlen(b)]=='/'));
 if(allowed&&session.active&&session.count<LAYERS&&strlen(source)<FL_PATH&&strlen(target)<FL_PATH&&!statfs(target,&fs)&&!strcmp(fs.f_fstypename,"nullfs")&&!strcmp(fs.f_mntonname,target)&&!strcmp(fs.f_mntfromname,source)&&(fs.f_flags&MNT_RDONLY)){
  struct layer *l=&session.layers[session.count++];strcpy(l->source,source);strcpy(l->target,target);l->fsid=fs.f_fsid;note("tracked",0);rc=0;
 }
 pthread_mutex_unlock(&lock);return rc;
}
void fl_lifecycle_dispatched(void){pthread_mutex_lock(&lock);session.dispatched=1;pthread_mutex_unlock(&lock);}
#endif
