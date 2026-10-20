/* SPDX-License-Identifier: GPL-3.0-or-later
 * General selected-title pre-exec mount gate, based on the validated folder-launch
 * lifecycle bridge. No title constants, game-file writes, or save access.
 */
#include "sm_platform.h"
#include "sm_shellcore_protocol.h"
#include "launch_gate.h"
#include "launch_policy.h"
#include "lifecycle.h"
#include "audit.h"
#include "platform_at.h"
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/ucred.h>
extern bool fl_run_sm_shellcore_hooks_start(void);
extern void fl_run_sm_shellcore_hooks_stop(void);
extern bool fl_run_d3_hooks_are_clear(void);
extern pid_t find_pid_by_name(const char *,bool);
extern int sceSystemServiceLaunchApp(const char *,const char *[],void *);
static FILE *journal;
static pthread_mutex_t gate_lock=PTHREAD_MUTEX_INITIALIZER,log_lock=PTHREAD_MUTEX_INITIALIZER;
static struct fl_gate_policy policy;
static struct fl_module_view plans[FL_MODULE_VIEWS];
static struct fl_game selected;
static size_t nplans;
static int listener=-1;
static volatile sig_atomic_t stopping;
static uid_t peer_uid;
static fl_progress report;
static uint64_t ms(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
void fl_gate_log(const char *fmt,...){pthread_mutex_lock(&log_lock);if(journal){va_list a;va_start(a,fmt);vfprintf(journal,fmt,a);va_end(a);fputc('\n',journal);fflush(journal);fsync(fileno(journal));}pthread_mutex_unlock(&log_lock);}
bool fl_gate_stopping(void){return stopping!=0;}
pid_t fl_gate_find_pid(const char *name,bool exclude){return find_pid_by_name(name,exclude);}
static int readonly(const char *source,const char *target){struct iovec v[]={IOVEC_ENTRY("fstype"),IOVEC_ENTRY("nullfs"),IOVEC_ENTRY("from"),IOVEC_ENTRY(source),IOVEC_ENTRY("fspath"),IOVEC_ENTRY(target)};fl_audit("preexec_mount","begin source=%s target=%s readonly=1",source,target);int rc=nmount(v,IOVEC_SIZE(v),MNT_RDONLY);fl_audit("preexec_mount","end target=%s rc=%d errno=%d",target,rc,rc?errno:0);return rc;}
static int verify_link_view(const struct fl_module_view *view,const char *target){
 DIR *d=opendir(view->source);if(!d)return EIO;int rc=0;size_t files=0;struct dirent *ent;
 while((ent=readdir(d))){if(!strcmp(ent->d_name,".")||!strcmp(ent->d_name,"..")||!strcmp(ent->d_name,FL_MODULE_BASE_NAME))continue;
  char linkpath[FL_PATH],value[512],original[FL_PATH],actual[FL_PATH];struct stat a,b;
  if(++files>4096||fl_join(linkpath,sizeof(linkpath),view->source,ent->d_name)){rc=EIO;break;}
  ssize_t n=readlink(linkpath,value,sizeof(value)-1);if(n<=0||(size_t)n>=sizeof(value)-1){rc=EIO;break;}value[n]=0;
  size_t prefix=strlen(FL_MODULE_BASE_NAME);if(strncmp(value,FL_MODULE_BASE_NAME,prefix)||value[prefix]!='/'||!value[prefix+1]||strchr(value+prefix+1,'/')||!strcmp(value+prefix+1,".")||!strcmp(value+prefix+1,"..")||fl_join(original,sizeof(original),view->base_source,value+prefix+1)||fl_join(actual,sizeof(actual),target,ent->d_name)||lstat(original,&a)||!S_ISREG(a.st_mode)||stat(actual,&b)||!S_ISREG(b.st_mode)||a.st_ino!=b.st_ino||a.st_size!=b.st_size){rc=EIO;break;}
 }
 closedir(d);return rc;
}
static int bind_actual(void){
 char app0[FL_PATH],root[FL_PATH],target[FL_PATH];struct statfs fs;struct stat a,b;
 int n=snprintf(app0,sizeof(app0),"/mnt/sandbox/%s_000/app0",selected.id);
 if(n<0||(size_t)n>=sizeof(app0)||fl_join(root,sizeof(root),"/system_ex/app",selected.id)||statfs(app0,&fs)||strcmp(fs.f_fstypename,"nullfs")||strcmp(fs.f_mntonname,app0)||strcmp(fs.f_mntfromname,root))return EPERM;
 /* All targets must be plain directories in this exact fresh app0 before any mount. */
 for(size_t k=0;k<nplans;k++){
  if(fl_join(target,sizeof(target),app0,plans[k].relative)||lstat(target,&a)||!S_ISDIR(a.st_mode)||statfs(target,&fs)||strcmp(fs.f_mntonname,app0))return EPERM;
 }
 for(size_t k=0;k<nplans;k++){
  if(fl_join(target,sizeof(target),app0,plans[k].relative))return EINVAL;
  fl_gate_log("PREEXEC MOUNT title=%s from=%s target=%s",selected.id,plans[k].source,target);
  if(readonly(plans[k].source,target))return errno?errno:EIO;
  if(fl_lifecycle_track(plans[k].source,target))return EIO;
  if(statfs(target,&fs)||strcmp(fs.f_fstypename,"nullfs")||strcmp(fs.f_mntonname,target)||strcmp(fs.f_mntfromname,plans[k].source)||!(fs.f_flags&MNT_RDONLY)||stat(plans[k].source,&a)||stat(target,&b)||a.st_ino!=b.st_ino)return EIO;
  if(plans[k].base_source[0]){
   char base[FL_PATH];if(fl_join(base,sizeof(base),target,FL_MODULE_BASE_NAME)||lstat(base,&a)||!S_ISDIR(a.st_mode)||readonly(plans[k].base_source,base))return errno?errno:EIO;
   if(fl_lifecycle_track(plans[k].base_source,base))return EIO;
   if(statfs(base,&fs)||strcmp(fs.f_fstypename,"nullfs")||strcmp(fs.f_mntonname,base)||strcmp(fs.f_mntfromname,plans[k].base_source)||!(fs.f_flags&MNT_RDONLY)||verify_link_view(&plans[k],target))return EIO;
   fl_gate_log("PREEXEC LINKS VERIFIED title=%s target=%s base=%s copied_library_bytes=0",selected.id,target,plans[k].base_source);
  }
  fl_gate_log("PREEXEC VERIFIED title=%s target=%s readonly=1 inode=%llu",selected.id,target,(unsigned long long)b.st_ino);
 }
 return 0;
}
static int request(const sm_shellcore_request_t *q){
 if(q->magic!=SM_SHELLCORE_PROTOCOL_MAGIC||q->version!=SM_SHELLCORE_PROTOCOL_VERSION||!memchr(q->title_id,0,sizeof(q->title_id)))return EINVAL;
 pthread_mutex_lock(&gate_lock);int rc=fl_gate_request(&policy,q->operation,q->title_id,q->thread_id,ms());
 if(!rc&&q->operation==3){report("Gercek app0 kutuphaneleri oyun baslamadan baglaniyor...");rc=bind_actual();policy.bound=rc? -1:1;if(!rc)report("Gercek app0 kutuphaneleri salt okunur olarak dogrulandi.");}
 fl_gate_log("GATE op=%u title=%s thread=%llu status=%d bound=%d",q->operation,q->title_id,(unsigned long long)q->thread_id,rc,policy.bound);
 pthread_mutex_unlock(&gate_lock);return rc;
}
static int transfer(int fd,void *data,size_t size,int sending){unsigned char *p=data;while(size){ssize_t n=sending?write(fd,p,size):read(fd,p,size);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;p+=n;size-=(size_t)n;}return 0;}
static void *serve(void *unused){(void)unused;while(!stopping){int fd=accept(listener,NULL,NULL);if(fd<0){if(errno==EINTR)continue;break;}struct timeval timeout={3,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));struct xucred cred;socklen_t len=sizeof(cred);sm_shellcore_request_t q={0};int32_t status=EPERM;
 if(!getsockopt(fd,0,LOCAL_PEERCRED,&cred,&len)&&len==sizeof(cred)&&cred.cr_version==XUCRED_VERSION&&(cred.cr_uid==peer_uid||cred.cr_uid==0)&&!transfer(fd,&q,sizeof(q),0))status=request(&q);
 transfer(fd,&status,sizeof(status),1);close(fd);}return NULL;}
static int transport_check(void){int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return -1;struct timeval tv={3,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));struct sockaddr_un sa={0};sa.sun_family=AF_UNIX;strcpy(sa.sun_path,SM_SHELLCORE_SOCKET_PATH);sa.sun_len=(uint8_t)(strlen(sa.sun_path)+3);sm_shellcore_request_t q={.magic=SM_SHELLCORE_PROTOCOL_MAGIC,.version=SM_SHELLCORE_PROTOCOL_VERSION,.operation=99,.thread_id=1};int32_t response=0;int ok=!connect(fd,(struct sockaddr *)&sa,sa.sun_len)&&!transfer(fd,&q,sizeof(q),1)&&!transfer(fd,&response,sizeof(response),0)&&response==EINVAL;close(fd);return ok?0:-1;}
int fl_gate_launch(const struct fl_game *game,const struct fl_module_view *views,size_t count,int user,fl_progress progress,int *launch_rc){
 if(!game||!views||!count||count>FL_MODULE_VIEWS||!launch_rc||!fl_title_id(game->id)||find_pid_by_name("eboot.bin",true)!=0)return -1;
 struct stat st;if(!lstat(SM_SHELLCORE_SOCKET_PATH,&st)||errno!=ENOENT||!lstat("/system_tmp/shadowmount.sock",&st)||errno!=ENOENT)return -1;
 selected=*game;memcpy(plans,views,count*sizeof(*views));nplans=count;report=progress;stopping=0;listener=-1;memset(&policy,0,sizeof(policy));memcpy(policy.title,game->id,10);policy.expires=ms()+60000;
 for(size_t k=0;k<count;k++){char prefix[FL_PATH],canonical[FL_PATH];snprintf(prefix,sizeof(prefix),"%s/%s/",FL_MODULE_OWNED_ROOT,game->id);if((strcmp(views[k].relative,"prx")&&strcmp(views[k].relative,"sce_module"))||strncmp(views[k].source,prefix,strlen(prefix))||!realpath(views[k].source,canonical)||strcmp(canonical,views[k].source))return -1;
  if(views[k].base_source[0]){char expected[FL_PATH];if(fl_join(expected,sizeof(expected),game->path,views[k].relative)||strcmp(expected,views[k].base_source)||!realpath(expected,canonical)||strcmp(canonical,expected))return -1;}
 }
 journal=fopen("/data/ps4-folder-loader-launch-gate.log","a");if(!journal)return -1;fl_gate_log("BEGIN title=%s plans=%zu",selected.id,nplans);
 int rc=-1,owned=0,server=0,attempted=0;pthread_t thread;pid_t shell=find_pid_by_name("SceShellCore",true);if(shell<=0)goto done;peer_uid=kernel_get_ucred_uid(shell);if(peer_uid==(uid_t)-1)goto done;
 listener=socket(AF_UNIX,SOCK_STREAM,0);if(listener<0)goto done;struct sockaddr_un sa={0};sa.sun_family=AF_UNIX;strcpy(sa.sun_path,SM_SHELLCORE_SOCKET_PATH);sa.sun_len=(uint8_t)(strlen(sa.sun_path)+3);
 if(bind(listener,(struct sockaddr *)&sa,sa.sun_len))goto done;owned=1;if(chown(sa.sun_path,peer_uid,(gid_t)-1)||chmod(sa.sun_path,0600)||listen(listener,8)||pthread_create(&thread,NULL,serve,NULL))goto done;server=1;
 if(transport_check()||!fl_lifecycle_busy())goto done;attempted=1;if(!fl_run_sm_shellcore_hooks_start())goto done;
 struct context{uint32_t size,user,options;uint64_t crash;uint32_t check;};_Static_assert(sizeof(struct context)==32,"launch ABI");struct context context={sizeof(context),(uint32_t)user,0,0,0};const char *argv[]={NULL};
 progress("Oyun gercek app0 icin tek kullanimlik yonlendirmeyle baslatiliyor...");fl_audit("launch","single_dispatch title=%s preexec_gate=1",selected.id);*launch_rc=sceSystemServiceLaunchApp(selected.id,argv,&context);fl_gate_log("LAUNCH rc=0x%08x",(unsigned)*launch_rc);
 for(unsigned tick=0;tick<40;tick++){pthread_mutex_lock(&gate_lock);int complete=policy.reported;pthread_mutex_unlock(&gate_lock);if(complete||*launch_rc<0)break;usleep(250000);}
 pthread_mutex_lock(&gate_lock);rc=policy.bound==1&&policy.reported&&policy.success?0:-1;pthread_mutex_unlock(&gate_lock);
 done:
 if(attempted){for(;;){fl_run_sm_shellcore_hooks_stop();if(fl_run_d3_hooks_are_clear())break;fl_gate_log("Waiting for runtime entrypoint restoration");usleep(500000);}}
 stopping=1;if(listener>=0){shutdown(listener,SHUT_RDWR);close(listener);listener=-1;}if(server)pthread_join(thread,NULL);if(owned)unlink(SM_SHELLCORE_SOCKET_PATH);
 fl_gate_log("END result=%d hooks_restored=1; owned mounts monitored by process-exit lifecycle",rc);fclose(journal);journal=NULL;return rc;
}
