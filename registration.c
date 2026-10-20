/* GPL-3.0-or-later. Register only the Folder Loader media shortcut.
 * No PKG APIs, batch installer, game/save writes, or game launch.
 */
#include "sm_platform.h"
#include "sm_runtime.h"
#include "sm_shellcore_hooks.h"
#include "sm_shellcore_protocol.h"
#include "engine.h"
#include <dirent.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/ucred.h>
#include "platform_at.h"
static char game_id[10];
#include "registration_policy.h"
static FILE *logfile;
static pthread_mutex_t log_mutex=PTHREAD_MUTEX_INITIALIZER,policy_mutex=PTHREAD_MUTEX_INITIALIZER;
static struct reg_policy policy;
static volatile sig_atomic_t stopping;
static int listener=-1,foreground_user;
static uid_t bridge_uid;
extern bool d3_hooks_are_clear(void);
extern int sceSystemServiceLaunchApp(const char*,const char*[],void*);
extern int sceUserServiceGetForegroundUser(int*);
void log_debug(const char *format,...){pthread_mutex_lock(&log_mutex);if(logfile){va_list a;va_start(a,format);vfprintf(logfile,format,a);va_end(a);fputc('\n',logfile);fflush(logfile);}pthread_mutex_unlock(&log_mutex);}
bool should_stop_requested(void){return stopping!=0;}
struct launch_context {uint32_t size,user,options;uint64_t crash;uint32_t check;};
_Static_assert(sizeof(struct launch_context)==32,"launch carrier ABI");
int d3_registration_carrier(void){struct launch_context c={sizeof(c),(uint32_t)foreground_user,0,0,0};const char *args[]={NULL};return sceSystemServiceLaunchApp(game_id,args,&c);}
pid_t find_pid_by_name(const char *name, bool exclude_self) {
    int mib[4]={CTL_KERN,KERN_PROC,KERN_PROC_PROC,0}; size_t bytes=0;
    if (sysctl(mib,4,NULL,&bytes,NULL,0) || !bytes) return -1;
    unsigned char *buf=malloc(bytes); if (!buf) return -1;
    if (sysctl(mib,4,buf,&bytes,NULL,0)) { free(buf); return -1; }
    pid_t found=0; size_t pos=0;
    while (pos+4<=bytes) {
        int size; pid_t pid; memcpy(&size,buf+pos,4);
        if (size<=447 || (size_t)size>bytes-pos) { found=-1; break; }
        memcpy(&pid,buf+pos+72,sizeof(pid));
        const char *comm=(char *)buf+pos+447; size_t avail=(size_t)size-447;
        if (strnlen(comm,avail)==avail) { found=-1; break; }
        if ((!exclude_self || pid!=getpid()) && !strcmp(comm,name)) { found=pid; break; }
        pos+=(size_t)size;
    }
    free(buf); return found;
}
static bool transfer(int fd,void *data,size_t n,bool sending) {
    unsigned char *p=data;
    while(n){ssize_t r=sending?write(fd,p,n):read(fd,p,n);
        if(r<0 && errno==EINTR)continue;if(r<=0)return false;p+=r;n-=(size_t)r;}
    return true;
}
static void *serve(void *unused) {
    (void)unused;
    while(!stopping) {
        int fd=accept(listener,NULL,NULL);if(fd<0){if(errno==EINTR)continue;break;}
        struct timeval tv={3,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
        setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
        sm_shellcore_request_t q={0};int32_t status=EPERM;
        struct xucred cred; socklen_t cred_size=sizeof(cred);
        if(!getsockopt(fd,0,LOCAL_PEERCRED,&cred,&cred_size) &&
           cred_size==sizeof(cred) && cred.cr_version==XUCRED_VERSION &&
           (cred.cr_uid==bridge_uid||cred.cr_uid==0) && transfer(fd,&q,sizeof(q),false) &&
           q.magic==SM_SHELLCORE_PROTOCOL_MAGIC && q.version==SM_SHELLCORE_PROTOCOL_VERSION) {
            pthread_mutex_lock(&policy_mutex);
            status=reg_request(&policy,q.operation,game_id,q.title_id,q.thread_id);
            pthread_mutex_unlock(&policy_mutex);
            log_debug("BRIDGE op=%u thread=%llu status=%d",q.operation,(unsigned long long)q.thread_id,status);
        }
        transfer(fd,&status,sizeof(status),true);close(fd);
    }
    return NULL;
}
static int setup_socket(void) {
    struct sockaddr_un sa={0};sa.sun_family=AF_UNIX;
    strcpy(sa.sun_path,SM_SHELLCORE_SOCKET_PATH);sa.sun_len=(uint8_t)(strlen(sa.sun_path)+3);
    listener=socket(AF_UNIX,SOCK_STREAM,0);if(listener<0)return -1;
    if(bind(listener,(struct sockaddr *)&sa,sa.sun_len))return -1;
    if(chown(sa.sun_path,bridge_uid,(gid_t)-1)||chmod(sa.sun_path,0600)||listen(listener,8)){unlink(sa.sun_path);return -1;}
    return 0;
}
static int check_transport(void) {
    int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return -1;
    struct timeval tv={3,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
    struct sockaddr_un sa={0};sa.sun_family=AF_UNIX;
    strcpy(sa.sun_path,SM_SHELLCORE_SOCKET_PATH);sa.sun_len=(uint8_t)(strlen(sa.sun_path)+3);
    sm_shellcore_request_t q={.magic=SM_SHELLCORE_PROTOCOL_MAGIC,.version=SM_SHELLCORE_PROTOCOL_VERSION,.operation=99,.thread_id=1};
    strcpy(q.title_id,game_id);int32_t reply=0;
    bool ok=!connect(fd,(struct sockaddr *)&sa,sa.sun_len) && transfer(fd,&q,sizeof(q),true) &&
        transfer(fd,&reply,sizeof(reply),false) && reply==EPERM;
    close(fd);return ok?0:-1;
}

static int new_file(const char *path,const void *data,size_t n){
 int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0644);if(fd<0)return -1;const unsigned char *p=data;int rc=0;
 while(n){ssize_t w=write(fd,p,n);if(w<0&&errno==EINTR)continue;if(w<=0){rc=-1;break;}p+=w;n-=(size_t)w;}
 if(fsync(fd))rc=-1;close(fd);return rc;
}
static int ro_bind(const char *from,const char *to){struct iovec v[]={IOVEC_ENTRY("fstype"),IOVEC_ENTRY("nullfs"),IOVEC_ENTRY("from"),IOVEC_ENTRY(from),IOVEC_ENTRY("fspath"),IOVEC_ENTRY(to)};return nmount(v,IOVEC_SIZE(v),MNT_RDONLY);}
static int system_ex_mode(bool readonly){struct statfs fs;if(statfs("/system_ex",&fs)||strcmp(fs.f_mntonname,"/system_ex"))return -1;struct iovec v[]={IOVEC_ENTRY("fstype"),IOVEC_ENTRY(fs.f_fstypename),IOVEC_ENTRY("fspath"),IOVEC_ENTRY("/system_ex"),IOVEC_ENTRY("from"),IOVEC_ENTRY(fs.f_mntfromname)};if(nmount(v,IOVEC_SIZE(v),MNT_UPDATE|(readonly?MNT_RDONLY:0)))return -1;return statfs("/system_ex",&fs)||((fs.f_flags&MNT_RDONLY)!=0)!=readonly?-1:0;}
static int mountpoint(const char *path){struct statfs fs;if(statfs("/system_ex",&fs))return -1;bool ro=(fs.f_flags&MNT_RDONLY)!=0;if(ro&&system_ex_mode(false))return -1;int rc=mkdir(path,0755);if(ro&&system_ex_mode(true))return -1;return rc;}
/* Copy metadata only into exclusively new directories; original files are read-only. */
static int metadata_copy(const char *source,const char *dest,unsigned depth,uint64_t *total,unsigned *files){
 if(depth>4)return -1;int in=open(source,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(in<0)return -1;DIR *d=fdopendir(in);if(!d){close(in);return -1;}int rc=0;struct dirent *e;
 while((e=readdir(d))){if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;if(!strcmp(e->d_name,"param.json")){rc=-1;break;}char a[FL_PATH],b[FL_PATH];struct stat st;
  if(fl_join(a,sizeof(a),source,e->d_name)||fl_join(b,sizeof(b),dest,e->d_name)||fstatat(in,e->d_name,&st,AT_SYMLINK_NOFOLLOW)){rc=-1;break;}
  if(S_ISDIR(st.st_mode)){if(mkdir(b,0755)||metadata_copy(a,b,depth+1,total,files)){rc=-1;break;}}
  else if(S_ISREG(st.st_mode)&&st.st_size>=0&&st.st_size<=32*1024*1024&&*total+(uint64_t)st.st_size<=256*1024*1024&&++*files<=1024){
   int fd=openat(in,e->d_name,O_RDONLY|O_NOFOLLOW);if(fd<0){rc=-1;break;}struct stat actual;if(fstat(fd,&actual)||actual.st_dev!=st.st_dev||actual.st_ino!=st.st_ino||actual.st_size!=st.st_size){close(fd);rc=-1;break;}
   size_t n=(size_t)st.st_size,at=0;unsigned char *data=malloc(n?n:1);if(!data){close(fd);rc=-1;break;}
   while(at<n){ssize_t r=read(fd,data+at,n-at);if(r<0&&errno==EINTR)continue;if(r<=0)break;at+=(size_t)r;}close(fd);rc=at==n?new_file(b,data,n):-1;free(data);*total+=n;if(rc)break;
  }else{rc=-1;break;}
 }closedir(d);return rc;
}
static void quoted(FILE *f,const char *s){fputc('"',f);for(const unsigned char *p=(const unsigned char*)s;*p;p++){if(*p=='"'||*p=='\\')fputc('\\',f);if(*p<32)fprintf(f,"\\u%04x",*p);else fputc(*p,f);}fputc('"',f);}
static int write_json(const char *path,const struct fl_game *game){int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0644);if(fd<0)return -1;FILE *f=fdopen(fd,"w");if(!f){close(fd);return -1;}fprintf(f,"{\"titleId\":\"%s\",\"titleName\":",game->id);quoted(f,game->title);fputs(",\"localizedParameters\":{\"defaultLanguage\":\"en-US\",\"en-US\":{\"titleName\":",f);quoted(f,game->title);fputs("}}}\n",f);int rc=fflush(f)||ferror(f)||fsync(fd);if(fclose(f))rc=-1;return rc;}
int fl_register_folder(const struct fl_game *game,fl_progress progress){
 int result=-1;bool socket_owned=false,server=false,hook_attempted=false;pthread_t thread;struct stat st;
 char app[FL_PATH],meta[FL_PATH],root[FL_PATH],priv[FL_PATH],src[FL_PATH],reg[FL_PATH],path[FL_PATH];
 if(!fl_title_id(game->id)||fl_join(app,sizeof(app),"/user/app",game->id)||fl_join(meta,sizeof(meta),"/user/appmeta",game->id)||fl_join(root,sizeof(root),"/system_ex/app",game->id)||fl_join(priv,sizeof(priv),"/system_data/priv/appmeta",game->id)||fl_join(src,sizeof(src),game->path,"sce_sys")||fl_join(reg,sizeof(reg),app,"sce_sys"))return -1;
 const char *targets[]={app,meta,root,priv};for(size_t i=0;i<4;i++)if(!lstat(targets[i],&st)||errno!=ENOENT){progress("Bu oyun icin mevcut veya yarim kayit var. Uzerine yazilmadi; once cakisma incelenmeli.");return -1;}
 const char *storage[]={"/user/patch","/mnt/ext1/user/app","/mnt/ext1/user/patch","/mnt/ext0/user/app","/mnt/ext0/user/patch"};for(size_t i=0;i<5;i++){if(fl_join(path,sizeof(path),storage[i],game->id)||!lstat(path,&st)||errno!=ENOENT){progress("Ayni oyun baska kurulum veya guncelleme kaydina sahip; degistirilmedi.");return -1;}}
 if(find_pid_by_name("eboot.bin",true)!=0||!lstat(SM_SHELLCORE_SOCKET_PATH,&st)||errno!=ENOENT)return -1;
 snprintf(game_id,sizeof(game_id),"%s",game->id);memset(&policy,0,sizeof(policy));stopping=0;listener=-1;
 logfile=fopen("/data/ps4-folder-loader-register.log","a");if(!logfile)return -1;log_debug("BEGIN generic title=%s source=%s",game->id,game->path);
 progress("Secilen oyun icin klasor kaydi hazirlaniyor...");
 if(mountpoint(root)||mkdir(app,0755)||mkdir(reg,0755)||mkdir(meta,0755)||mkdir(priv,0755))goto done;
 if(fl_join(path,sizeof(path),app,"ps4-folder-loader.pending")||new_file(path,game->path,strlen(game->path)))goto done;
 uint64_t total=0;unsigned files=0;if(metadata_copy(src,reg,0,&total,&files))goto done;
 /* Native registration consumes the mirrored metadata tree. */
 total=0;files=0;if(metadata_copy(src,meta,0,&total,&files))goto done;
 if(fl_join(path,sizeof(path),reg,"param.json")||write_json(path,game)||fl_join(path,sizeof(path),meta,"param.json")||write_json(path,game)||fl_join(path,sizeof(path),app,"mount.lnk")||new_file(path,game->path,strlen(game->path)))goto done;
 if(ro_bind(game->path,root)||fl_private_metadata(game,reg))goto done;
 if(sceUserServiceGetForegroundUser(&foreground_user)<0||foreground_user<=0)goto done;
 pid_t shell=find_pid_by_name("SceShellCore",true);if(shell<=0)goto done;bridge_uid=kernel_get_ucred_uid(shell);if(bridge_uid==(uid_t)-1)goto done;
 if(setup_socket())goto done;socket_owned=true;if(pthread_create(&thread,NULL,serve,NULL))goto done;server=true;
 if(check_transport())goto done;hook_attempted=true;if(!sm_shellcore_hooks_start())goto done;
 pthread_mutex_lock(&policy_mutex);policy.armed=true;pthread_mutex_unlock(&policy_mutex);
 int rc=-1;bool dispatched=sm_shellcore_install_title_dir(game_id,"/user/app/",&rc);
 pthread_mutex_lock(&policy_mutex);policy.armed=false;bool confirmed=policy.claimed&&policy.reported&&policy.success;pthread_mutex_unlock(&policy_mutex);
 log_debug("TitleDir title=%s dispatched=%d rc=0x%08x confirmed=%d",game_id,dispatched,(unsigned)rc,confirmed);
 if(dispatched&&confirmed&&(rc==0||(uint32_t)rc==0x80990002u)){
  if(fl_join(path,sizeof(path),app,"ps4-folder-loader.owner")||new_file(path,"PS4FL-GAME-v1\n",14))goto done;
  if(fl_join(path,sizeof(path),app,"ps4-folder-loader.pending")||unlink(path))goto done;result=0;
 }
 done:
 if(hook_attempted){for(;;){sm_shellcore_hooks_stop();if(d3_hooks_are_clear())break;log_debug("Waiting for entrypoint restoration");usleep(500000);}}
 stopping=1;if(listener>=0){shutdown(listener,SHUT_RDWR);close(listener);listener=-1;}if(server)pthread_join(thread,NULL);if(socket_owned)unlink(SM_SHELLCORE_SOCKET_PATH);
 log_debug("END result=%d; source/save unchanged; new metadata retained",result);fclose(logfile);logfile=NULL;
 if(result)progress("Klasor kaydi tamamlanamadi. Kismi kayit korundu; gunluk incelenmeli.");return result;
}
/* Refresh a verified pre-existing folder registration. No uninstall or delete. */
int fl_refresh_folder(const struct fl_game *game,fl_progress progress){
 int result=-1;bool socket_owned=false,server=false,hook_attempted=false;pthread_t thread;struct stat st;char reg[FL_PATH],meta[FL_PATH],path[FL_PATH];
 if(!fl_title_id(game->id)||find_pid_by_name("eboot.bin",true)!=0||!lstat(SM_SHELLCORE_SOCKET_PATH,&st)||errno!=ENOENT||!lstat("/system_tmp/shadowmount.sock",&st)||errno!=ENOENT)return -1;
 if(fl_join(path,sizeof(path),"/user/app",game->id)||fl_join(reg,sizeof(reg),path,"sce_sys")||fl_join(meta,sizeof(meta),"/user/appmeta",game->id))return -1;
 snprintf(game_id,sizeof(game_id),"%s",game->id);memset(&policy,0,sizeof(policy));stopping=0;listener=-1;
 logfile=fopen("/data/ps4-folder-loader-register.log","a");if(!logfile)return -1;log_debug("BEGIN refresh verified folder title=%s source=%s; no uninstall",game->id,game->path);
 const char *dirs[]={reg,meta};for(size_t i=0;i<2;i++){if(fl_join(path,sizeof(path),dirs[i],"param.json"))goto done;if(lstat(path,&st)){if(errno!=ENOENT||write_json(path,game))goto done;log_debug("NEW ABSENT JSON %s",path);}else if(!S_ISREG(st.st_mode))goto done;}
 if(fl_private_metadata(game,reg)){log_debug("Private registry preparation failed errno=%d",errno);goto done;}
 if(sceUserServiceGetForegroundUser(&foreground_user)<0||foreground_user<=0)goto done;
 pid_t shell=find_pid_by_name("SceShellCore",true);if(shell<=0)goto done;bridge_uid=kernel_get_ucred_uid(shell);if(bridge_uid==(uid_t)-1)goto done;
 if(setup_socket())goto done;socket_owned=true;if(pthread_create(&thread,NULL,serve,NULL))goto done;server=true;
 if(check_transport())goto done;hook_attempted=true;if(!sm_shellcore_hooks_start())goto done;
 pthread_mutex_lock(&policy_mutex);policy.armed=true;pthread_mutex_unlock(&policy_mutex);
 int rc=-1;bool dispatched=sm_shellcore_install_title_dir(game_id,"/user/app/",&rc);
 pthread_mutex_lock(&policy_mutex);policy.armed=false;bool confirmed=policy.claimed&&policy.reported&&policy.success;pthread_mutex_unlock(&policy_mutex);
 log_debug("REFRESH TitleDir title=%s dispatched=%d rc=0x%08x confirmed=%d",game_id,dispatched,(unsigned)rc,confirmed);
 if(dispatched&&confirmed&&(rc==0||(uint32_t)rc==0x80990002u)){
  char stamp[128];snprintf(stamp,sizeof(stamp),"/data/ps4-folder-loader-refreshed-%s",game_id);if(new_file(stamp,game->path,strlen(game->path)))goto done;result=0;
 }
 done:
 if(hook_attempted){for(;;){sm_shellcore_hooks_stop();if(d3_hooks_are_clear())break;log_debug("Waiting for refresh entrypoint restoration");usleep(500000);}}
 stopping=1;if(listener>=0){shutdown(listener,SHUT_RDWR);close(listener);listener=-1;}if(server)pthread_join(thread,NULL);if(socket_owned)unlink(SM_SHELLCORE_SOCKET_PATH);
 log_debug("END refresh result=%d; no source/save edits",result);fclose(logfile);logfile=NULL;
 if(result)progress("Klasor kaydi yenilenemedi; oyun baslatilmadi. Gunluk incelenmeli.");return result;
}
