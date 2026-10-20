/* GPL-3.0-or-later. Register only the Goda media shortcut.
 * No PKG APIs, batch installer, game/save writes, or game launch.
 */
#include "sm_platform.h"
#include "sm_runtime.h"
#include "sm_shellcore_hooks.h"
#include "sm_shellcore_protocol.h"
#include "policy.h"
#include "icon.h"
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/ucred.h>
#define GAME "PFLD00001"
#define APP "/user/app/" GAME
#define META "/user/appmeta/" GAME
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
int d3_registration_carrier(void){struct launch_context c={sizeof(c),(uint32_t)foreground_user,0,0,0};const char *args[]={NULL};return sceSystemServiceLaunchApp(GAME,args,&c);}
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
            status=reg_request(&policy,q.operation,q.title_id,q.thread_id);
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
    strcpy(q.title_id,GAME);int32_t reply=0;
    bool ok=!connect(fd,(struct sockaddr *)&sa,sa.sun_len) && transfer(fd,&q,sizeof(q),true) &&
        transfer(fd,&reply,sizeof(reply),false) && reply==EPERM;
    close(fd);return ok?0:-1;
}

static int new_file(const char *path,const void *data,size_t n){int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0644);if(fd<0)return -1;log_debug("OWN NEW FILE %s bytes=%zu",path,n);const unsigned char *s=data;int rc=0;while(n){ssize_t w=write(fd,s,n);if(w<0&&errno==EINTR)continue;if(w<=0){rc=-1;break;}s+=w;n-=(size_t)w;}if(fsync(fd))rc=-1;close(fd);return rc;}
/* Existing shortcut updates require our exact ownership marker. No other title is eligible. */
static int owned_panel(void){char marker[16]={0};int fd=open(APP "/ps4-folder-loader.owner",O_RDONLY|O_NOFOLLOW);if(fd<0)return 0;ssize_t n=read(fd,marker,sizeof(marker));close(fd);return n==15&&!memcmp(marker,"PS4FL-PANEL-v1\n",15);}
static int panel_file(const char *path,const void *data,size_t size,int updating){
 if(!updating)return new_file(path,data,size);
 struct stat st;if(lstat(path,&st)||!S_ISREG(st.st_mode))return -1;
 char tmp[1024];int n=snprintf(tmp,sizeof(tmp),"%s.goda-new",path);if(n<0||(size_t)n>=sizeof(tmp)||new_file(tmp,data,size))return -1;
 if(rename(tmp,path)){unlink(tmp);return -1;}log_debug("OWN UPDATED FILE %s bytes=%zu",path,size);return 0;
}
int main(void){
 int lock=open("/data/ps4-folder-loader-panel.lock",O_CREAT|O_RDWR,0600);if(lock<0||flock(lock,LOCK_EX|LOCK_NB))return 1;
 logfile=fopen("/data/ps4-folder-loader-panel.log","a");if(!logfile){close(lock);return 1;}
 log_debug("BEGIN own media shortcut only; no game or save modifications");
 int result=1;bool socket_owned=false,server=false,hook_attempted=false;pthread_t thread;struct stat st;
 const uint8_t caps[16]={[0 ... 15]=0xff};
 if((kernel_get_fw_version()>>16)!=0x1360u||kernel_set_ucred_authid(-1,0x4800000000000006ull)||kernel_set_ucred_caps(-1,caps)||kernel_set_ucred_uid(-1,0))goto done;
 if(find_pid_by_name("eboot.bin",true)!=0){log_debug("REFUSED active game; shortcut not changed");goto done;}
 if(!lstat(SM_SHELLCORE_SOCKET_PATH,&st)||errno!=ENOENT||!lstat("/system_tmp/shadowmount.sock",&st)||errno!=ENOENT){log_debug("REFUSED existing lifecycle service");goto done;}
 int updating=0;const char *paths[]={APP,META};int existing=0;for(size_t i=0;i<2;i++){if(!lstat(paths[i],&st)){if(!S_ISDIR(st.st_mode))goto done;existing++;}else if(errno!=ENOENT)goto done;}if(existing){if(existing!=2||!owned_panel()){log_debug("REFUSED unowned or partial existing shortcut");goto done;}updating=1;}
 if(sceUserServiceInitialize(NULL)<0||sceUserServiceGetForegroundUser(&foreground_user)<0||foreground_user<=0)goto done;
 static const char param[]= "{\"titleId\":\"PFLD00001\",\"applicationCategoryType\":65536,\"deeplinkUri\":\"http://127.0.0.1:9134/\",\"localizedParameters\":{\"defaultLanguage\":\"en-US\",\"en-US\":{\"titleName\":\"Goda\"}}}\n";
 if(!updating&&(mkdir(APP,0755)||mkdir(APP "/sce_sys",0755)||mkdir(META,0755))){log_debug("NEW DIR creation failed errno=%d; own partial state retained",errno);goto done;}
 if((!updating&&new_file(APP "/ps4-folder-loader.owner","PS4FL-PANEL-v1\n",15))||panel_file(APP "/sce_sys/param.json",param,sizeof(param)-1,updating)||panel_file(META "/param.json",param,sizeof(param)-1,updating)||panel_file(APP "/sce_sys/icon0.png",panel_icon,sizeof(panel_icon),updating)||panel_file(META "/icon0.png",panel_icon,sizeof(panel_icon),updating))goto done;
 pid_t shell=find_pid_by_name("SceShellCore",true);if(shell<=0)goto done;bridge_uid=kernel_get_ucred_uid(shell);if(bridge_uid==(uid_t)-1)goto done;
 if(setup_socket())goto done;socket_owned=true;if(pthread_create(&thread,NULL,serve,NULL))goto done;server=true;
 if(check_transport())goto done;hook_attempted=true;if(!sm_shellcore_hooks_start())goto done;
 pthread_mutex_lock(&policy_mutex);policy.armed=true;pthread_mutex_unlock(&policy_mutex);
 int rc=-1;bool dispatched=sm_shellcore_install_title_dir(GAME,"/user/app/",&rc);
 pthread_mutex_lock(&policy_mutex);policy.armed=false;bool confirmed=policy.claimed&&policy.reported&&policy.success;pthread_mutex_unlock(&policy_mutex);
 log_debug("TitleDir dispatched=%d rc=0x%08x confirmed=%d",dispatched,(unsigned)rc,confirmed);
 if(dispatched&&confirmed&&(rc==0||(uint32_t)rc==0x80990002u))result=0;
 done:
 if(hook_attempted){for(;;){sm_shellcore_hooks_stop();if(d3_hooks_are_clear())break;log_debug("Retaining service until entry points restored");usleep(500000);}}
 stopping=1;if(listener>=0){shutdown(listener,SHUT_RDWR);close(listener);}if(server)pthread_join(thread,NULL);if(socket_owned)unlink(SM_SHELLCORE_SOCKET_PATH);
 log_debug("END result=%d; no game launched",result);fclose(logfile);close(lock);return result;
}
