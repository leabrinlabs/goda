/* GPL-3.0-or-later. General PS4 folder launch and readonly mount management.
 * Source files and saves are never written. Scoped registration lives separately.
 */
#include "engine.h"
#include "module_alias.h"
#include "launch_gate.h"
#include "lifecycle.h"
#include "launch_observation.h"
#include "browser.h"
#include "audit.h"
#ifdef FL_HOST
int fl_runtime_access(void){return 0;}
int fl_launch(const struct fl_game *g,fl_progress p){(void)g;p("Bilgisayar onizlemesi: konsolda baslatma yapilmaz.");return -1;}
#else
#include "sm_platform.h"
#include <sys/sysctl.h>
#include "mount_snapshot.h"
extern int sceSystemServiceLaunchApp(const char*,const char*[],void*);
extern int sceUserServiceGetForegroundUser(int*);
int fl_runtime_access(void){const uint8_t caps[16]={[0 ... 15]=0xff};return (kernel_get_fw_version()>>16)!=0x1360u||kernel_set_ucred_authid(-1,0x4800000000000006ull)||kernel_set_ucred_caps(-1,caps)||kernel_set_ucred_uid(-1,0)?-1:0;}
static pid_t game_pid(void){
 int mib[4]={CTL_KERN,KERN_PROC,KERN_PROC_PROC,0};size_t bytes=0;if(sysctl(mib,4,NULL,&bytes,NULL,0)||!bytes)return -1;
 unsigned char *buf=malloc(bytes);if(!buf)return -1;if(sysctl(mib,4,buf,&bytes,NULL,0)){free(buf);return -1;}
 pid_t found=0;size_t pos=0;while(pos+4<=bytes){int size;pid_t pid;memcpy(&size,buf+pos,4);if(size<=447||(size_t)size>bytes-pos){found=-1;break;}
 memcpy(&pid,buf+pos+72,sizeof(pid));const char *name=(char*)buf+pos+447;size_t available=(size_t)size-447;if(strnlen(name,available)==available){found=-1;break;}
 if(!strcmp(name,"eboot.bin")){found=pid;break;}pos+=(size_t)size;}free(buf);return found;
}
static int exact_ro(const char *p,const char *from){struct statfs f;return !statfs(p,&f)&&!strcmp(f.f_fstypename,"nullfs")&&!strcmp(f.f_mntonname,p)&&!strcmp(f.f_mntfromname,from)&&(f.f_flags&MNT_RDONLY);}
static int owned_module_mount(const struct statfs *fs,const char *root,const char *id){
 if(strcmp(fs->f_fstypename,"nullfs")||!(fs->f_flags&MNT_RDONLY))return 0;char prefix[FL_PATH],target[FL_PATH],canonical[FL_PATH];int n=snprintf(prefix,sizeof(prefix),"/data/ps4-folder-loader/overlays/%s/",id);if(n<0||(size_t)n>=sizeof(prefix)||strncmp(fs->f_mntfromname,prefix,(size_t)n)||!realpath(fs->f_mntfromname,canonical)||strcmp(canonical,fs->f_mntfromname))return 0;
 const char *dirs[]={"prx","sce_module"};for(size_t i=0;i<2;i++)if(!fl_join(target,sizeof(target),root,dirs[i])&&!strcmp(fs->f_mntonname,target))return 1;return 0;
}
static int root_same_inode(const char *source,const char *root){struct stat a,b;return !stat(source,&a)&&!stat(root,&b)&&a.st_ino==b.st_ino;}
static int ro_bind(const char *from,const char *to){struct iovec v[]={IOVEC_ENTRY("fstype"),IOVEC_ENTRY("nullfs"),IOVEC_ENTRY("from"),IOVEC_ENTRY(from),IOVEC_ENTRY("fspath"),IOVEC_ENTRY(to)};fl_audit("mount","begin source=%s target=%s readonly=1",from,to);int rc=nmount(v,IOVEC_SIZE(v),MNT_RDONLY);fl_audit("mount","end target=%s rc=%d errno=%d",to,rc,rc?errno:0);return rc;}
static int unmount_logged(const char *target){fl_audit("unmount","begin target=%s flags=0 setup_cleanup=1",target);int rc=unmount(target,0);fl_audit("unmount","end target=%s rc=%d errno=%d",target,rc,rc?errno:0);return rc;}
static int same_file(const char *a,const char *b){
 int x=open(a,O_RDONLY|O_NOFOLLOW),y=open(b,O_RDONLY|O_NOFOLLOW);if(x<0||y<0){if(x>=0)close(x);if(y>=0)close(y);return 0;}struct stat sx,sy;int ok=!fstat(x,&sx)&&!fstat(y,&sy)&&S_ISREG(sx.st_mode)&&S_ISREG(sy.st_mode)&&sx.st_size==sy.st_size&&sx.st_size<1024*1024;unsigned char ax[4096],ay[4096];
 while(ok){ssize_t nx=read(x,ax,sizeof(ax)),ny=read(y,ay,sizeof(ay));if(nx<0&&errno==EINTR)continue;if(nx<0||ny!=nx||(nx>0&&memcmp(ax,ay,(size_t)nx))){ok=0;break;}if(!nx)break;}close(x);close(y);return ok;
}
static int owned(const char *app){
 char p[FL_PATH],marker[32];
 if(fl_join(p,sizeof(p),app,"ps4-folder-loader.pending"))return 0;struct stat st;if(!lstat(p,&st)||errno!=ENOENT)return 0;
 const char *names[]={"ps4-folder-loader.owner","d3tr-folder-register.owner"};const char *values[]={"PS4FL-GAME-v1\n","D3TR-REG-v1\n"};
 for(size_t i=0;i<2;i++){if(fl_join(p,sizeof(p),app,names[i]))return 0;int fd=open(p,O_RDONLY|O_NOFOLLOW);if(fd<0)continue;ssize_t n=read(fd,marker,sizeof(marker));close(fd);if(n==(ssize_t)strlen(values[i])&&!memcmp(marker,values[i],(size_t)n))return 1;}return 0;
}
/* After reboot, only an empty native mountpoint is eligible for reuse. */
static int empty_native_root(const char *path){
 struct stat st;struct statfs fs;if(lstat(path,&st)||!S_ISDIR(st.st_mode)||S_ISLNK(st.st_mode)||statfs(path,&fs)||strcmp(fs.f_mntonname,"/system_ex"))return 0;
 DIR *dir=opendir(path);if(!dir)return 0;int empty=1;struct dirent *ent;errno=0;while((ent=readdir(dir))){if(strcmp(ent->d_name,".")&&strcmp(ent->d_name,"..")){empty=0;break;}}if(!ent&&errno)empty=0;closedir(dir);return empty;
}
/* Reuse only a verifiable pre-existing folder link; never adopt installed PKGs.
 * Metadata stays unchanged, only the readonly game view can be redirected. */
static int existing_folder(const char *app,const char *mount,const struct fl_game *selected){
 char link[FL_PATH],source[FL_PATH],sfo[FL_PATH],registered[FL_PATH],error[256];struct stat st;struct statfs fs;struct fl_game g;
 if(fl_join(link,sizeof(link),app,"ps4-folder-loader.pending")||!lstat(link,&st)||errno!=ENOENT)return 0;
 if(fl_join(link,sizeof(link),app,"app.pkg")||!lstat(link,&st)||errno!=ENOENT||fl_join(link,sizeof(link),app,"mount.lnk"))return 0;
 int fd=open(link,O_RDONLY|O_NOFOLLOW);if(fd<0)return 0;ssize_t n=read(fd,source,sizeof(source)-1);int ok=!fstat(fd,&st)&&S_ISREG(st.st_mode)&&n>0&&st.st_size==n;close(fd);if(!ok)return 0;source[n]=0;
 if(fl_inspect_game(source,&g,error,sizeof(error))||strcmp(g.id,selected->id)||strcmp(g.version,selected->version)||statfs(mount,&fs))return 0;
 if(!empty_native_root(mount)&&(strcmp(fs.f_fstypename,"nullfs")||strcmp(fs.f_mntonname,mount)||(strcmp(fs.f_mntfromname,source)&&strcmp(fs.f_mntfromname,selected->path)&&strcmp(fs.f_mntfromname,app))))return 0;
 return !fl_join(sfo,sizeof(sfo),source,"sce_sys/param.sfo")&&!fl_join(registered,sizeof(registered),app,"sce_sys/param.sfo")&&same_file(sfo,registered);
}
static int private_owned(const char *priv,const char *id){char path[FL_PATH],data[16];struct statfs fs;if(statfs(priv,&fs)||strcmp(fs.f_mntonname,"/system_data")||fl_join(path,sizeof(path),priv,"ps4-folder-loader.private"))return 0;int fd=open(path,O_RDONLY|O_NOFOLLOW);if(fd<0)return 0;ssize_t n=read(fd,data,sizeof(data));close(fd);return n==10&&!memcmp(data,id,9)&&data[9]=='\n';}
static int copy_missing(const char *source,const char *dest){struct stat st;if(!lstat(dest,&st))return same_file(source,dest)?0:-1;if(errno!=ENOENT)return -1;int in=open(source,O_RDONLY|O_NOFOLLOW);if(in<0)return -1;if(fstat(in,&st)||!S_ISREG(st.st_mode)||st.st_size<=0||st.st_size>512*1024){close(in);return -1;}size_t n=(size_t)st.st_size,at=0;unsigned char *data=malloc(n);if(!data){close(in);return -1;}while(at<n){ssize_t r=read(in,data+at,n-at);if(r<0&&errno==EINTR)continue;if(r<=0)break;at+=(size_t)r;}close(in);if(at!=n){free(data);return -1;}int out=open(dest,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0644);if(out<0){free(data);return -1;}at=0;while(at<n){ssize_t w=write(out,data+at,n-at);if(w<0&&errno==EINTR)continue;if(w<=0)break;at+=(size_t)w;}int ok=at==n&&!fsync(out);close(out);free(data);return ok&&same_file(source,dest)?0:-1;}
/* Private registry directory is distinct from game data. Sony's TitleDir
 * service must be able to update it. Only add absent, identical source files. */
int fl_private_metadata(const struct fl_game *game,const char *reg){
 char priv[FL_PATH],a[FL_PATH],b[FL_PATH];struct stat st;struct statfs fs;int removed=0;
 if(fl_join(priv,sizeof(priv),"/system_data/priv/appmeta",game->id))return -1;
 if(exact_ro(priv,reg)){if(unmount_logged(priv))return -1;removed=1;}
 if(lstat(priv,&st)||!S_ISDIR(st.st_mode)||statfs(priv,&fs)||strcmp(fs.f_mntonname,"/system_data"))goto fail;
 const char *names[]={"param.sfo","nptitle.dat","npbind.dat"};for(size_t i=0;i<3;i++){if(fl_join(a,sizeof(a),reg,names[i])||fl_join(b,sizeof(b),priv,names[i])||copy_missing(a,b))goto fail;}
 if(fl_join(b,sizeof(b),priv,"ps4-folder-loader.private"))goto fail;
 if(lstat(b,&st)){if(errno!=ENOENT)goto fail;int fd=open(b,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0644);if(fd<0)goto fail;char marker[11];snprintf(marker,sizeof(marker),"%s\n",game->id);int ok=write(fd,marker,10)==10&&!fsync(fd);close(fd);if(!ok)goto fail;}
 return private_owned(priv,game->id)?0:-1;
 fail:if(removed)ro_bind(reg,priv);return -1;
}
/* Only fill ABSENT registration metadata from the selected package tree.
 * Existing bytes are compared and never replaced. No game/save file writes. */
static int supplement_metadata(const struct fl_game *game,const char *reg){
 const char *names[]={"npbind.dat","nptitle.dat"};char source[FL_PATH],a[FL_PATH],b[FL_PATH],meta[FL_PATH],sfo[FL_PATH];
 if(fl_join(source,sizeof(source),game->path,"sce_sys")||fl_join(meta,sizeof(meta),"/user/appmeta",game->id)||fl_join(a,sizeof(a),source,"param.sfo")||fl_join(sfo,sizeof(sfo),meta,"param.sfo")||!same_file(a,sfo))return -1;
 const char *dirs[]={reg,meta};
 for(size_t i=0;i<2;i++){
  if(fl_join(a,sizeof(a),source,names[i]))return -1;struct stat st;if(lstat(a,&st)){if(errno==ENOENT)continue;return -1;}if(!S_ISREG(st.st_mode)||st.st_size<=0||st.st_size>16384)return -1;
  for(size_t j=0;j<2;j++){
   if(fl_join(b,sizeof(b),dirs[j],names[i]))return -1;
   if(!lstat(b,&st)){if(!same_file(a,b))return -1;continue;}if(errno!=ENOENT)return -1;
   int in=open(a,O_RDONLY|O_NOFOLLOW);if(in<0)return -1;unsigned char data[16384];size_t n=0;int bad=0;while(n<sizeof(data)){ssize_t got=read(in,data+n,sizeof(data)-n);if(got<0&&errno==EINTR)continue;if(got<0){bad=1;break;}if(!got)break;n+=(size_t)got;}close(in);if(bad||!n||n==sizeof(data))return -1;
   FILE *journal=fopen("/data/ps4-folder-loader-metadata.log","a");if(!journal)return -1;fprintf(journal,"NEW ABSENT title=%s target=%s source=%s bytes=%zu\n",game->id,b,a,n);if(fflush(journal)||fsync(fileno(journal))){fclose(journal);return -1;}
   int out=open(b,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0644);if(out<0){fclose(journal);return -1;}size_t at=0;while(at<n){ssize_t w=write(out,data+at,n-at);if(w<0&&errno==EINTR)continue;if(w<=0)break;at+=(size_t)w;}int ok=at==n&&!fsync(out);close(out);ok=ok&&same_file(a,b);fprintf(journal,"COMPLETE target=%s verified=%d\n",b,ok);fflush(journal);fsync(fileno(journal));fclose(journal);if(!ok)return -1;
  }
 }return 0;
}
int fl_launch(const struct fl_game *input,fl_progress progress){
 struct fl_game selected;char error[256],root[FL_PATH],app[FL_PATH],reg[FL_PATH],meta[FL_PATH],priv[FL_PATH],srcsfo[FL_PATH],regsfo[FL_PATH];int result=-1,newroot=0,newmeta=0,newpriv=0,lifecycle=0;
 if(fl_lifecycle_busy()){progress("Onceki oyunun kapanis temizligi suruyor veya dogrulanamadi. Yeni baslatma engellendi.");return -1;}
 progress("Oyun klasoru ve baslatma kosullari denetleniyor...");
 if(fl_inspect_game(input->path,&selected,error,sizeof(error))||strcmp(selected.id,input->id)){progress("Secilen oyun degisti veya okunamadi. Listeyi yenileyin.");return -1;}
 if((kernel_get_fw_version()>>16)!=0x1360u){progress("Bu alfa mevcut PS5 yazilim surumunu desteklemiyor.");return -1;}
 if(game_pid()!=0){progress("Once acik PS4 oyununu PS5 menusunden kapatin, sonra tekrar Baslat deyin.");return -1;}
 struct stat st;if(!lstat("/system_tmp/d3trlaunch.sock",&st)||errno!=ENOENT||!lstat("/system_tmp/shadowmount.sock",&st)||errno!=ENOENT){progress("Baska bir oyun baslaticisi etkin. Bu deneme baslatilmadi.");return -1;}
 progress("Baslatma yetkisi hazirlaniyor...");
 if(fl_runtime_access()){progress("Baslatma yetkisi alinamadi.");return -1;}
 if(fl_join(app,sizeof(app),"/user/app",selected.id)||fl_join(root,sizeof(root),"/system_ex/app",selected.id)||fl_join(reg,sizeof(reg),app,"sce_sys")||fl_join(meta,sizeof(meta),root,"sce_sys")||fl_join(priv,sizeof(priv),"/system_data/priv/appmeta",selected.id))return -1;
 progress("Mevcut klasor kaydi denetleniyor...");
 int linked=existing_folder(app,root,&selected);
 if(!owned(app)&&!linked){
  if(fl_register_folder(&selected,progress))return -1;
 }
 if(fl_join(srcsfo,sizeof(srcsfo),selected.path,"sce_sys/param.sfo")||fl_join(regsfo,sizeof(regsfo),reg,"param.sfo")||!same_file(srcsfo,regsfo)){progress("Secilen surum mevcut klasor kaydiyla eslesmiyor. Guncelleme destegi henuz etkin degil.");return -1;}
 progress("Baslatma kaydinin metadata dosyalari denetleniyor...");
 if(supplement_metadata(&selected,reg)){progress("Baslatma kaydinin ek metadata dosyalari eslesmiyor veya tamamlanamadi. Mevcut dosyalarin uzerine yazilmadi.");return -1;}
 if(!owned(app)&&linked){char stamp[128];snprintf(stamp,sizeof(stamp),"/data/ps4-folder-loader-refreshed-%s",selected.id);if(lstat(stamp,&st)){if(errno!=ENOENT)return -1;progress("Eski klasor kaydi guncel metadatayla yenileniyor...");if(fl_refresh_folder(&selected,progress))return -1;}}
 progress("Oyun kimligi ve salt okunur klasor gorunumu denetleniyor...");
 struct statfs f;if(statfs(root,&f))return -1;
 if(exact_ro(root,app)){
  if(game_pid()!=0||unmount_logged(root)||ro_bind(selected.path,root)||statfs(root,&f)){progress("Bekleme metadata gorunumu oyun baglantisina gecirilemedi.");return -1;}
  newroot=1;
 }
 if(strcmp(f.f_fstypename,"nullfs")||strcmp(f.f_mntonname,root)){
  if((!owned(app)&&!linked)||!empty_native_root(root)||ro_bind(selected.path,root)||statfs(root,&f)){progress("Salt okunur klasor gorunumu kurulamadi.");return -1;}
  newroot=1;
 }
 /* Only accept a previous mount whose source has the same SFO identity. */
 struct fl_game previous;if(fl_inspect_game(f.f_mntfromname,&previous,error,sizeof(error))||strcmp(previous.id,selected.id)){progress("Var olan oyun baglantisinin sahipligi dogrulanamadi.");return -1;}
 if(!exact_ro(root,selected.path)||!root_same_inode(selected.path,root)){
  struct statfs *mounts=NULL;int n=fl_mount_snapshot(&mounts);if(n<=0)return -1;int conflict=0;
  for(int i=0;i<n;i++)if(!strncmp(mounts[i].f_mntonname,root,strlen(root))&&mounts[i].f_mntonname[strlen(root)]=='/'){
   if((strcmp(mounts[i].f_mntonname,meta)||!exact_ro(meta,reg))&&!owned_module_mount(&mounts[i],root,selected.id)){conflict=1;break;}
  }
  free(mounts);if(conflict){progress("Oyunun altinda baska bir baglanti var. Degistirilmedi.");return -1;}
  progress("Oyun klasorunun salt okunur baglantisi hazirlaniyor...");
  if(game_pid()!=0||ro_bind(selected.path,root)){progress("Salt okunur oyun gorunumu hazirlanamadi.");return -1;}newroot=1;
 }
 if(!exact_ro(meta,reg)){
  progress("Oyun metadata baglantisi hazirlaniyor...");
  if(statfs(meta,&f)||strcmp(f.f_mntonname,root)||!exact_ro(root,selected.path)||ro_bind(reg,meta)){progress("Oyun bilgileri baglanamadi.");goto done;}newmeta=1;
 }
 if(!private_owned(priv,selected.id)&&!exact_ro(priv,reg)){
  progress("Ozel metadata kaydi denetleniyor...");
  if(lstat(priv,&st)&&errno==ENOENT&&mkdir(priv,0755)){progress("Yeni oyun bilgi klasoru olusturulamadi.");goto done;}
  if(lstat(priv,&st)||!S_ISDIR(st.st_mode)||statfs(priv,&f)||strcmp(f.f_mntonname,"/system_data")||ro_bind(reg,priv)){progress("Kayit bilgileri baglanamadi.");goto done;}newpriv=1;
 }
 int user=-1;if(sceUserServiceGetForegroundUser(&user)<0||user<=0){progress("Etkin kullanici okunamadi.");goto done;}
 if(game_pid()!=0){progress("Baska bir oyun acildi; islem durduruldu.");goto done;}
 struct fl_module_view views[FL_MODULE_VIEWS];size_t view_count=0;
 if(fl_prepare_module_views(&selected,views,&view_count,progress)){progress("Oyun kutuphanelerinin dosya adlari hazirlanamadi; baslatma durduruldu.");goto done;}
 if(view_count>FL_MODULE_VIEWS)goto done;
 for(size_t i=0;i<view_count;i++){
  char target[FL_PATH],prefix[FL_PATH],canonical[FL_PATH];int n=snprintf(prefix,sizeof(prefix),"%s/%s/",FL_MODULE_OWNED_ROOT,selected.id);
  if((strcmp(views[i].relative,"prx")&&strcmp(views[i].relative,"sce_module"))||n<0||(size_t)n>=sizeof(prefix)||strncmp(views[i].source,prefix,(size_t)n)||!realpath(views[i].source,canonical)||strcmp(canonical,views[i].source)||fl_join(target,sizeof(target),root,views[i].relative)||lstat(target,&st)||!S_ISDIR(st.st_mode)||statfs(target,&f))goto done;
  if(strcmp(f.f_mntonname,root)&&!owned_module_mount(&f,root,selected.id)){progress("Kutuphanenin konumunda baska bir baglanti var; degistirilmedi.");goto done;}
  /* A child mount here does not propagate through the later app0 nullfs.
     The one-shot pre-exec gate binds it inside the actual sandbox instead. */
 }
 if(game_pid()!=0){progress("Baska bir oyun acildi; islem durduruldu.");goto done;}

 struct launch_context{uint32_t size,user,options;uint64_t crash;uint32_t check;};_Static_assert(sizeof(struct launch_context)==32,"launch ABI");
 struct launch_context context={sizeof(context),(uint32_t)user,0,0,0};const char *argv[]={NULL};int rc=-1;
 if(fl_browser_before_launch()){progress("PS5 gezinme penceresi kapatilamadi; oyun baslatma istegi gonderilmedi.");goto done;}
 if(fl_lifecycle_begin(&selected)){progress("Kapanis izleyicisi baslatilamadi; oyun baslatilmadi.");goto done;}
 lifecycle=1;newroot=newmeta=newpriv=0;
 if(fl_lifecycle_track(selected.path,root)||fl_lifecycle_track(reg,meta)){progress("Baglanti sahipligi kapanis izleyicisine kaydedilemedi; baslatma durdu.");goto done;}
 if(view_count){
  /* A queued pre-exec gate can retain the readonly root even on failure. */
  newroot=newmeta=newpriv=0;
  if(fl_gate_launch(&selected,views,view_count,user,progress,&rc)){progress("Gercek app0 baslatma yonlendirmesi dogrulanamadi. Yeni denemeden once gunluk incelenmeli.");goto done;}
 }else{progress("Oyun baslatiliyor...");fl_audit("launch","single_dispatch title=%s",selected.id);rc=sceSystemServiceLaunchApp(selected.id,argv,&context);}
 fl_lifecycle_dispatched();lifecycle=0;
 /* A queued launch can outlive the API call. Retain readonly views even if
    no process is observed yet; never dismantle a queued game's filesystem. */
 newroot=newmeta=newpriv=0;
 if(rc<0){char message[192];snprintf(message,sizeof(message),"Baslatma istegi reddedildi (0x%08x). Oyun dosyalari degistirilmedi.",(unsigned)rc);progress(message);goto done;}
 for(unsigned i=0;i<40;i++){pid_t pid=game_pid();if(pid>0){app_info_t info={0};if(!sceKernelGetAppInfo(pid,&info)&&!strcmp(info.title_id,selected.id)){
    progress("Oyun sureci basladi; acilista kapanma olup olmadigi izleniyor...");
    struct fl_launch_observation observation={.pid=pid};int observed=0;
    for(unsigned tick=0;tick<240;tick++){
     usleep(250000);pid_t candidate=(pid_t)observation.pid;int sample=1;app_info_t current={0};
     int info_rc=sceKernelGetAppInfo(candidate,&current);
     if(info_rc){candidate=game_pid();sample=candidate<0?-1:candidate==0?0:1;if(candidate>0)info_rc=sceKernelGetAppInfo(candidate,&current);}
     if(candidate>0){if(info_rc)sample=-1;else if(strcmp(current.title_id,selected.id)||current.app_id!=info.app_id)sample=2;}
     if(sample!=1){FILE *diag=fopen("/data/ps4-folder-loader-observation.log","a");if(diag){fprintf(diag,"sample=%d expected_pid=%lld candidate=%d expected_app=0x%08x actual_app=0x%08x info_rc=0x%08x expected_title=%s actual_title=%.14s\n",sample,(long long)observation.pid,(int)candidate,info.app_id,current.app_id,(unsigned)info_rc,selected.id,current.title_id);fclose(diag);}}
     observed=fl_observe_launch(&observation,sample,candidate);
     if(observed==1){pid=(pid_t)observation.pid;break;}
     if(observed==-1){
      fl_audit("launch","observed_exit_before_settlement title=%s pid=%d exit_reason_unclassified=1 auto_ui_reopen=0",selected.id,(int)observation.pid);
      progress("Oyun sureci baslangic izlemesi tamamlanmadan kapandi. Kapatma veya cokme ayrimi gunlukten denetlenmeli.");result=FL_LAUNCH_OBSERVED_EXIT;goto done;
     }
     if(observed<0){progress("Oyun sureci veya uygulama kimligi guvenle dogrulanamadi; yeni baslatma istegi gonderilmedi.");goto done;}
    }
    if(observed!=1){progress("Oyun sureci kararliligi zaman sinirinda dogrulanamadi; yeniden baslatma istegi gonderilmedi.");goto done;}
    app_info_t settled={0};
    if(sceKernelGetAppInfo(pid,&settled)||strcmp(settled.title_id,selected.id)||settled.app_id!=info.app_id){progress("Oyun kimligi degisti; odak istegi gonderilmedi.");goto done;}
    fl_audit("launch","settled title=%s pid=%d app_id=0x%08x duplicate_launch_requests=0",selected.id,(int)pid,settled.app_id);
    progress("Oyun sureci dogrulandi. Pencere gecisinin gorsel sonucu konsolda ayrica dogrulanmali.");result=0;goto done;
   }}usleep(250000);}
 progress("Baslatma istegi gonderildi; oyun sureci henuz dogrulanamadi. Tekrar Baslat'a basmadan PS5 ekranini kontrol edin.");
 done:
 if(lifecycle)fl_lifecycle_dispatched();
 if(result&&game_pid()==0){
  if(newpriv&&exact_ro(priv,reg))unmount_logged(priv);
  if(newmeta&&exact_ro(meta,reg)&&unmount_logged(meta))newroot=0;
  if(newroot&&exact_ro(root,selected.path))unmount_logged(root);
 }
 return result;
}
#endif
