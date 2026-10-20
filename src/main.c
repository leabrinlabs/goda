/* GPL-3.0-or-later. Single ELF, loopback-only web UI and read-only catalog. */
#include "catalog.h"
#include "engine.h"
#include "lifecycle.h"
#include "browser.h"
#include "extractor.h"
#include "pkg_diagnostics.h"
#include "http_policy.h"
#include "ui.h"
#include "assets.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#define PORT 9134
#define FL_VERSION "0.6.13-library-status"
static uint64_t runtime_started_us,runtime_next_us;
static volatile sig_atomic_t stopping;
static pthread_mutex_t state_lock=PTHREAD_MUTEX_INITIALIZER;
static struct fl_game games[FL_MAX_GAMES],selected;
static size_t game_count;
static unsigned revision=1;
#ifdef FL_HOST
static char host_storage_root[FL_PATH];
#endif
static int busy,job_kind,job_result;
static unsigned job_serial;
static uint64_t job_done,job_total;
static volatile sig_atomic_t extraction_cancel;
static char extract_root[FL_PATH],package[FL_PATH];
static char job_source[FL_PATH],job_target[FL_PATH];
static unsigned error_serial;
static struct {unsigned id;int result;char code[48],text[512],detail[FL_PATH],stage[512],source[FL_PATH],target[FL_PATH];} failure;
/* Called with state_lock held. Recorded by the existing passive runtime log;
 * HTTP rejections are retained too, even though no worker job was started. */
static void remember_error(const char *code,const char *text,const char *detail,const char *stage,const char *source,const char *target,int result){
 failure.id=++error_serial;failure.result=result;
 snprintf(failure.code,sizeof(failure.code),"%s",code);snprintf(failure.text,sizeof(failure.text),"%s",text);
 snprintf(failure.detail,sizeof(failure.detail),"%s",detail);snprintf(failure.stage,sizeof(failure.stage),"%s",stage);
 snprintf(failure.source,sizeof(failure.source),"%s",source);snprintf(failure.target,sizeof(failure.target),"%s",target);
}
static char root[FL_PATH]="",message[512]="Hazir.",token[65];
static char config_dir[FL_PATH]="/data/ps4-folder-loader";
static void progress(const char *s){
#ifndef FL_HOST
 /* Persist stage before a mount/launch: UI state alone is lost on disconnect. */
 int saved=errno;FILE *f=fopen("/data/ps4-folder-loader-events.log","a");if(f){fprintf(f,"launch serial=%u: %s\n",job_serial,s);fflush(f);fsync(fileno(f));fclose(f);}errno=saved;
#endif
 pthread_mutex_lock(&state_lock);snprintf(message,sizeof(message),"%s",s);pthread_mutex_unlock(&state_lock);
}
static void extraction_progress(const char *s,uint64_t done,uint64_t total){pthread_mutex_lock(&state_lock);snprintf(message,sizeof(message),"%s",s);job_done=done;job_total=total;pthread_mutex_unlock(&state_lock);}
static void *worker(void *unused){
 (void)unused;char output[FL_PATH];int result;
 if(job_kind==2||job_kind==3){if(fl_runtime_access()){snprintf(output,sizeof(output),"Konsol yetkisi veya surumu uygun degil.");result=-1;}else if(job_kind==3)result=fl_restore_permissions(job_source,job_target,extraction_progress,output,sizeof(output));else result=fl_extract_pkg(job_source,job_target,extraction_progress,&extraction_cancel,output,sizeof(output));}
 else if(job_kind==4){result=fl_browser_before_launch();progress(result?"Arayuz kapatma istegi reddedildi; oyun baslatilmadi.":"Arayuz kapatma istegi gonderildi; oyun baslatilmadi.");}
 /* An observed early process exit may be a user close or a crash. Neither
  * permits reopening the browser the user just dismissed. UI opens only
  * when explicitly starting the application. */
 else result=fl_launch(&selected,progress);
 pthread_mutex_lock(&state_lock);
 if(job_kind==2&&result){struct fl_pkg_diagnostic d=fl_pkg_diagnose(output);remember_error(d.code,d.message,output,message,job_source,job_target,result);}
 if(job_kind==3)snprintf(message,sizeof(message),"%.500s",output);
 else if(job_kind==2)snprintf(message,sizeof(message),result?"Cikarma durdu: %.470s":"Cikarma ve dosya dogrulamasi tamamlandi: %.450s",output);
 job_result=result;job_serial++;busy=0;pthread_mutex_unlock(&state_lock);return NULL;
}
static void stop(int sig){(void)sig;stopping=1;extraction_cancel=1;}
struct output {char *data;size_t len,cap;char **target;size_t *length;int failed;};
static struct output *out_open(char **data,size_t *len){struct output *o=calloc(1,sizeof(*o));if(o){o->target=data;o->length=len;}return o;}
static void out_write(struct output *o,const void *data,size_t n){if(o->failed)return;if(n>2*1024*1024-o->len){o->failed=1;return;}size_t need=o->len+n+1;if(need>o->cap){size_t cap=o->cap?o->cap:1024;while(cap<need)cap*=2;char *p=realloc(o->data,cap);if(!p){o->failed=1;return;}o->data=p;o->cap=cap;}memcpy(o->data+o->len,data,n);o->len+=n;o->data[o->len]=0;}
static void out_char(int c,struct output *o){char b=(char)c;out_write(o,&b,1);}
static void out_puts(const char *s,struct output *o){out_write(o,s,strlen(s));}
static void out_printf(struct output *o,const char *format,...){char buf[1024];va_list a;va_start(a,format);int n=vsnprintf(buf,sizeof(buf),format,a);va_end(a);if(n<0||(size_t)n>=sizeof(buf)){o->failed=1;return;}out_write(o,buf,(size_t)n);}
static void out_close(struct output *o){if(o->failed){free(o->data);o->data=NULL;o->len=0;}*o->target=o->data;*o->length=o->len;free(o);}
static void json(struct output *out,const char *s){out_char('"',out);for(const unsigned char *p=(const unsigned char*)s;*p;p++){if(*p=='"'||*p=='\\'){out_char('\\',out);out_char(*p,out);}else if(*p<32)out_printf(out,"\\u%04x",*p);else out_char(*p,out);}out_char('"',out);}
/* One formatter for HTTP and passive telemetry. No process enumeration,
 * privilege changes, launch calls or native service calls on this path. */
static void failure_json(struct output *f){
 out_puts("{\"code\":",f);json(f,failure.code);out_puts(",\"error\":",f);json(f,failure.text);
 out_puts(",\"detail\":",f);json(f,failure.detail);out_puts(",\"stage\":",f);json(f,failure.stage);
 out_puts(",\"source\":",f);json(f,failure.source);out_puts(",\"target\":",f);json(f,failure.target);
 out_printf(f,",\"error_id\":%u,\"result\":%d}",failure.id,failure.result);
}
static void state_json(struct output *f){
 pthread_mutex_lock(&state_lock);int phase=fl_lifecycle_phase();
 out_printf(f,"{\"busy\":%s,\"runtime_active\":%s,\"runtime_phase\":%d,\"native_home_launch_supported\":false,\"message\":",busy?"true":"false",phase?"true":"false",phase);
 json(f,phase==3?"Oyun kapandi; baglantilar temizleniyor.":(!busy&&job_kind==1&&job_serial&&job_result==0&&!phase)?"Oyun kapandi; kapanis temizligi tamamlandi.":message);
 out_printf(f,",\"job\":\"%s\",\"serial\":%u,\"result\":%d,\"done\":%llu,\"total\":%llu",job_kind==2?"extract":job_kind==3?"permissions":job_kind==4?"dismiss-ui":job_kind==1?"launch":"",job_serial,job_result,(unsigned long long)job_done,(unsigned long long)job_total);
 out_puts(",\"failure\":",f);if(failure.code[0])failure_json(f);else out_puts("null",f);out_char('}',f);
 pthread_mutex_unlock(&state_lock);
}
static void runtime_log(void){
 struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return;
 uint64_t now=(uint64_t)t.tv_sec*1000000+(uint64_t)t.tv_nsec/1000;
 if(now<runtime_next_us)return;runtime_next_us=now+2000000;
 if(!runtime_started_us)runtime_started_us=now;
 char path[FL_PATH];
#ifdef FL_HOST
 if(fl_join(path,sizeof(path),config_dir,"runtime.log"))return;
#else
 snprintf(path,sizeof(path),"/data/ps4-folder-loader-runtime.log");
#endif
 char *data=NULL;size_t size=0;struct output *f=out_open(&data,&size);if(!f)return;
 out_printf(f,"{\"v\":1,\"version\":\"%s\",\"loader_pid\":%d,\"started_us\":%llu,\"mono_us\":%llu,\"state\":",FL_VERSION,(int)getpid(),(unsigned long long)runtime_started_us,(unsigned long long)now);
 state_json(f);out_puts("}\n",f);out_close(f);
 if(data){
  /* Release state locks before file I/O. Only the loader's own log is opened. */
  int fd=open(path,O_CREAT|O_APPEND|O_WRONLY|O_NOFOLLOW,0600);
  if(fd>=0){struct stat st;if(!fstat(fd,&st)&&S_ISREG(st.st_mode)){
   /* This is a small rolling diagnostic log, not a growing game database.
    * The existing tailer detects truncation; PC captures retain received data. */
   int ready=st.st_size<=1024*1024-(off_t)size||!ftruncate(fd,0);
   if(ready){size_t at=0;while(at<size){ssize_t n=write(fd,data+at,size-at);if(n<0&&errno==EINTR)continue;if(n<=0)break;at+=(size_t)n;}if(at==size)fsync(fd);}
  }close(fd);}
 }free(data);
}
static int unhex(int c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static int field(const char *body,const char *key,char *out,size_t cap){
 size_t keylen=strlen(key);out[0]=0;int found=0;const char *p=body;
 while(*p){const char *end=strchr(p,'&');if(!end)end=p+strlen(p);const char *eq=memchr(p,'=',(size_t)(end-p));
 if(eq&&(size_t)(eq-p)==keylen&&!memcmp(p,key,keylen)){
  if(found)return -1;found=1;size_t n=0;for(const char *v=eq+1;v<end;v++){int c=(unsigned char)*v;if(c=='+')c=' ';else if(c=='%'){if(v+2>=end||unhex(v[1])<0||unhex(v[2])<0)return -1;c=unhex(v[1])*16+unhex(v[2]);v+=2;}if(!c||c<32||n+1>=cap)return -1;out[n++]=(char)c;}out[n]=0;
 }p=*end?end+1:end;
 }return found;
}
static int write_all(int fd,const void *v,size_t n){const char *p=v;while(n){ssize_t r=send(fd,p,n,0);if(r<0&&errno==EINTR)continue;if(r<=0)return -1;p+=r;n-=(size_t)r;}return 0;}
static void response(int fd,int code,const char *type,const void *body,size_t n){char h[1024];int size=snprintf(h,sizeof(h),"HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'none'\r\nX-Frame-Options: DENY\r\nCross-Origin-Resource-Policy: same-origin\r\n\r\n",code,code==200?"OK":"Error",type,n);if(size>0&&(size_t)size<sizeof(h)){write_all(fd,h,(size_t)size);write_all(fd,body,n);}}
static void error_response(int fd,int code,const char *s){char *body=NULL;size_t n=0;struct output *f=out_open(&body,&n);if(!f)return;out_puts("{\"error\":",f);json(f,s);out_char('}',f);out_close(f);response(fd,code,"application/json; charset=utf-8",body,n);free(body);}
static int load_config(void){char p[FL_PATH],buf[FL_PATH];if(fl_join(p,sizeof(p),config_dir,"root.txt"))return -1;int fd=open(p,O_RDONLY|O_NOFOLLOW);if(fd<0)return -1;ssize_t n=read(fd,buf,sizeof(buf)-1);close(fd);if(n<=0||n>=(ssize_t)sizeof(buf)-1)return -1;buf[n]=0;char *nl=strchr(buf,'\n');if(nl)*nl=0;char canonical[FL_PATH];if(!fl_allowed_directory(buf,canonical))return -1;snprintf(root,sizeof(root),"%s",canonical);return 0;}
static int save_config(void){struct stat st;if(mkdir(config_dir,0700)&&errno!=EEXIST)return -1;if(lstat(config_dir,&st)||!S_ISDIR(st.st_mode))return -1;char tmp[FL_PATH],dest[FL_PATH];if(fl_join(tmp,sizeof(tmp),config_dir,"root.new")||fl_join(dest,sizeof(dest),config_dir,"root.txt"))return -1;int fd=open(tmp,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0600);if(fd<0)return -1;size_t n=strlen(root);ssize_t wrote=write(fd,root,n);int rc=wrote==(ssize_t)n&&fsync(fd)==0?0:-1;close(fd);if(!rc)rc=rename(tmp,dest);if(rc)unlink(tmp);return rc;}
static int save_extract_config(void){
 char tmp[FL_PATH],dest[FL_PATH];if(fl_join(tmp,sizeof(tmp),config_dir,"extract-root.new")||fl_join(dest,sizeof(dest),config_dir,"extract-root.txt"))return -1;
 int fd=open(tmp,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0600);if(fd<0)return -1;size_t n=strlen(extract_root);int rc=write(fd,extract_root,n)==(ssize_t)n&&fsync(fd)==0?0:-1;close(fd);if(!rc)rc=rename(tmp,dest);if(rc)unlink(tmp);return rc;
}
static void load_extract_config(void){char p[FL_PATH],b[FL_PATH],real[FL_PATH];if(fl_join(p,sizeof(p),config_dir,"extract-root.txt"))return;int fd=open(p,O_RDONLY|O_NOFOLLOW);if(fd<0)return;ssize_t n=read(fd,b,sizeof(b)-1);close(fd);if(n<=0||n>=(ssize_t)sizeof(b)-1)return;b[n]=0;if(fl_allowed_directory(b,real))snprintf(extract_root,sizeof(extract_root),"%s",real);}
static void icon_response(int fd,const char *url){
 unsigned gen,index;char tail;
 if(sscanf(url,"/icon/%u/%u%c",&gen,&index,&tail)!=2||gen!=revision||index>=game_count){error_response(fd,404,"Kapak bulunamadi");return;}
 struct fl_game check;char reason[256],path[FL_PATH];
 if(fl_inspect_game(games[index].path,&check,reason,sizeof(reason))||strcmp(check.id,games[index].id)||fl_join(path,sizeof(path),check.path,"sce_sys/icon0.png")){error_response(fd,404,"Kapak bulunamadi");return;}
 int in=open(path,O_RDONLY|O_NOFOLLOW);if(in<0){error_response(fd,404,"Kapak bulunamadi");return;}struct stat st;
 if(fstat(in,&st)||!S_ISREG(st.st_mode)||st.st_size<8||st.st_size>8*1024*1024){close(in);error_response(fd,404,"Kapak okunamadi");return;}
 size_t size=(size_t)st.st_size,got=0;unsigned char *data=malloc(size);if(!data){close(in);error_response(fd,500,"Bellek yetersiz");return;}
 while(got<size){ssize_t n=read(in,data+got,size-got);if(n<0&&errno==EINTR)continue;if(n<=0)break;got+=(size_t)n;}close(in);
 if(got==size&&!memcmp(data,"\x89PNG\r\n\x1a\n",8))response(fd,200,"image/png",data,size);else error_response(fd,404,"Kapak okunamadi");free(data);
}
static void api(int fd,const char *body){
 char op[32],auth[80],path[FL_PATH],id[32];if(field(body,"token",auth,sizeof(auth))!=1||strcmp(auth,token)){error_response(fd,403,"Gecersiz oturum");return;}
 if(field(body,"op",op,sizeof(op))!=1){error_response(fd,400,"Islem eksik");return;}
 char *out=NULL;size_t size=0;struct output *f=out_open(&out,&size);if(!f){error_response(fd,500,"Bellek yetersiz");return;}int status=200;
 if(!strcmp(op,"state"))state_json(f);
 else if(!strcmp(op,"config")){out_puts("{\"root\":",f);json(f,root);out_puts(",\"extract_root\":",f);json(f,extract_root);out_puts(",\"package\":",f);json(f,package);out_char('}',f);}
 else if(!strcmp(op,"locations")){
  out_puts("{\"locations\":[",f);size_t count=0;char canonical[FL_PATH];
#ifdef FL_HOST
  const char *paths[]={host_storage_root};const char *names[]={"Önizleme diski"};
#else
  const char *paths[]={"/mnt/ext0","/mnt/ext1","/mnt/usb0","/mnt/usb1","/mnt/usb2","/mnt/usb3","/mnt/usb4","/mnt/usb5","/mnt/usb6","/mnt/usb7","/data"};
  const char *names[]={"Harici disk · ext0","Harici disk · ext1","USB 0","USB 1","USB 2","USB 3","USB 4","USB 5","USB 6","USB 7","Dahili disk · data"};
#endif
  for(size_t i=0;i<sizeof(paths)/sizeof(paths[0]);i++){if(!fl_allowed_directory(paths[i],canonical))continue;if(count++)out_char(',',f);out_puts("{\"name\":",f);json(f,names[i]);out_puts(",\"path\":",f);json(f,canonical);out_char('}',f);}out_puts("]}",f);
 }
 else if(!strcmp(op,"browse")||!strcmp(op,"files")){
  char real[FL_PATH];if(field(body,"path",path,sizeof(path))!=1||!fl_allowed_directory(path,real)){status=400;out_puts("{\"error\":\"Klasor okunamadi veya desteklenen depolamada degil.\"}",f);}
  else{out_puts("{\"path\":",f);json(f,real);char parent[FL_PATH];snprintf(parent,sizeof(parent),"%s",real);char *slash=strrchr(parent,'/');if(slash&&slash!=parent)*slash=0;char resolved[FL_PATH];out_puts(",\"parent\":",f);json(f,fl_allowed_directory(parent,resolved)?resolved:"");out_puts(",\"directories\":[",f);
   for(int kind=0;kind<2;kind++){
    if(kind)out_puts("],\"packages\":[",f);
    DIR *dir=opendir(real);struct dirent *e;size_t n=0;
    if(dir){while((e=readdir(dir))&&n<512){
     if(e->d_name[0]=='.')continue;char child[FL_PATH];struct stat st;
     if(fl_join(child,sizeof(child),real,e->d_name)||lstat(child,&st))continue;
     if(!kind&&!S_ISDIR(st.st_mode))continue;
     size_t len=strlen(e->d_name);
     if(kind&&(strcmp(op,"files")||!S_ISREG(st.st_mode)||len<4||strcasecmp(e->d_name+len-4,".pkg")))continue;
     if(n++)out_char(',',f);out_puts("{\"name\":",f);json(f,e->d_name);out_puts(",\"path\":",f);json(f,child);if(kind)out_printf(f,",\"size\":%llu",(unsigned long long)st.st_size);out_char('}',f);
    }closedir(dir);}
   }out_puts("]}",f);
  }
 }
 else if(!strcmp(op,"scan")){
  pthread_mutex_lock(&state_lock);int active=busy;pthread_mutex_unlock(&state_lock);char real[FL_PATH],err[256];
  if(active){status=409;out_puts("{\"error\":\"Baslatma surerken klasor degistirilemez.\"}",f);}
  else if(field(body,"path",path,sizeof(path))!=1||!fl_allowed_directory(path,real)||fl_scan(real,games,&game_count,err,sizeof(err))){status=400;out_puts("{\"error\":\"Oyun klasoru okunamadi. Konumu kontrol edin.\"}",f);game_count=0;}
  else{snprintf(root,sizeof(root),"%s",real);revision++;int saved=save_config();out_puts("{\"root\":",f);json(f,root);out_printf(f,",\"saved\":%s,\"games\":[",saved?"false":"true");for(size_t i=0;i<game_count;i++){if(i)out_char(',',f);out_puts("{\"id\":",f);json(f,games[i].id);out_puts(",\"title\":",f);json(f,games[i].title);out_puts(",\"version\":",f);json(f,games[i].version);out_puts(",\"path\":",f);json(f,games[i].path);out_puts(",\"release\":",f);json(f,"");out_printf(f,",\"icon\":\"/icon/%u/%zu\"",revision,i);out_char('}',f);}out_puts("]}",f);}
 }
 else if(!strcmp(op,"extract")||!strcmp(op,"restore-permissions")){
  char source[FL_PATH]="",target[FL_PATH]="",canonical[FL_PATH],parent[FL_PATH];struct stat st;
  const char *code=NULL,*reason=NULL,*detail=NULL;
  if(field(body,"source",source,sizeof(source))!=1||!source[0]||field(body,"target",target,sizeof(target))!=1||!target[0]){
   code="GODA-PKG-INPUT";reason="Bir PKG dosyası ve çıkarma konumu seç.";detail="Missing, duplicate, overlong or invalid source/target field.";
  }else if(!fl_allowed_directory(target,canonical)){
   code="GODA-PKG-TARGET";reason="Çıkarma konumu bulunamadı veya izin verilen depolama alanında değil. Konum seç ile mevcut bir klasör seç.";detail="Target must be an existing canonical allowed storage directory.";
  }else{
   snprintf(parent,sizeof(parent),"%s",source);char *slash=strrchr(parent,'/');
   int valid=0;if(slash&&slash!=parent){*slash=0;char realparent[FL_PATH],realfile[FL_PATH];valid=fl_allowed_directory(parent,realparent)&&!strcmp(parent,realparent)&&realpath(source,realfile)&&!strcmp(source,realfile)&&!lstat(source,&st)&&S_ISREG(st.st_mode);}
   if(!valid){code="GODA-PKG-SOURCE";reason="PKG dosyası bulunamadı veya bu konumdan okunamıyor. Aktarımı kontrol edip dosyayı yeniden seç.";detail="Source must be a regular file at an exact canonical allowed path; symbolic links are rejected.";}
  }
  pthread_mutex_lock(&state_lock);
  if(busy){status=409;out_puts("{\"error\":\"Başka bir işlem sürüyor. Tamamlanmasını bekle.\",\"code\":\"GODA-PKG-BUSY\",\"stage\":\"request\"}",f);}
  else if(code){status=400;remember_error(code,reason,detail,"request validation",source,target,400);failure_json(f);}
  else{
   snprintf(job_source,sizeof(job_source),"%s",source);snprintf(job_target,sizeof(job_target),"%s",canonical);if(!strcmp(op,"extract")){snprintf(package,sizeof(package),"%s",source);snprintf(extract_root,sizeof(extract_root),"%s",canonical);save_config();save_extract_config();}
   failure.code[0]=0;busy=1;job_kind=!strcmp(op,"restore-permissions")?3:2;job_result=0;job_done=job_total=0;extraction_cancel=0;snprintf(message,sizeof(message),"Paket denetleniyor...");
   pthread_t t;if(pthread_create(&t,NULL,worker,NULL)){busy=0;status=500;remember_error("GODA-PKG-TASK","Çıkarma görevi başlatılamadı. İşlem yapılmadı.","pthread_create failed; no extraction worker started.","worker creation",source,canonical,500);failure_json(f);}else{pthread_detach(t);out_puts(!strcmp(op,"restore-permissions")?"{\"message\":\"Paketin dosya izinleri geri yukleniyor.\"}":"{\"message\":\"PS5 uzerinde cikarma baslatildi.\"}",f);}
  }pthread_mutex_unlock(&state_lock);
 }
 else if(!strcmp(op,"cancel")){
  pthread_mutex_lock(&state_lock);if(busy&&job_kind==2){extraction_cancel=1;out_puts("{\"message\":\"Durdurma istendi; mevcut dosya yazimi guvenle sonlandiriliyor.\"}",f);}else{status=409;out_puts("{\"error\":\"Etkin cikarma islemi yok.\"}",f);}pthread_mutex_unlock(&state_lock);
 }
 else if(!strcmp(op,"dismiss-ui")){
  /* Navigation-only diagnostic: never closes or launches a game. Reuse the
   * production pre-launch browser path, and refuse any active lifecycle. */
  pthread_mutex_lock(&state_lock);
  if(busy||fl_lifecycle_busy()){status=409;out_puts("{\"error\":\"Etkin islem sirasinda arayuz testi yapilamaz.\"}",f);}
  else{busy=1;job_kind=4;job_result=0;job_done=job_total=0;pthread_t t;
   if(pthread_create(&t,NULL,worker,NULL)){busy=0;status=500;out_puts("{\"error\":\"Arayuz gorevi olusturulamadi.\"}",f);}
   else{pthread_detach(t);out_puts("{\"message\":\"Yalniz arayuz kapatma istendi; oyun baslatilmayacak.\"}",f);}
  }pthread_mutex_unlock(&state_lock);
 }
 else if(!strcmp(op,"launch")){
  if(field(body,"id",id,sizeof(id))!=1||!fl_title_id(id)){status=400;out_puts("{\"error\":\"Gecersiz oyun\"}",f);}
  else{int has_path=field(body,"path",path,sizeof(path));
   if(has_path<0){out_close(f);free(out);error_response(fd,400,"Gecersiz oyun yolu");return;}
   pthread_mutex_lock(&state_lock);size_t i=game_count,matches=0;
   for(size_t j=0;j<game_count;j++)if(!strcmp(id,games[j].id)&&(!has_path||!strcmp(path,games[j].path))){i=j;matches++;}
   if(matches!=1)i=game_count;
   if(busy||i==game_count){status=409;out_puts("{\"error\":\"Baslatma suruyor veya oyun listede yok.\"}",f);}
   else{selected=games[i];busy=1;job_kind=1;job_done=job_total=0;job_result=0;snprintf(message,sizeof(message),"Secilen oyun denetleniyor...");pthread_t t;if(pthread_create(&t,NULL,worker,NULL)){busy=0;status=500;out_puts("{\"error\":\"Baslatma gorevi olusturulamadi.\"}",f);}else{pthread_detach(t);out_puts("{\"message\":\"Baslatma istegi alindi.\"}",f);}}
   pthread_mutex_unlock(&state_lock);
  }
 }else{status=404;out_puts("{\"error\":\"Bilinmeyen islem\"}",f);}
 out_close(f);response(fd,status,"application/json; charset=utf-8",out,size);free(out);
}
static void handle(int fd){
 char buf[8192];size_t used=0;char *end=NULL;while(used<sizeof(buf)-1){ssize_t n=recv(fd,buf+used,sizeof(buf)-1-used,0);if(n<0&&errno==EINTR)continue;if(n<=0)return;used+=(size_t)n;buf[used]=0;end=strstr(buf,"\r\n\r\n");if(end)break;}
 if(!end){error_response(fd,400,"HTTP basligi uzun");return;}size_t header=(size_t)(end+4-buf);char method[8],url[128],version[16];if(sscanf(buf,"%7s %127s %15s",method,url,version)!=3){error_response(fd,400,"HTTP istegi bozuk");return;}
 if(memchr(buf,0,header)){error_response(fd,400,"Gecersiz HTTP basligi");return;}
 int local_source=fl_http_local_request(buf,end);
 if(!strcmp(method,"GET")&&!local_source){error_response(fd,403,"Gecersiz yerel istek kaynagi");return;}
 if(!strcmp(method,"GET")&&!strncmp(url,"/assets/",8)){
  for(size_t i=0;i<sizeof(fl_assets)/sizeof(fl_assets[0]);i++)if(!strcmp(url,fl_assets[i].route)){response(fd,200,"image/png",fl_assets[i].data,fl_assets[i].size);return;}
  error_response(fd,404,"Gorsel bulunamadi");return;
 }
 if(!strcmp(method,"GET")&&!strncmp(url,"/icon/",6)){icon_response(fd,url);return;}
 if(!strcmp(method,"GET")&&!strcmp(url,"/")){const char *ui=(const char*)fl_ui;const char *slot=strstr(ui,"__TOKEN__");char *out=NULL;size_t n=0;struct output *f=out_open(&out,&n);if(!f||!slot){if(f)out_close(f);free(out);return;}out_write(f,ui,(size_t)(slot-ui));out_puts(token,f);out_puts(slot+9,f);out_close(f);response(fd,200,"text/html; charset=utf-8",out,n);free(out);return;}
 if(strcmp(method,"POST")||strcmp(url,"/api")){error_response(fd,404,"Bulunamadi");return;}
 size_t length=0;int count=0;char *line=strstr(buf,"\r\n");while(line&&line+2<end){line+=2;char *next=strstr(line,"\r\n");if(!next)break;if(!strncasecmp(line,"Content-Length:",15)){char *tail;unsigned long long v=strtoull(line+15,&tail,10);while(tail<next&&*tail==' ')tail++;if(tail!=next||v>4096||count++){error_response(fd,400,"Gecersiz istek boyutu");return;}length=(size_t)v;}if(!strncasecmp(line,"Transfer-Encoding:",18)){error_response(fd,400,"Parcali istek desteklenmiyor");return;}line=next;}
 if(!count||header+length>=sizeof(buf)){error_response(fd,400,"Istek govdesi eksik");return;}
 while(used<header+length){ssize_t n=recv(fd,buf+used,header+length-used,0);if(n<0&&errno==EINTR)continue;if(n<=0)return;used+=(size_t)n;}buf[header+length]=0;if(memchr(buf+header,0,length)){error_response(fd,400,"Gecersiz metin");return;}
 /* Consume only the bounded declared body before rejecting POST, so closing
  * an unread socket does not discard the error response with a TCP reset. */
 if(!local_source){error_response(fd,403,"Gecersiz yerel istek kaynagi");return;}api(fd,buf+header);
}
static void default_root(void){
#ifndef FL_HOST
 const char *disks[]={"/mnt/ext1","/mnt/ext0","/mnt/usb0","/mnt/usb1","/mnt/usb2","/mnt/usb3","/mnt/usb4","/mnt/usb5","/mnt/usb6","/mnt/usb7","/data"};
 char candidate[FL_PATH],canonical[FL_PATH];
 for(unsigned pass=0;pass<2;pass++)for(size_t i=0;i<sizeof(disks)/sizeof(disks[0]);i++){
  if(pass)snprintf(candidate,sizeof(candidate),"%s",disks[i]);else if(fl_join(candidate,sizeof(candidate),disks[i],"PS4"))continue;
  if(fl_allowed_directory(candidate,canonical)){snprintf(root,sizeof(root),"%s",canonical);return;}
 }
#endif
}
int main(int argc,char **argv){
 signal(SIGPIPE,SIG_IGN);signal(SIGINT,stop);signal(SIGTERM,stop);
#ifdef FL_HOST
 if(argc<2){fprintf(stderr,"Usage: %s HOST_ROOT\n",argv[0]);return 1;}char resolved[FL_PATH];if(!realpath(argv[1],resolved))return 1;fl_set_host_root(resolved);snprintf(root,sizeof(root),"%s",resolved);snprintf(host_storage_root,sizeof(host_storage_root),"%s",resolved);if(fl_join(config_dir,sizeof(config_dir),resolved,".loader-preview"))return 1;
#else
 (void)argc;(void)argv;
#endif
 unsigned char random[24];arc4random_buf(random,sizeof(random));for(size_t i=0;i<sizeof(random);i++)snprintf(token+i*2,3,"%02x",random[i]);default_root();load_config();snprintf(extract_root,sizeof(extract_root),"%s",root);load_extract_config();
 int server=socket(AF_INET,SOCK_STREAM,0);if(server<0)return 1;int reuse=1;setsockopt(server,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));struct sockaddr_in addr={0};addr.sin_family=AF_INET;addr.sin_port=htons(PORT);addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 if(bind(server,(struct sockaddr*)&addr,sizeof(addr))||listen(server,8)){close(server);return 1;}
 runtime_log();
#ifndef FL_HOST
 extern int sceUserServiceInitialize(void*);extern int sceSystemServiceLaunchWebBrowser(const char*,void*);
 int user_init=sceUserServiceInitialize(NULL);
 int browser=user_init<0?user_init:sceSystemServiceLaunchWebBrowser("http://127.0.0.1:9134/",NULL);
 /* Native services must be initialized before opening the browser. Record
  * failures without invoking another navigation strategy. */
 FILE *browser_log=fopen("/data/ps4-folder-loader-browser.log","a");if(browser_log){fprintf(browser_log,"loader_browser user_init=0x%08x open_rc=0x%08x\n",(unsigned)user_init,(unsigned)browser);fflush(browser_log);fsync(fileno(browser_log));fclose(browser_log);}
#endif
 printf("Goda UI listening on 127.0.0.1:%d\n",PORT);fflush(stdout);
 while(!stopping||fl_lifecycle_busy()){runtime_log();fd_set reads;FD_ZERO(&reads);FD_SET(server,&reads);struct timeval wait={1,0};int ready=select(server+1,&reads,NULL,NULL,&wait);if(ready<0){if(errno==EINTR)continue;break;}if(!ready)continue;int fd=accept(server,NULL,NULL);if(fd<0)continue;struct timeval tv={3,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));handle(fd);close(fd);}
 close(server);for(;;){pthread_mutex_lock(&state_lock);int active=busy;pthread_mutex_unlock(&state_lock);if(!active)break;usleep(100000);}return 0;
}
