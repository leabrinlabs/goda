/* GPL-3.0-or-later. Read-only directory/SFO discovery. No game writes. */
#include "catalog.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
static char host_root[FL_PATH];
void fl_set_host_root(const char *s){if(s)snprintf(host_root,sizeof(host_root),"%s",s);}
static int under(const char *p,const char *r){size_t n=strlen(r);return !strncmp(p,r,n)&&(!p[n]||p[n]=='/');}
int fl_title_id(const char *s){if(!s||strlen(s)!=9||strncmp(s,"CUSA",4))return 0;for(int i=4;i<9;i++)if(s[i]<'0'||s[i]>'9')return 0;return 1;}
int fl_join(char *out,size_t cap,const char *a,const char *b){int n=snprintf(out,cap,"%s%s%s",a,a[0]&&a[strlen(a)-1]=='/'?"":"/",b);return n<0||(size_t)n>=cap?-1:0;}
int fl_allowed_directory(const char *p,char out[FL_PATH]){
 struct stat st;if(!p||strlen(p)>=FL_PATH||!realpath(p,out)||stat(out,&st)||!S_ISDIR(st.st_mode))return 0;
#ifdef FL_HOST
 return host_root[0]&&under(out,host_root);
#else
 const char *roots[]={"/mnt/ext0","/mnt/ext1","/mnt/usb0","/mnt/usb1","/mnt/usb2","/mnt/usb3","/mnt/usb4","/mnt/usb5","/mnt/usb6","/mnt/usb7","/data"};
 for(size_t i=0;i<sizeof(roots)/sizeof(roots[0]);i++)if(under(out,roots[i]))return 1;
 return 0;
#endif
}
static uint16_t u16(const unsigned char *p){return (uint16_t)(p[0]|p[1]<<8);}
static uint32_t u32(const unsigned char *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static int fail(char *out,size_t cap,const char *s){snprintf(out,cap,"%s",s);return -1;}
int fl_sfo(const unsigned char *b,size_t n,struct fl_game *g,char *error,size_t cap){
 if(n<20||memcmp(b,"\0PSF",4)||(u32(b+4)!=0x100&&u32(b+4)!=0x101))return fail(error,cap,"Gecersiz param.sfo");
 size_t ko=u32(b+8),vo=u32(b+12),count=u32(b+16);if(count>4096||20+count*16>ko||ko>vo||vo>n)return fail(error,cap,"SFO sinirlari gecersiz");
 char category[16]="";unsigned seen=0;
 for(size_t i=0;i<count;i++){
  const unsigned char *e=b+20+i*16;size_t kr=u16(e),len=u32(e+4),max=u32(e+8),vr=u32(e+12);
  if(kr>=vo-ko||vr>n-vo||len>n-vo-vr||max<len||max>n-vo-vr)return fail(error,cap,"SFO kaydi bozuk");
  const char *key=(const char*)b+ko+kr;const char *value=(const char*)b+vo+vr;if(!memchr(key,0,vo-ko-kr))return fail(error,cap,"SFO anahtari bozuk");
  char *dest=NULL;size_t destcap=0;unsigned flag=0;
  if(!strcmp(key,"TITLE_ID")){dest=g->id;destcap=sizeof(g->id);flag=1;}
  else if(!strcmp(key,"TITLE")){dest=g->title;destcap=sizeof(g->title);flag=2;}
  else if(!strcmp(key,"APP_VER")){dest=g->version;destcap=sizeof(g->version);flag=4;}
  else if(!strcmp(key,"CATEGORY")){dest=category;destcap=sizeof(category);flag=8;}
  if(!dest)continue;
  if(seen&flag||u16(e+2)!=0x204||!len||value[len-1]||memchr(value,0,len-1)||len>destcap)return fail(error,cap,"SFO metin kaydi gecersiz");
  memcpy(dest,value,len);seen|=flag;
 }
 if(!fl_title_id(g->id)||strcmp(category,"gd"))return fail(error,cap,"CUSA ana oyun klasoru gerekli; guncelleme klasoru secilemez");
 if(!g->title[0])snprintf(g->title,sizeof(g->title),"%s",g->id);return 0;
}
int fl_inspect_game(const char *path,struct fl_game *g,char *error,size_t cap){
 memset(g,0,sizeof(*g));char real[FL_PATH],file[FL_PATH];struct stat st;
 if(!fl_allowed_directory(path,real)||strcmp(real,path))return fail(error,cap,"Klasor desteklenen depolamada ve dogrudan bir dizin olmali");

 if(fl_join(file,sizeof(file),real,".ps4fl-incomplete"))return -1;
 if(!lstat(file,&st)||errno!=ENOENT)return fail(error,cap,"Cikarma tamamlanmamis");
 if(fl_join(file,sizeof(file),real,"sce_sys")||lstat(file,&st)||!S_ISDIR(st.st_mode))return fail(error,cap,"sce_sys eksik veya baglanti");
 if(fl_join(file,sizeof(file),real,"sce_sys/param.sfo"))return -1;
 int fd=open(file,O_RDONLY|O_NOFOLLOW);if(fd<0)return fail(error,cap,"param.sfo okunamadi");
 if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<20||st.st_size>512*1024){close(fd);return fail(error,cap,"SFO dosya boyutu gecersiz");}
 size_t n=(size_t)st.st_size;unsigned char *b=malloc(n);if(!b){close(fd);return fail(error,cap,"Bellek yetersiz");}size_t got=0;
 while(got<n){ssize_t r=read(fd,b+got,n-got);if(r<0&&errno==EINTR)continue;if(r<=0)break;got+=(size_t)r;}close(fd);
 int rc=got==n?fl_sfo(b,n,g,error,cap):fail(error,cap,"SFO eksik okundu");free(b);if(rc)return rc;

 if(fl_join(file,sizeof(file),real,"eboot.bin"))return -1;fd=open(file,O_RDONLY|O_NOFOLLOW);unsigned char magic[4];
 if(fd<0)return fail(error,cap,"eboot.bin eksik");rc=fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<64||read(fd,magic,4)!=4;close(fd);
 if(rc||(!(!memcmp(magic,"\x7f" "ELF",4))&&memcmp(magic,"\x4f\x15\x3d\x1d",4)))return fail(error,cap,"eboot.bin ELF/SELF olarak taninmadi");
 snprintf(g->path,sizeof(g->path),"%s",real);return 0;
}
static int order(const void *a,const void *b){const struct fl_game *x=a,*y=b;int n=strcmp(x->title,y->title);return n?n:strcmp(x->id,y->id);}
static int scan_level(const char *path,struct fl_game *games,size_t *count,unsigned depth,unsigned *visited,char *error,size_t cap){
 if(++*visited>4096)return fail(error,cap,"Tarama 4096 klasor sinirina ulasti; daha yakin bir oyun klasoru secin");
 struct fl_game g;char reason[256],candidate[FL_PATH];struct stat st;
 int has_sfo=!fl_join(candidate,sizeof(candidate),path,"sce_sys/param.sfo")&&!lstat(candidate,&st)&&S_ISREG(st.st_mode);
 int has_eboot=!fl_join(candidate,sizeof(candidate),path,"eboot.bin")&&!lstat(candidate,&st)&&S_ISREG(st.st_mode);
 if(has_sfo||has_eboot){
  if(!fl_inspect_game(path,&g,reason,sizeof(reason))){if(*count>=FL_MAX_GAMES)return fail(error,cap,"Oyun listesi 512 sinirini asti");games[(*count)++]=g;}
  return 0; /* Never recurse through a game's asset tree, including invalid dumps. */
 }
 if(depth>=6)return 0;
 DIR *dir=opendir(path);if(!dir)return 0;struct dirent *ent;int rc=0;
 while((ent=readdir(dir))){if(ent->d_name[0]=='.')continue;char child[FL_PATH],canonical[FL_PATH];
  if(fl_join(child,sizeof(child),path,ent->d_name)||lstat(child,&st)||!S_ISDIR(st.st_mode)||!fl_allowed_directory(child,canonical)||strcmp(child,canonical))continue;
  rc=scan_level(child,games,count,depth+1,visited,error,cap);if(rc)break;
 }closedir(dir);return rc;
}
int fl_scan(const char *root,struct fl_game *games,size_t *count,char *error,size_t cap){
 *count=0;char real[FL_PATH];if(!fl_allowed_directory(root,real))return fail(error,cap,"Oyun kok klasoru okunamadi");
 unsigned visited=0;int rc=scan_level(real,games,count,0,&visited,error,cap);qsort(games,*count,sizeof(*games),order);return rc;
}
