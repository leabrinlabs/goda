#include "../module_alias.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
static void p16(unsigned char *p,unsigned x){p[0]=x;p[1]=x>>8;}
static void p32(unsigned char *p,unsigned x){for(int i=0;i<4;i++)p[i]=(unsigned char)(x>>(i*8));}
static void p64(unsigned char *p,unsigned long long x){for(int i=0;i<8;i++)p[i]=(unsigned char)(x>>(i*8));}
static void put(const char *path,const void *b,size_t n,mode_t mode){int fd=open(path,O_WRONLY|O_CREAT|O_EXCL,0600);assert(fd>=0);assert(write(fd,b,n)==(ssize_t)n);assert(!fchmod(fd,mode));close(fd);}
static void path(char *out,const char *a,const char *b){assert(!fl_join(out,FL_PATH,a,b));}
static void make_elf(unsigned char elf[1024],const char *needed,int self,unsigned char out[2048],size_t *len){memset(elf,0,1024);memcpy(elf,"\x7f" "ELF",4);elf[4]=2;elf[5]=1;p16(elf+18,62);p64(elf+32,64);p16(elf+54,56);p16(elf+56,2);p32(elf+64,2);p64(elf+72,256);p64(elf+96,64);p32(elf+120,0x61000000);p64(elf+128,512);p64(elf+152,256);p64(elf+256,0x61000035);p64(elf+264,0);p64(elf+272,0x61000037);p64(elf+280,strlen(needed)+1);p64(elf+288,1);p64(elf+296,0);strcpy((char*)elf+512,needed);if(!self){memcpy(out,elf,1024);*len=1024;return;}memset(out,0,2048);memcpy(out,"\x4f\x15\x3d\x1d",4);out[6]=1;p32(out+8,0x101);p16(out+24,2);p64(out+32,0);p64(out+40,512);p64(out+48,64);p64(out+64,1ull<<20);p64(out+72,768);p64(out+80,256);memcpy(out+96,elf,176);memcpy(out+512,elf+256,64);memcpy(out+768,elf+512,256);*len=1024;}
static void log_message(const char *s){fprintf(stderr,"%s\n",s);}
int main(void){char tmp[]="/tmp/ps4fl-alias-XXXXXX";char *raw=mkdtemp(tmp);assert(raw);char root[FL_PATH];assert(realpath(raw,root));char gamepath[FL_PATH],owned[FL_PATH],p[FL_PATH],dir[FL_PATH];path(gamepath,root,"game");assert(!mkdir(gamepath,0755));path(owned,root,"owned");fl_module_views_host_root(owned);path(dir,gamepath,"prx");assert(!mkdir(dir,0755));path(p,dir,"samplemodule.prx");const char content[]="original module bytes";put(p,content,sizeof(content),0555);unsigned char elf[1024],image[2048];size_t n;make_elf(elf,"SampleModule.prx",1,image,&n);path(p,gamepath,"eboot.bin");put(p,image,n,0555);struct fl_game g;memset(&g,0,sizeof(g));strcpy(g.id,"CUSA12345");strcpy(g.path,gamepath);struct fl_module_view views[FL_MODULE_VIEWS];size_t count;
 assert(!fl_prepare_module_views(&g,views,&count,log_message));assert(count==1&&!strcmp(views[0].relative,"prx"));path(p,views[0].source,"SampleModule.prx");struct stat st;assert(!stat(p,&st)&&(st.st_mode&0777)==0555);char got[sizeof(content)];int fd=open(p,O_RDONLY);assert(read(fd,got,sizeof(got))==(ssize_t)sizeof(got)&&!memcmp(got,content,sizeof(got)));close(fd);DIR *dd=opendir(dir);assert(dd);struct dirent *de;int regular=0;while((de=readdir(dd)))if(strcmp(de->d_name,".")&&strcmp(de->d_name,".."))regular++;closedir(dd);assert(regular==1);path(p,dir,"samplemodule.prx");assert(!stat(p,&st)&&(st.st_mode&0777)==0555);
 /* Duplicate case-insensitive source matches are ambiguous, never chosen. */
 char second[FL_PATH];path(second,gamepath,"sce_module");assert(!mkdir(second,0755));path(p,second,"SAMPLEMODULE.PRX");put(p,content,sizeof(content),0555);assert(fl_prepare_module_views(&g,views,&count,log_message)&&!count);assert(!unlink(p));
 /* Symlinks inside affected directory are refused rather than copied. */
 path(p,dir,"escape");assert(!symlink("/etc/passwd",p));assert(fl_prepare_module_views(&g,views,&count,log_message)&&!count);assert(!unlink(p));
 /* Unsafe dependency path is rejected. */
 path(p,gamepath,"eboot.bin");assert(!unlink(p));make_elf(elf,"../unsafe.prx",0,image,&n);put(p,image,n,0555);assert(fl_prepare_module_views(&g,views,&count,log_message)&&!count);
 /* Exact existing filename needs no owned copy or mount plan. */
 assert(!unlink(p));make_elf(elf,"samplemodule.prx",0,image,&n);put(p,image,n,0555);assert(!fl_prepare_module_views(&g,views,&count,log_message)&&!count);
 puts("PASS fakeSELF+ELF exactdependencies, ownedaliases, modes, originalunchanged, ambiguity, symlinks, traversal, no-op");return 0;}
