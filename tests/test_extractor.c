/* Mock-package integration tests: new temporary fixture files only. */
#include "../extractor.h"
#include "../extract_reader.h"
#include "../catalog.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
struct fl_pkg_reader {int fd;};
static struct fl_pkg_reader reader;
static uint8_t sfo[512];static size_t sfo_n;
static int badmeta,case_names,badpath,conflict;
static fl_pkg_file items[3];
static const uint8_t boot[]={0x4f,0x15,0x3d,0x1d,1,2,3,4};
static void p16(uint8_t *p,unsigned x){p[0]=x;p[1]=x>>8;}
static void p32(uint8_t *p,unsigned x){for(int i=0;i<4;i++)p[i]=(uint8_t)(x>>(8*i));}
static void make_sfo(const char *category){memset(sfo,0,sizeof(sfo));memcpy(sfo,"\0PSF",4);p32(sfo+4,0x101);p32(sfo+8,68);p32(sfo+12,128);p32(sfo+16,3);const char *keys[]={"TITLE_ID","CATEGORY","APP_VER"};const char *vals[]={"CUSA12345",category,"01.46"};unsigned ko=0,vo=0;for(unsigned i=0;i<3;i++){uint8_t *e=sfo+20+i*16;p16(e,ko);p16(e+2,0x204);unsigned n=(unsigned)strlen(vals[i])+1;p32(e+4,n);p32(e+8,n);p32(e+12,vo);strcpy((char*)sfo+68+ko,keys[i]);strcpy((char*)sfo+128+vo,vals[i]);ko+=(unsigned)strlen(keys[i])+1;vo+=n;}sfo_n=128+vo;}
fl_pkg_reader *fl_pkg_open(const char *path,char *e,size_t cap){(void)e;(void)cap;reader.fd=open(path,O_RDONLY|O_NOFOLLOW);return reader.fd<0?NULL:&reader;}
void fl_pkg_close(fl_pkg_reader *r){if(r)close(r->fd);}
const char *fl_pkg_error(const fl_pkg_reader *r){(void)r;return "mock source failure";}
const char *fl_pkg_content_id(const fl_pkg_reader *r){(void)r;return "EP0000-CUSA12345_00-FIXTURE000000000";}
int fl_pkg_source_stat(const fl_pkg_reader *r,struct stat *s){return fstat(r->fd,s);}
uint32_t fl_pkg_file_mode(const fl_pkg_reader *r,size_t index){(void)r;return index==0?0555:0644;}
size_t fl_pkg_file_count(const fl_pkg_reader *r){(void)r;return case_names?3:2;}
const fl_pkg_file *fl_pkg_files(const fl_pkg_reader *r){(void)r;items[0]=(fl_pkg_file){"eboot.bin",0,sizeof(boot)};items[1]=(fl_pkg_file){case_names?"Data/a":badpath?"../escape":"sce_sys/param.sfo",1,case_names?sizeof(boot):sfo_n};items[2]=(fl_pkg_file){"data/b",2,sizeof(boot)};return items;}
int fl_pkg_read(fl_pkg_reader *r,size_t i,uint64_t off,void *out,size_t n){(void)r;const uint8_t *p=i==1&&!case_names?sfo:boot;memcpy(out,p+off,n);if(conflict&&i==1&&n)((uint8_t*)out)[0]^=1;return 0;}
int fl_pkg_metadata_present(const fl_pkg_reader *r,uint32_t id){(void)r;return id==0x1000||id==0x403;}
uint8_t *fl_pkg_metadata_entry(fl_pkg_reader *r,uint32_t id,size_t *n){(void)r;if(badmeta&&id==0x403)return NULL;const uint8_t *p=id==0x1000?sfo:boot;*n=id==0x1000?sfo_n:sizeof(boot);uint8_t *o=malloc(*n);memcpy(o,p,*n);return o;}
static volatile sig_atomic_t cancel_flag;
static void cancel_notify(const char *p,uint64_t done,uint64_t total){(void)done;(void)total;if(!strcmp(p,"eboot.bin"))cancel_flag=1;}
static char attack_parent[FL_PATH],attack_target[FL_PATH];
static void symlink_notify(const char *p,uint64_t done,uint64_t total){(void)done;(void)total;if(!strcmp(p,"eboot.bin"))symlink(attack_target,attack_parent);}
static int exists(const char *p){struct stat s;return lstat(p,&s)==0;}
static void join(char *out,const char *a,const char *b){assert(!fl_join(out,FL_PATH,a,b));}
int main(void){char temp[]="/tmp/ps4fl-extractor-XXXXXX",*root=mkdtemp(temp);assert(root);char canonical[FL_PATH];assert(realpath(root,canonical));root=canonical;fl_set_host_root(root);char source[FL_PATH],dest[FL_PATH],out[FL_PATH],path[FL_PATH],target[FL_PATH];join(source,root,"source.pkg");int fd=open(source,O_CREAT|O_EXCL|O_WRONLY,0644);assert(fd>=0&&write(fd,"source fixture",14)==14);close(fd);make_sfo("gd");
join(dest,root,"success");assert(!mkdir(dest,0755));int first=fl_extract_pkg(source,dest,NULL,NULL,out,sizeof(out));if(first)fprintf(stderr,"FAIL %s\n",out);assert(!first);join(target,dest,"CUSA12345");assert(!strcmp(out,target));join(path,target,"eboot.bin");struct stat boot_stat;assert(!stat(path,&boot_stat)&&(boot_stat.st_mode&0777)==0555);join(path,target,".ps4fl-incomplete");assert(!exists(path));join(path,target,"sce_sys/npbind.dat");assert(exists(path));join(path,target,".ps4fl-manifest.json");assert(exists(path));
/* Early-alpha migration restores PFS mode and preserves all file contents. */
join(path,target,"eboot.bin");assert(!chmod(path,0644));assert(!fl_restore_permissions(source,target,NULL,out,sizeof(out)));assert(!stat(path,&boot_stat)&&(boot_stat.st_mode&0777)==0555);
/* Never overwrite an existing game directory. */
assert(fl_extract_pkg(source,dest,NULL,NULL,out,sizeof(out)));join(path,target,"eboot.bin");fd=open(path,O_RDONLY);uint8_t b[8];assert(read(fd,b,8)==8&&!memcmp(b,boot,8));close(fd);
join(dest,root,"cancel");assert(!mkdir(dest,0755));cancel_flag=0;assert(fl_extract_pkg(source,dest,cancel_notify,&cancel_flag,out,sizeof(out)));join(target,dest,"CUSA12345");join(path,target,".ps4fl-incomplete");assert(exists(path));
join(dest,root,"metadata-conflict");assert(!mkdir(dest,0755));conflict=1;assert(fl_extract_pkg(source,dest,NULL,NULL,out,sizeof(out)));conflict=0;join(target,dest,"CUSA12345");join(path,target,".ps4fl-incomplete");assert(exists(path));
join(dest,root,"badmeta");assert(!mkdir(dest,0755));badmeta=1;assert(fl_extract_pkg(source,dest,NULL,NULL,out,sizeof(out)));badmeta=0;join(target,dest,"CUSA12345");assert(!exists(target));
join(dest,root,"badpath");assert(!mkdir(dest,0755));badpath=1;assert(fl_extract_pkg(source,dest,NULL,NULL,out,sizeof(out)));badpath=0;join(target,dest,"CUSA12345");assert(!exists(target));
join(dest,root,"casefold");assert(!mkdir(dest,0755));case_names=1;assert(fl_extract_pkg(source,dest,NULL,NULL,out,sizeof(out)));case_names=0;join(target,dest,"CUSA12345");join(path,target,".ps4fl-incomplete");assert(exists(path));
join(dest,root,"symlink");assert(!mkdir(dest,0755));join(target,dest,"CUSA12345");join(attack_parent,target,"sce_sys");join(attack_target,root,"untouched");assert(!mkdir(attack_target,0755));assert(fl_extract_pkg(source,dest,symlink_notify,NULL,out,sizeof(out)));join(path,attack_target,"param.sfo");assert(!exists(path));join(path,target,".ps4fl-incomplete");assert(exists(path));
join(dest,root,"update");assert(!mkdir(dest,0755));make_sfo("gp");assert(!fl_extract_pkg(source,dest,NULL,NULL,out,sizeof(out)));join(target,dest,"CUSA12345_update_01.46");assert(!strcmp(out,target));
printf("PASS fresh extraction, metadata merge, no-overwrite, cancellation, incomplete marker, decode failure, traversal, case-fold collision, update output: %s\n",root);return 0;}
