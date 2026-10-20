/* SPDX-License-Identifier: GPL-3.0-or-later
 * Bounded read-only fake-SELF / ELF dynamic dependency inspection and owned
 * module-directory copies. Format interpretation follows existing self_format.py
 * (OpenOrbis/shadPS4). Does not execute or rewrite the selected executable.
 */
#include "module_alias.h"
#include "vendor/crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include "platform_at.h"
#define NPH 64
#define NEEDED 256
#define MODULES 2048
#define COPY_MAX (512ull*1024*1024)
#define BUFFER_SIZE (256u*1024u)
struct segment {uint64_t offset,size,source;uint32_t type;};
struct image {int fd;uint64_t size,embedded;struct segment ph[NPH];size_t n;int self;};
struct module {char name[256];unsigned dir;struct stat st;};
struct dependency {char name[256];int match;};
struct context {fl_progress progress;struct image image;struct dependency *needed;size_t nneeded;struct module *modules;size_t nmodules;int gamefd,dirs[2],affected[2];uint64_t bytes;uint8_t *buffer;};
static const char *dirnames[]={"prx","sce_module"};
#ifdef FL_HOST
static char owned_root[FL_PATH];
void fl_module_views_host_root(const char *path){snprintf(owned_root,sizeof(owned_root),"%s",path?path:"");}
#else
static const char owned_root[]=FL_MODULE_OWNED_ROOT;
#endif
static uint16_t l16(const uint8_t *p){return (uint16_t)(p[0]|p[1]<<8);}
static uint32_t l32(const uint8_t *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint64_t l64(const uint8_t *p){return l32(p)|((uint64_t)l32(p+4)<<32);}
static int range(uint64_t size,uint64_t at,uint64_t n){return at<=size&&n<=size-at;}
static void module_log(const char *s){
#ifndef FL_HOST
 int saved=errno;FILE *f=fopen("/data/ps4-folder-loader-modules.log","a");if(f){fprintf(f,"%s (errno=%d)\n",s,saved);fclose(f);}errno=saved;
#else
 (void)s;
#endif
}
static int fail(struct context *c,const char *s){module_log(s);if(c->progress)c->progress(s);return -1;}
static int read_at(int fd,uint64_t at,void *out,size_t n){uint8_t *p=out;while(n){ssize_t z=pread(fd,p,n,(off_t)at);if(z<0&&errno==EINTR)continue;if(z<=0)return -1;p+=z;at+=(uint64_t)z;n-=(size_t)z;}return 0;}
static int image_read(struct image *i,uint64_t at,void *out,size_t n){if(!i->self)return range(i->size,at,n)?read_at(i->fd,at,out,n):-1;for(size_t k=0;k<i->n;k++){struct segment *p=&i->ph[k];if(p->source!=UINT64_MAX&&at>=p->offset&&range(p->size,at-p->offset,n))return read_at(i->fd,p->source+(at-p->offset),out,n);}return -1;}
static int dependency_name(const char *s){size_t n=strlen(s);if(!n||n>255||!strcmp(s,".")||!strcmp(s,".."))return 0;for(size_t k=0;k<n;k++)if((unsigned char)s[k]<32||(unsigned char)s[k]>126||s[k]=='/'||s[k]=='\\'||s[k]==':')return 0;return 1;}
static int parse_needed(struct context *c){struct image *i=&c->image;uint8_t head[64],elf[64];struct stat st;if(fstat(i->fd,&st)||!S_ISREG(st.st_mode)||st.st_size<64)return fail(c,"Module inspection: invalid executable");i->size=(uint64_t)st.st_size;if(read_at(i->fd,0,head,64))return -1;uint16_t entries=0;
 if(!memcmp(head,"\x4f\x15\x3d\x1d",4)){i->self=1;entries=l16(head+24);if(!entries||entries>128||head[6]!=1||l32(head+8)!=0x101)return fail(c,"Module inspection: unsupported SELF header");i->embedded=32+(uint64_t)entries*32;if(!range(i->size,i->embedded,64)||read_at(i->fd,i->embedded,elf,64))return -1;}
 else memcpy(elf,head,64);
 if(memcmp(elf,"\x7f" "ELF",4)||elf[4]!=2||elf[5]!=1||l16(elf+18)!=62||l16(elf+54)!=56)return fail(c,"Module inspection: unsupported ELF");
 uint64_t phoff=l64(elf+32);i->n=l16(elf+56);if(!i->n||i->n>NPH||!range(i->size,i->embedded,phoff)||!range(i->size,i->embedded+phoff,i->n*56))return fail(c,"Module inspection: invalid program table");
 for(size_t k=0;k<i->n;k++){uint8_t ph[56];if(read_at(i->fd,i->embedded+phoff+k*56,ph,56))return -1;i->ph[k]=(struct segment){l64(ph+8),l64(ph+32),UINT64_MAX,l32(ph)};if(i->ph[k].offset>UINT64_MAX-i->ph[k].size)return fail(c,"Module inspection: segment range overflow");if(!i->self){if(!range(i->size,i->ph[k].offset,i->ph[k].size))return -1;i->ph[k].source=i->ph[k].offset;}}
 if(i->self)for(unsigned k=0;k<entries;k++){uint8_t e[32];if(read_at(i->fd,32+(uint64_t)k*32,e,32))return -1;uint64_t flags=l64(e),at=l64(e+8),n=l64(e+16);if(flags&0x10000)continue;if(flags&(2|8))return fail(c,"Module inspection: encrypted/compressed SELF unsupported");unsigned pi=(unsigned)((flags>>20)&0xffff);if(pi>=i->n||n!=i->ph[pi].size||!range(i->size,at,n)||i->ph[pi].source!=UINT64_MAX)return fail(c,"Module inspection: invalid SELF segment");i->ph[pi].source=at;}
 struct segment *dyn=NULL,*data=NULL;for(size_t k=0;k<i->n;k++){if(i->ph[k].type==2){if(dyn)return -1;dyn=&i->ph[k];}if(i->ph[k].type==0x61000000){if(data)return -1;data=&i->ph[k];}}
 if(!dyn)return 0;if(!data||dyn->size>65536||dyn->size%16)return fail(c,"Module inspection: dynamic table unsupported");
 uint64_t str=UINT64_MAX,sz=0,offsets[NEEDED];size_t no=0;int end=0;
 for(uint64_t at=0;at<dyn->size;at+=16){uint8_t d[16];if(image_read(i,dyn->offset+at,d,16))return -1;uint64_t t=l64(d),v=l64(d+8);if(!t){end=1;break;}if(t==0x61000035){if(str!=UINT64_MAX)return -1;str=v;}if(t==0x61000037){if(sz)return -1;sz=v;}if(t==1){if(no>=NEEDED)return fail(c,"Module inspection: dependency limit exceeded");offsets[no++]=v;}}
 if(!end)return -1;if(!no)return 0;if(str==UINT64_MAX||!sz||sz>1024*1024||!range(data->size,str,sz))return fail(c,"Module inspection: invalid string table");
 char *strings=malloc((size_t)sz);if(!strings)return -1;if(image_read(i,data->offset+str,strings,(size_t)sz)){free(strings);return -1;}
 for(size_t k=0;k<no;k++){if(offsets[k]>=sz||!memchr(strings+offsets[k],0,(size_t)(sz-offsets[k]))||!dependency_name(strings+offsets[k])){free(strings);return fail(c,"Module inspection: unsafe dependency name");}const char *s=strings+offsets[k];int duplicate=0;for(size_t j=0;j<c->nneeded;j++)if(!strcmp(c->needed[j].name,s))duplicate=1;if(!duplicate){snprintf(c->needed[c->nneeded].name,256,"%s",s);c->needed[c->nneeded++].match=-1;}}
 free(strings);return 0;
}
static int is_module(const char *name){const char *ext=strrchr(name,'.');return ext&&(!strcasecmp(ext,".prx")||!strcasecmp(ext,".sprx"));}
static int scan_modules(struct context *c){for(unsigned dir=0;dir<2;dir++){c->dirs[dir]=openat(c->gamefd,dirnames[dir],O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(c->dirs[dir]<0){if(errno==ENOENT)continue;return fail(c,"Module directory cannot be inspected safely");}int scan=openat(c->dirs[dir],".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(scan<0)return -1;DIR *d=fdopendir(scan);if(!d){close(scan);return -1;}struct dirent *ent;int rc=0;while((ent=readdir(d))){if(!strcmp(ent->d_name,".")||!strcmp(ent->d_name,".."))continue;if(!is_module(ent->d_name))continue;struct stat st;if(!dependency_name(ent->d_name)||fstatat(c->dirs[dir],ent->d_name,&st,AT_SYMLINK_NOFOLLOW)||!S_ISREG(st.st_mode)||st.st_size<0||c->nmodules>=MODULES){rc=-1;break;}struct module *m=&c->modules[c->nmodules++];snprintf(m->name,sizeof(m->name),"%s",ent->d_name);m->dir=dir;m->st=st;}closedir(d);if(rc)return fail(c,"Unsafe or excessive module entries");}
 for(size_t k=0;k<c->nneeded;k++){struct dependency *d=&c->needed[k];size_t matches=0;for(size_t j=0;j<c->nmodules;j++)if(!strcasecmp(d->name,c->modules[j].name)){d->match=(int)j;matches++;}if(matches>1)return fail(c,"Ambiguous case-insensitive module match; refusing alias");if(matches==1&&strcmp(d->name,c->modules[d->match].name))c->affected[c->modules[d->match].dir]=1;
  if(!matches&&is_module(d->name)){struct stat st;if(!fstatat(c->gamefd,d->name,&st,AT_SYMLINK_NOFOLLOW))continue;int scan=openat(c->gamefd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(scan<0)return -1;DIR *root=fdopendir(scan);if(!root){close(scan);return -1;}struct dirent *e;int mismatch=0;while((e=readdir(root)))if(!strcasecmp(d->name,e->d_name)&&strcmp(d->name,e->d_name))mismatch=1;closedir(root);if(mismatch)return fail(c,"Root-level module case aliases are unsupported");}}
 return 0;
}
static int write_all(int fd,const void *data,size_t n){const uint8_t *p=data;while(n){ssize_t z=write(fd,p,n);if(z<0&&errno==EINTR)continue;if(z<=0)return -1;p+=z;n-=(size_t)z;}return 0;}
#ifndef FL_LINK_VIEWS
static int copy_module(struct context *c,int source,int dest,const char *from,const char *to){int in=openat(source,from,O_RDONLY|O_NOFOLLOW);if(in<0)return fail(c,"Cannot open source module");struct stat before,after;if(fstat(in,&before)||!S_ISREG(before.st_mode)||before.st_size<0||(uint64_t)before.st_size>COPY_MAX-c->bytes){close(in);return fail(c,"Module overlay exceeds 512 MiB or contains unsafe file");}c->bytes+=(uint64_t)before.st_size;int existing=0;char dest_name[256];snprintf(dest_name,sizeof(dest_name),"%s",to);int out=openat(dest,dest_name,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(out<0&&errno==EEXIST){out=openat(dest,to,O_RDONLY|O_NOFOLLOW);existing=1;}if(out<0){char detail[640];snprintf(detail,sizeof(detail),"Module output failed fd=%d name=%s source=%s",dest,dest_name,from);module_log(detail);close(in);return fail(c,"Cannot create module overlay file (case-sensitive storage required)");}int rc=-1;sha256_ctx hash;sha256_init(&hash);uint64_t at=0;uint8_t expected[32],actual[32];while(at<(uint64_t)before.st_size){size_t n=(uint64_t)before.st_size-at>BUFFER_SIZE?BUFFER_SIZE:(size_t)((uint64_t)before.st_size-at);if(read_at(in,at,c->buffer,n)||(!existing&&write_all(out,c->buffer,n)))goto done;sha256_update(&hash,c->buffer,n);at+=n;}sha256_final(&hash,expected);if(fstat(in,&after)||before.st_dev!=after.st_dev||before.st_ino!=after.st_ino||before.st_size!=after.st_size||before.st_mtime!=after.st_mtime||before.st_ctime!=after.st_ctime)goto done;
 sha256_init(&hash);at=0;while(at<(uint64_t)before.st_size){size_t n=(uint64_t)before.st_size-at>BUFFER_SIZE?BUFFER_SIZE:(size_t)((uint64_t)before.st_size-at);if(read_at(out,at,c->buffer,n))goto done;sha256_update(&hash,c->buffer,n);at+=n;}sha256_final(&hash,actual);if(memcmp(expected,actual,32))goto done;struct stat output;if(fstat(out,&output)||output.st_size!=before.st_size)goto done;if(existing){if((output.st_mode&0777)!=(before.st_mode&0777)||output.st_uid!=before.st_uid||output.st_gid!=before.st_gid)goto done;}else{if((output.st_uid!=before.st_uid||output.st_gid!=before.st_gid)&&fchown(out,before.st_uid,before.st_gid))goto done;if(fchmod(out,before.st_mode&0777)||fsync(out))goto done;}rc=0;
done:close(out);close(in);return rc?fail(c,"Module copy validation failed; original retained"):0;}
#endif
static int owned_dir(struct context *c,const char *path){if(!path||path[0]!='/'||strlen(path)>=FL_PATH)return fail(c,"Invalid owned overlay root");char p[FL_PATH];snprintf(p,sizeof(p),"%s",path);int fd=open("/",O_RDONLY|O_DIRECTORY);if(fd<0)return -1;char *part=p+1,*slash;do{slash=strchr(part,'/');if(slash)*slash=0;if(!dependency_name(part)){close(fd);return -1;}if(mkdirat(fd,part,0755)&&errno!=EEXIST){close(fd);return -1;}int next=openat(fd,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);close(fd);if(next<0)return -1;fd=next;part=slash?slash+1:NULL;}while(part);return fd;}
#ifndef FL_LINK_VIEWS
static int copy_directory(struct context *c,unsigned which,int attempt){if(mkdirat(attempt,dirnames[which],0755))return fail(c,"Module directory creation failed");int out=openat(attempt,dirnames[which],O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(out<0)return fail(c,"Module output directory open failed");int scan=openat(c->dirs[which],".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(scan<0){close(out);return fail(c,"Module source directory open failed");}DIR *dir=fdopendir(scan);if(!dir){close(scan);close(out);return fail(c,"Module fdopendir failed");}struct dirent *ent;int rc=0;while((ent=readdir(dir))){if(!strcmp(ent->d_name,".")||!strcmp(ent->d_name,".."))continue;if((module_log(ent->d_name),!dependency_name(ent->d_name))||copy_module(c,c->dirs[which],out,ent->d_name,ent->d_name)){rc=-1;break;}}closedir(dir);
 if(!rc)for(size_t k=0;k<c->nneeded;k++){struct dependency *d=&c->needed[k];if(d->match<0)continue;struct module *m=&c->modules[d->match];if(m->dir==which&&strcmp(d->name,m->name)&&copy_module(c,c->dirs[which],out,m->name,d->name)){rc=-1;break;}}
 struct stat st;if(!rc&&(fstat(c->dirs[which],&st)||fchmod(out,st.st_mode&0777)||fsync(out)))rc=fail(c,"Module directory finalization failed");close(out);return rc;
}
#else
/* Only path names are written. Library contents remain at base_source. */
static int link_name(struct context *c,int out,const char *name,const char *original){
 char value[512];if(!dependency_name(name)||!dependency_name(original)||!strcmp(name,FL_MODULE_BASE_NAME))return fail(c,"Unsafe module link name");
 int n=snprintf(value,sizeof(value),"%s/%s",FL_MODULE_BASE_NAME,original);if(n<0||(size_t)n>=sizeof(value))return -1;
 if(symlinkat(value,out,name)){
  if(errno==EEXIST){char existing[512];ssize_t z=readlinkat(out,name,existing,sizeof(existing));if(z==n&&!memcmp(existing,value,(size_t)n))return 0;}
  return fail(c,"Cannot create owned module link; source unchanged");
 }return 0;
}
static int copy_directory(struct context *c,unsigned which,int attempt){
 if(mkdirat(attempt,dirnames[which],0755))return -1;int out=openat(attempt,dirnames[which],O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(out<0)return -1;
 int rc=-1,scan=-1;DIR *d=NULL;if(mkdirat(out,FL_MODULE_BASE_NAME,0755))goto done;
 scan=openat(c->dirs[which],".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(scan<0)goto done;d=fdopendir(scan);if(!d){close(scan);goto done;}
 struct dirent *ent;size_t files=0;errno=0;while((ent=readdir(d))){if(!strcmp(ent->d_name,".")||!strcmp(ent->d_name,".."))continue;struct stat st;
  if(++files>MODULES||!dependency_name(ent->d_name)||!strcmp(ent->d_name,FL_MODULE_BASE_NAME)||fstatat(c->dirs[which],ent->d_name,&st,AT_SYMLINK_NOFOLLOW)||!S_ISREG(st.st_mode)||link_name(c,out,ent->d_name,ent->d_name))goto done;
  errno=0;
 }if(errno)goto done;
 for(size_t k=0;k<c->nneeded;k++){struct dependency *d=&c->needed[k];if(d->match<0)continue;struct module *m=&c->modules[d->match];if(m->dir==which&&strcmp(d->name,m->name)&&link_name(c,out,d->name,m->name))goto done;}
 if(fsync(out))goto done;rc=0;
 done:if(d)closedir(d);close(out);return rc;
}
#endif
int fl_prepare_module_views(const struct fl_game *game,struct fl_module_view views[FL_MODULE_VIEWS],size_t *count,fl_progress progress){if(count)*count=0;if(!game||!views||!count||!fl_title_id(game->id))return -1;struct context c;memset(&c,0,sizeof(c));c.progress=progress;c.gamefd=-1;c.image.fd=-1;c.dirs[0]=c.dirs[1]=-1;c.needed=calloc(NEEDED,sizeof(*c.needed));c.modules=calloc(MODULES,sizeof(*c.modules));int rc=-1,base=-1,title=-1,attempt=-1;char attempt_name[64],rootpath[FL_PATH];memset(views,0,sizeof(*views)*FL_MODULE_VIEWS);if(!c.needed||!c.modules)goto done;
 char canonical[FL_PATH];if(!realpath(game->path,canonical)||strcmp(canonical,game->path)){fail(&c,"Module source game path must be canonical");goto done;}c.gamefd=open(game->path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(c.gamefd<0)goto done;c.image.fd=openat(c.gamefd,"eboot.bin",O_RDONLY|O_NOFOLLOW);if(c.image.fd<0||parse_needed(&c)||scan_modules(&c))goto done;
 if(!c.affected[0]&&!c.affected[1]){rc=0;goto done;}if(progress)progress("Preparing owned module filename compatibility view");
#ifndef FL_LINK_VIEWS
 c.buffer=malloc(BUFFER_SIZE);if(!c.buffer)goto done;
#endif
 base=owned_dir(&c,owned_root);if(base<0)goto done;if(mkdirat(base,game->id,0755)&&errno!=EEXIST)goto done;title=openat(base,game->id,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(title<0)goto done;struct timespec ts;if(clock_gettime(CLOCK_MONOTONIC,&ts))goto done;for(unsigned n=0;n<64;n++){snprintf(attempt_name,sizeof(attempt_name),"run-%lx-%lx-%u",(unsigned long)getpid(),(unsigned long)ts.tv_nsec,n);if(!mkdirat(title,attempt_name,0755)){attempt=openat(title,attempt_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);break;}if(errno!=EEXIST)goto done;}if(attempt<0)goto done;
 int marker=openat(attempt,".ps4fl-module-view.owner",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0644);if(marker<0)goto done;
#ifdef FL_LINK_VIEWS
 const char owner[]="PS4FL-MODULE-LINK-v1\n";
#else
 const char owner[]="PS4FL-MODULE-VIEW-v1\n";
#endif
int marker_error=write_all(marker,owner,sizeof(owner)-1)||fsync(marker);close(marker);if(marker_error)goto done;
 int len=snprintf(rootpath,sizeof(rootpath),"%s/%s/%s",owned_root,game->id,attempt_name);if(len<0||(size_t)len>=sizeof(rootpath))goto done;
 for(unsigned k=0;k<2;k++)if(c.affected[k]){if(copy_directory(&c,k,attempt))goto done;struct fl_module_view *v=&views[*count];if(fl_join(v->source,sizeof(v->source),rootpath,dirnames[k]))goto done;snprintf(v->relative,sizeof(v->relative),"%s",dirnames[k]);
#ifdef FL_LINK_VIEWS
 if(fl_join(v->base_source,sizeof(v->base_source),game->path,dirnames[k]))goto done;
#endif
 (*count)++;}if(fsync(attempt)||fsync(title)||fsync(base))goto done;rc=0;
done:if(rc){*count=0;memset(views,0,sizeof(*views)*FL_MODULE_VIEWS);fail(&c,"Module compatibility view was not activated");}if(attempt>=0)close(attempt);if(title>=0)close(title);if(base>=0)close(base);for(unsigned k=0;k<2;k++)if(c.dirs[k]>=0)close(c.dirs[k]);if(c.image.fd>=0)close(c.image.fd);if(c.gamefd>=0)close(c.gamefd);free(c.buffer);free(c.needed);free(c.modules);return rc;}
