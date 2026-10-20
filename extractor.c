/* SPDX-License-Identifier: GPL-3.0-or-later
 * New-directory-only extraction. SHA256 output reread verifies extraction I/O,
 * not authenticity of the signed PFS hashes (reader does not authenticate them).
 */
#include "extractor.h"
#include "extract_reader.h"
#include "catalog.h"
#include "vendor/pkg.h"
#include "vendor/crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include "platform_at.h"
#define COPY_BUFFER (1024u*1024u)
#define RESERVE_BYTES (64u*1024u*1024u)
#define MAX_METADATA 160
struct metadata { uint32_t id; char path[128]; uint64_t size; };
struct context {
 fl_pkg_reader *reader; int rootfd; uint8_t *buffer; FILE *manifest;
 uint64_t done,total; size_t manifest_count; volatile sig_atomic_t *cancel;
 void (*progress)(const char *,uint64_t,uint64_t);
 char *error; size_t error_cap;
};
static int error(struct context *c,const char *message){if(c->error&&c->error_cap)snprintf(c->error,c->error_cap,"%s",message);return -1;}
static int cancelled(struct context *c){return c->cancel&&*c->cancel;}
static void progress(struct context *c,const char *message){if(c->progress)c->progress(message,c->done,c->total);}
static int valid_path(const char *path){
 if(!path||!*path||strlen(path)>=FL_PATH||path[0]=='/')return 0;
 const char *p=path;
 while(*p){const char *end=strchr(p,'/');size_t n=end?(size_t)(end-p):strlen(p);
  if(!n||n>255||(n==1&&p[0]=='.')||(n==2&&!memcmp(p,"..",2))||(n>=7&&!strncasecmp(p,".ps4fl-",7)))return 0;
  for(size_t i=0;i<n;i++)if((unsigned char)p[i]<32||(unsigned char)p[i]>126||p[i]=='\\'||p[i]==':')return 0;
  if(!end)break;p=end+1;if(!*p)return 0;
 }return 1;
}
/* Exact spelling matters on case-sensitive and case-insensitive media alike. */
static int spelling_matches(int fd,const char *name){
 int scan=openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(scan<0)return -1;
 DIR *dir=fdopendir(scan);if(!dir){close(scan);return -1;}int result=0;struct dirent *ent;
 errno=0;while((ent=readdir(dir))){if(!strcasecmp(ent->d_name,name)&&strcmp(ent->d_name,name)){result=-1;break;}}
 if(errno)result=-1;closedir(dir);return result;
}
/* Returns parent FD, never follows a link; caller closes. */
static int parent_fd(struct context *c,const char *path,char leaf[256]){
 if(!valid_path(path))return error(c,"Unsafe or unsupported output path");
 char copy[FL_PATH];memcpy(copy,path,strlen(path)+1);int fd=dup(c->rootfd);if(fd<0)return error(c,"Cannot duplicate output directory");
 char *p=copy,*slash;
 while((slash=strchr(p,'/'))){*slash=0;if(spelling_matches(fd,p)){close(fd);return error(c,"Case-folded output name collision");}
  if(mkdirat(fd,p,0755)&&errno!=EEXIST){close(fd);return error(c,"Cannot create output subdirectory");}
  int next=openat(fd,p,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);close(fd);if(next<0)return error(c,"Output parent is not a safe directory");fd=next;p=slash+1;
 }
 if(spelling_matches(fd,p)){close(fd);return error(c,"Case-folded output name collision");}memcpy(leaf,p,strlen(p)+1);return fd;
}
static int write_all(int fd,const uint8_t *p,size_t n){while(n){ssize_t z=write(fd,p,n);if(z<0&&errno==EINTR)continue;if(z<=0)return -1;p+=z;n-=(size_t)z;}return 0;}
static int read_all(int fd,uint8_t *p,size_t n){while(n){ssize_t z=read(fd,p,n);if(z<0&&errno==EINTR)continue;if(z<=0)return -1;p+=z;n-=(size_t)z;}return 0;}
static int sync_directory(int fd){return fsync(fd);}
static void json_string(FILE *f,const char *s){fputc('"',f);for(const unsigned char *p=(const unsigned char*)s;*p;p++){if(*p=='"'||*p=='\\'){fputc('\\',f);fputc(*p,f);}else if(*p<32)fprintf(f,"\\u%04x",*p);else fputc(*p,f);}fputc('"',f);}
static int manifest_file(struct context *c,const char *path,uint64_t size,const uint8_t hash[32]){
 if(c->manifest_count++)fputs(",\n",c->manifest);fputs("    {\"path\":",c->manifest);json_string(c->manifest,path);fprintf(c->manifest,",\"size\":%llu,\"sha256\":\"",(unsigned long long)size);for(int i=0;i<32;i++)fprintf(c->manifest,"%02x",hash[i]);fputs("\"}",c->manifest);return ferror(c->manifest)?error(c,"Manifest write failed"):0;
}
/* All bytes are hashed while writing, then the complete output is read again. */
static int copy_file(struct context *c,const char *path,size_t index,const uint8_t *memory,uint64_t size,int allow_identical){
 if(cancelled(c))return error(c,"Extraction cancelled; incomplete directory retained");
 char leaf[256];int parent=parent_fd(c,path,leaf);if(parent<0)return -1;
 mode_t output_mode=memory?0644:(mode_t)(fl_pkg_file_mode(c->reader,index)&0777u);
 int fd=openat(parent,leaf,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,output_mode),existing=0;
 if(fd<0&&errno==EEXIST&&allow_identical){fd=openat(parent,leaf,O_RDONLY|O_NOFOLLOW);existing=1;}
 if(fd<0){close(parent);return error(c,"Output file already exists or cannot be created");}
 struct stat st;if(fstat(fd,&st)||!S_ISREG(st.st_mode)||(existing&&(uint64_t)st.st_size!=size)){close(fd);close(parent);return error(c,"Conflicting output metadata");}
 sha256_ctx hash;sha256_init(&hash);uint64_t at=0;int rc=-1;uint8_t expected_hash[32],actual_hash[32];
 while(at<size){if(cancelled(c)){error(c,"Extraction cancelled; incomplete directory retained");goto end;}size_t n=(size-at)>COPY_BUFFER?COPY_BUFFER:(size_t)(size-at);const uint8_t *source=memory?memory+(size_t)at:c->buffer;
  if(!memory&&fl_pkg_read(c->reader,index,at,c->buffer,n)){error(c,fl_pkg_error(c->reader));goto end;}sha256_update(&hash,source,n);
  if(existing){if(read_all(fd,c->buffer,n)||memcmp(c->buffer,source,n)){error(c,"Inner and outer metadata disagree");goto end;}}
  else if(write_all(fd,source,n)){error(c,"Output write failed (space or I/O error)");goto end;}
  at+=n;c->done+=n;progress(c,path);
 }
 sha256_final(&hash,expected_hash);
 if(!existing){if(fchmod(fd,output_mode)){error(c,"Cannot preserve source file permissions");goto end;}if(fsync(fd)){error(c,"Output flush failed");goto end;}if(close(fd)){fd=-1;error(c,"Output close failed");goto end;}fd=openat(parent,leaf,O_RDONLY|O_NOFOLLOW);if(fd<0){error(c,"Cannot reopen output for verification");goto end;}}
 else if(lseek(fd,0,SEEK_SET)<0){error(c,"Cannot rewind output verification");goto end;}
 if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<0||(uint64_t)st.st_size!=size){error(c,"Output size changed");goto end;}
 char verify_label[FL_PATH+32];snprintf(verify_label,sizeof(verify_label),"Dogrulaniyor: %s",path);progress(c,verify_label);
 sha256_init(&hash);at=0;while(at<size){if(cancelled(c)){error(c,"Extraction cancelled during output verification");goto end;}size_t n=size-at>COPY_BUFFER?COPY_BUFFER:(size_t)(size-at);if(read_all(fd,c->buffer,n)){error(c,"Output reread failed");goto end;}sha256_update(&hash,c->buffer,n);at+=n;}
 sha256_final(&hash,actual_hash);if(memcmp(actual_hash,expected_hash,32)){error(c,"Output SHA256 reread mismatch");goto end;}
 if(!existing&&manifest_file(c,path,size,expected_hash))goto end;
 progress(c,path);rc=0;
end:if(fd>=0)close(fd);if(!existing&&rc==0&&sync_directory(parent))rc=error(c,"Output directory flush failed");close(parent);return rc;
}
static int meta_path(uint32_t id,char *path,size_t cap){
 struct fixed {uint32_t id;const char *name;} fixed[]={
 {0x402,"sce_sys/nptitle.dat"},{0x403,"sce_sys/npbind.dat"},{0x409,"sce_sys/psreserved.dat"},
 {0x1000,"sce_sys/param.sfo"},{0x1001,"sce_sys/playgo-chunk.dat"},{0x1002,"sce_sys/playgo-chunk.sha"},{0x1003,"sce_sys/playgo-manifest.xml"},{0x1004,"sce_sys/pronunciation.xml"},{0x1005,"sce_sys/pronunciation.sig"},{0x1006,"sce_sys/pic1.png"},
 {0x1200,"sce_sys/icon0.png"},{0x1260,"sce_sys/changeinfo/changeinfo.xml"},{0x1280,"sce_sys/icon0.dds"},{0x12c0,"sce_sys/pic1.dds"}};
 for(size_t i=0;i<sizeof(fixed)/sizeof(fixed[0]);i++)if(id==fixed[i].id){snprintf(path,cap,"%s",fixed[i].name);return 1;}
 if(id>=0x1201&&id<=0x121f){snprintf(path,cap,"sce_sys/icon0_%02u.png",id-0x1201);return 1;}
 if(id>=0x1261&&id<=0x127f){snprintf(path,cap,"sce_sys/changeinfo/changeinfo_%02u.xml",id-0x1261);return 1;}
 if(id>=0x1400&&id<=0x141f){snprintf(path,cap,"sce_sys/trophy/trophy%02u.trp",id-0x1400);return 1;}return 0;
}
static int same_source(const struct stat *a,const struct stat *b){
#if defined(__APPLE__)
 return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_size==b->st_size&&a->st_mtimespec.tv_sec==b->st_mtimespec.tv_sec&&a->st_mtimespec.tv_nsec==b->st_mtimespec.tv_nsec&&a->st_ctimespec.tv_sec==b->st_ctimespec.tv_sec&&a->st_ctimespec.tv_nsec==b->st_ctimespec.tv_nsec;
#else
 return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_size==b->st_size&&a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
#endif
}
static int path_cmp(const void *a,const void *b){const fl_pkg_file *const *x=a,*const *y=b;return strcasecmp((*x)->path,(*y)->path);}
static int inventory(struct context *c){size_t count=fl_pkg_file_count(c->reader);const fl_pkg_file *files=fl_pkg_files(c->reader);const fl_pkg_file **sorted=malloc(count*sizeof(*sorted));if(!sorted)return error(c,"Inventory allocation failed");for(size_t i=0;i<count;i++){if(!valid_path(files[i].path)||files[i].size>UINT64_MAX-c->total){free(sorted);return error(c,"Unsafe path or extraction size overflow");}sorted[i]=&files[i];c->total+=files[i].size;}qsort(sorted,count,sizeof(*sorted),path_cmp);for(size_t i=1;i<count;i++){size_t n=strlen(sorted[i-1]->path);if(!strcasecmp(sorted[i-1]->path,sorted[i]->path)||(!strncasecmp(sorted[i-1]->path,sorted[i]->path,n)&&sorted[i]->path[n]=='/')){free(sorted);return error(c,"Duplicate or conflicting case-folded file paths");}}free(sorted);return 0;}
int fl_extract_pkg(const char *source,const char *dest_root,void (*notify)(const char*,uint64_t,uint64_t),volatile sig_atomic_t *cancel,char *output,size_t output_cap){
 struct context c;memset(&c,0,sizeof(c));c.rootfd=-1;c.error=output;c.error_cap=output_cap;c.progress=notify;c.cancel=cancel;if(output&&output_cap)*output=0;
 char root[FL_PATH],source_parent[FL_PATH],source_real[FL_PATH],target[FL_PATH],name[128],read_error[256];int basefd=-1,marker=-1,manifestfd=-1,rc=-1;struct stat before,after;uint8_t *sfo_data=NULL;sfo_t *sfo=NULL;struct metadata metadata[MAX_METADATA];size_t nmeta=0;const fl_pkg_file *files=NULL;
 if(!source||!dest_root||!output||!output_cap||strlen(source)>=FL_PATH)return error(&c,"Invalid extraction arguments");
 snprintf(source_parent,sizeof(source_parent),"%s",source);char *slash=strrchr(source_parent,'/');if(!slash)return error(&c,"Package source must be an absolute path");*slash=0;if(!fl_allowed_directory(source_parent,source_real)||strcmp(source_parent,source_real)||!fl_allowed_directory(dest_root,root)||strcmp(root,dest_root))return error(&c,"Source and output must use canonical allowed storage directories");
 if(cancelled(&c))return error(&c,"Extraction cancelled before opening package");progress(&c,"Reading package inventory");c.reader=fl_pkg_open(source,read_error,sizeof(read_error));if(!c.reader)return error(&c,read_error);
 if(fl_pkg_source_stat(c.reader,&before)||!S_ISREG(before.st_mode)){error(&c,"Source is not a regular package");goto done;}
 size_t sfo_len=0;sfo_data=fl_pkg_metadata_entry(c.reader,0x1000,&sfo_len);sfo=calloc(1,sizeof(*sfo));if(!sfo||!sfo_data||sfo_parse(sfo_data,sfo_len,sfo)){error(&c,"Package param.sfo is absent or corrupt");goto done;}
 const sfo_item_t *id=sfo_get(sfo,"TITLE_ID"),*cat=sfo_get(sfo,"CATEGORY"),*version=sfo_get(sfo,"APP_VER");if(!id||id->is_int||!fl_title_id(id->sval)||!cat||cat->is_int||(strcmp(cat->sval,"gd")&&strcmp(cat->sval,"gp"))){error(&c,"Package must be a valid PS4 base game or update");goto done;}
 if(strlen(fl_pkg_content_id(c.reader))<16||strncmp(id->sval,fl_pkg_content_id(c.reader)+7,9)){error(&c,"Package content ID and title ID disagree");goto done;}
 if(strcmp(cat->sval,"gp")==0){if(!version||version->is_int||!version->sval[0]||strlen(version->sval)>31){error(&c,"Invalid update version");goto done;}for(const char *p=version->sval;*p;p++)if(!isdigit((unsigned char)*p)&&*p!='.'){error(&c,"Unsupported update version characters");goto done;}snprintf(name,sizeof(name),"%s_update_%s",id->sval,version->sval);}else snprintf(name,sizeof(name),"%s",id->sval);
 if(fl_join(target,sizeof(target),root,name)||strlen(target)>=output_cap||inventory(&c)){if(!output[0])error(&c,"Output path too long");goto done;}
 /* Decode all supported entries before making output; discard bytes after sizing. */
 for(uint32_t eid=0x400;eid<=0x141f;eid++){if(cancelled(&c)){error(&c,"Extraction cancelled while checking metadata");goto done;}char path[128];if(!meta_path(eid,path,sizeof(path))||!fl_pkg_metadata_present(c.reader,eid))continue;if(nmeta>=MAX_METADATA){error(&c,"Metadata entry limit exceeded");goto done;}size_t n=0;uint8_t *data=fl_pkg_metadata_entry(c.reader,eid,&n);if(!data||c.total>UINT64_MAX-n){free(data);error(&c,"Present package metadata failed decoding");goto done;}free(data);metadata[nmeta].id=eid;metadata[nmeta].size=n;snprintf(metadata[nmeta].path,sizeof(metadata[nmeta].path),"%s",path);nmeta++;c.total+=n;}
 basefd=open(root,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(basefd<0){error(&c,"Cannot open extraction destination");goto done;}struct statvfs space;if(fstatvfs(basefd,&space)||!space.f_frsize||space.f_bavail>UINT64_MAX/space.f_frsize||c.total>UINT64_MAX-RESERVE_BYTES||(uint64_t)space.f_bavail*space.f_frsize<c.total+RESERVE_BYTES){error(&c,"Not enough free space (64 MiB reserve required)");goto done;}
 if(cancelled(&c)){error(&c,"Extraction cancelled before output creation");goto done;}
 if(spelling_matches(basefd,name)||mkdirat(basefd,name,0755)){error(&c,"Output directory already exists or cannot be created");goto done;}
 c.rootfd=openat(basefd,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(c.rootfd<0){error(&c,"Cannot open new output directory");goto done;}
 marker=openat(c.rootfd,".ps4fl-incomplete",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0644);if(marker<0||write_all(marker,(const uint8_t*)"Extraction incomplete\n",22)||fsync(marker)||sync_directory(c.rootfd)||sync_directory(basefd)){error(&c,"Cannot create durable incomplete marker");goto done;}close(marker);marker=-1;
 c.buffer=malloc(COPY_BUFFER);if(!c.buffer){error(&c,"Extraction buffer allocation failed");goto done;}
 manifestfd=openat(c.rootfd,".ps4fl-manifest.json",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0644);if(manifestfd<0){error(&c,"Cannot create extraction manifest");goto done;}c.manifest=fdopen(manifestfd,"w");if(!c.manifest){error(&c,"Cannot open extraction manifest stream");goto done;}manifestfd=-1;
 fputs("{\"format\":1,\"verification\":\"output SHA256 reread; signed PFS hashes not authenticated\",\"content_id\":",c.manifest);json_string(c.manifest,fl_pkg_content_id(c.reader));fputs(",\"files\":[\n",c.manifest);
 files=fl_pkg_files(c.reader);for(size_t i=0;i<fl_pkg_file_count(c.reader);i++)if(copy_file(&c,files[i].path,i,NULL,files[i].size,0))goto done;
 for(size_t i=0;i<nmeta;i++){if(cancelled(&c)){error(&c,"Extraction cancelled before metadata");goto done;}size_t n=0;uint8_t *data=fl_pkg_metadata_entry(c.reader,metadata[i].id,&n);if(!data||n!=metadata[i].size){free(data);error(&c,"Metadata changed or failed decoding");goto done;}int copied=copy_file(&c,metadata[i].path,0,data,n,1);free(data);if(copied)goto done;}
 if(fl_pkg_source_stat(c.reader,&after)||!same_source(&before,&after)){error(&c,"Source package changed during extraction");goto done;}
 /* Base game must contain both native startup and metadata before completion. */
 if(!strcmp(cat->sval,"gd")){int fd=openat(c.rootfd,"eboot.bin",O_RDONLY|O_NOFOLLOW);struct stat st;if(fd<0||fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<4){if(fd>=0)close(fd);error(&c,"Base game is missing eboot.bin");goto done;}close(fd);}
 fputs("\n],\"complete\":true}\n",c.manifest);if(fflush(c.manifest)||ferror(c.manifest)||fsync(fileno(c.manifest))){error(&c,"Cannot flush completed extraction manifest");goto done;}if(fclose(c.manifest)){c.manifest=NULL;error(&c,"Cannot close completed manifest");goto done;}c.manifest=NULL;
 if(cancelled(&c)){error(&c,"Extraction cancelled before completion");goto done;}if(unlinkat(c.rootfd,".ps4fl-incomplete",0)){error(&c,"Cannot remove incomplete marker");goto done;}if(sync_directory(c.rootfd)){int incomplete=openat(c.rootfd,".ps4fl-incomplete",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0644);if(incomplete>=0){write_all(incomplete,(const uint8_t*)"Final directory flush failed\n",29);fsync(incomplete);close(incomplete);}error(&c,"Cannot flush finalized directory; completion not confirmed");goto done;}
 snprintf(output,output_cap,"%s",target);c.done=c.total;progress(&c,"Extraction complete; output SHA256 reread verified");rc=0;
done:if(c.manifest)fclose(c.manifest);if(manifestfd>=0)close(manifestfd);if(marker>=0)close(marker);if(c.rootfd>=0)close(c.rootfd);if(basefd>=0)close(basefd);free(c.buffer);free(sfo_data);free(sfo);fl_pkg_close(c.reader);return rc;
}

int fl_restore_permissions(const char *source,const char *target,void (*notify)(const char*,uint64_t,uint64_t),char *err,size_t cap){
 char canonical[FL_PATH],path[FL_PATH],reader_error[256];struct stat st;int root=-1,rc=-1;fl_pkg_reader *r=NULL;uint8_t *sfo=NULL;size_t sfo_len=0;
 if(!source||!target||!err||!cap)return -1;*err=0;
 if(!fl_allowed_directory(target,canonical)||strcmp(canonical,target)){snprintf(err,cap,"Invalid output directory");return -1;}
 if(fl_join(path,sizeof(path),target,".ps4fl-incomplete")||!lstat(path,&st)||errno!=ENOENT){snprintf(err,cap,"Output is incomplete");return -1;}
 root=open(target,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(root<0){snprintf(err,cap,"Cannot open output directory");return -1;}
 r=fl_pkg_open(source,reader_error,sizeof(reader_error));if(!r){snprintf(err,cap,"%s",reader_error);goto done;}
 int fd=openat(root,".ps4fl-manifest.json",O_RDONLY|O_NOFOLLOW);if(fd<0){snprintf(err,cap,"Not a loader extraction output");goto done;}
 if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<20||st.st_size>2*1024*1024){close(fd);snprintf(err,cap,"Invalid output manifest");goto done;}
 size_t n=(size_t)st.st_size;char *manifest=malloc(n+1);if(!manifest){close(fd);goto done;}int bad=read_all(fd,(uint8_t*)manifest,n);close(fd);manifest[n]=0;
 char cid[128];snprintf(cid,sizeof(cid),"\"content_id\":\"%s\"",fl_pkg_content_id(r));const char *end="],\"complete\":true}\n";size_t suffix=strlen(end);
 int valid=!bad&&!memchr(manifest,0,n)&&strstr(manifest,cid)&&n>=suffix&&!memcmp(manifest+n-suffix,end,suffix);free(manifest);if(!valid){snprintf(err,cap,"Completed manifest does not match source package");goto done;}
 sfo=fl_pkg_metadata_entry(r,0x1000,&sfo_len);fd=openat(root,"sce_sys/param.sfo",O_RDONLY|O_NOFOLLOW);if(!sfo||sfo_len>512*1024||fd<0){if(fd>=0)close(fd);snprintf(err,cap,"Cannot compare output identity");goto done;}
 uint8_t *check=malloc(sfo_len?sfo_len:1);valid=check&&!fstat(fd,&st)&&S_ISREG(st.st_mode)&&st.st_size==(off_t)sfo_len&&!read_all(fd,check,sfo_len)&&!memcmp(check,sfo,sfo_len);free(check);close(fd);if(!valid){snprintf(err,cap,"Output SFO does not match package");goto done;}
 const fl_pkg_file *files=fl_pkg_files(r);size_t count=fl_pkg_file_count(r);
 for(size_t i=0;i<count;i++){
  if(!valid_path(files[i].path)){snprintf(err,cap,"Unsafe file path");goto done;}
  char relative[FL_PATH];snprintf(relative,sizeof(relative),"%s",files[i].path);int parent=dup(root);char *part=relative,*slash;
  if(parent<0)goto done;
  while((slash=strchr(part,'/'))){*slash=0;int next=openat(parent,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);close(parent);parent=next;if(parent<0)break;part=slash+1;}
  if(parent<0){snprintf(err,cap,"Output parent missing or linked");goto done;}
  fd=openat(parent,part,O_RDONLY|O_NOFOLLOW);close(parent);mode_t mode=(mode_t)(fl_pkg_file_mode(r,i)&0777u);
  if(fd<0){snprintf(err,cap,"Output file missing");goto done;}
  if(!mode||fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<0||(uint64_t)st.st_size!=files[i].size||fchmod(fd,mode)||fsync(fd)){close(fd);snprintf(err,cap,"Cannot restore file mode");goto done;}close(fd);
  if(notify)notify(files[i].path,i+1,count);
 }
 snprintf(err,cap,"Paketin dosya izinleri geri yuklendi; dosya icerikleri degistirilmedi.");rc=0;
 done:if(!err[0])snprintf(err,cap,"Permission migration failed");free(sfo);fl_pkg_close(r);if(root>=0)close(root);return rc;
}
