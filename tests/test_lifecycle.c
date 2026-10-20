/* Exercise the production mount-release routine against a fake mount table. */
#define FL_LIFECYCLE_TEST
#include "../src/lifecycle.c"
#include <assert.h>
static struct statfs table[8];static int mounts,calls,busy,snapshot_race;
void fl_audit(const char *component,const char *fmt,...){(void)component;(void)fmt;}
int fixture_getfsstat(struct statfs *out,long bytes,int flags){(void)flags;if(!out)return mounts;size_t cap=(size_t)bytes/sizeof(*out);size_t n=(size_t)mounts<cap?(size_t)mounts:cap;memcpy(out,table,n*sizeof(*out));return snapshot_race?(int)cap:(int)n;}
int fixture_getmntinfo(struct statfs **out,int flags){(void)flags;*out=table;return mounts;}
int fixture_statfs(const char *path,struct statfs *out){for(int i=mounts-1;i>=0;i--)if(!strcmp(table[i].f_mntonname,path)){*out=table[i];return 0;}errno=ENOENT;return -1;}
int fixture_unmount(const char *path,int flags){assert(flags==0);calls++;if(busy){errno=EBUSY;return -1;}for(int i=mounts-1;i>=0;i--)if(!strcmp(table[i].f_mntonname,path)){memmove(table+i,table+i+1,(size_t)(mounts-i-1)*sizeof(*table));mounts--;return 0;}assert(0);return -1;}
int sceKernelGetAppInfo(pid_t pid,app_info_t *info){(void)pid;(void)info;return -1;}
static void add(const char *source,const char *target,int fsid){struct statfs *f=&table[mounts++];memset(f,0,sizeof(*f));strcpy(f->f_fstypename,"nullfs");strcpy(f->f_mntfromname,source);strcpy(f->f_mntonname,target);f->f_flags=MNT_RDONLY;memcpy(&f->f_fsid,&fsid,sizeof(fsid));}
static void setup(void){memset(&session,0,sizeof(session));memcpy(session.title,"CUSA99999",10);session.active=1;mounts=calls=busy=snapshot_race=0;add("/unrelated","/unrelated-mount",77);}
static void owned(const char *source,const char *target,int fsid){add(source,target,fsid);struct layer *l=&session.layers[session.count++];strcpy(l->source,source);strcpy(l->target,target);l->fsid=table[mounts-1].f_fsid;}
int main(void){
 const char *outer="/mnt/sandbox/CUSA99999_000/app0/prx",*inner="/mnt/sandbox/CUSA99999_000/app0/prx/.ps4fl-original";
 setup();owned("/owned/links",outer,1);owned("/game/prx",inner,2);
 assert(!release_top()&&session.count==1&&calls==1);assert(!release_top()&&!session.count&&calls==2);assert(mounts==1);
 setup();owned("/owned/links",outer,1);busy=1;assert(release_top()<0&&session.count==1&&calls==1);busy=0;assert(!release_top()&&!session.count);
 setup();owned("/owned/links",outer,1);add("/foreign",outer,99);assert(release_top()<0&&session.count==1&&calls==0);
 setup();add("/legacy",outer,99);owned("/owned/links",outer,1);assert(!release_top()&&!session.count&&calls==1&&mounts==2&&!strcmp(table[1].f_mntfromname,"/legacy"));
 setup();owned("/owned/links",outer,1);add("/foreign",inner,3);assert(release_top()<0&&session.count==1&&calls==0);
 setup();owned("/owned/links",outer,1);mounts--;assert(!release_top()&&!session.count&&calls==0);
 setup();owned("/owned/links",outer,1);table[mounts-1].f_flags=0;assert(release_top()<0&&session.count==1&&calls==0);
 setup();owned("/owned/links",outer,1);snapshot_race=1;assert(release_top()<0&&session.count==1&&calls==0);
 assert(!fl_cleanup_allowed(0,0,1,0,0));assert(!fl_cleanup_allowed(1,1,1,0,0));assert(!fl_cleanup_allowed(1,0,0,0,0));
 assert(fl_cleanup_allowed(1,0,1,1,0));assert(!fl_cleanup_allowed(1,0,1,1,1));assert(fl_cleanup_allowed(1,0,1,0,1));
 puts("PASS: inner-first cleanup, busy retry, replacement identity, foreign child, absent mount, readonly guard, exit ordering");return 0;
}
