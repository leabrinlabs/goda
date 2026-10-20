#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/mount.h>
#ifndef KERN_PROC_PROC
#define KERN_PROC_PROC 8
#endif
typedef struct {uint32_t app_id;char title_id[10];} app_info_t;
int sceKernelGetAppInfo(pid_t,app_info_t*);
int fixture_getmntinfo(struct statfs **,int);
int fixture_getfsstat(struct statfs *,long,int);
int fixture_unmount(const char *,int);
int fixture_statfs(const char *,struct statfs *);
#define getmntinfo fixture_getmntinfo
#define getfsstat(buf,size,flags) fixture_getfsstat(buf,size,flags)
#define unmount fixture_unmount
#define statfs(path,out) fixture_statfs(path,out)
