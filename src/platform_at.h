/* GPL-3.0-or-later. SDK raw *at stubs retain FreeBSD carry/errno ABI.
 * Isolate the syscall behind a C call boundary; the PS5 syscall path can
 * clear volatile registers (including r8/r9). Declare all as modified.
 * Normalize it before POSIX callers inspect return values or errno.
 * Otherwise EEXIST=17 can be mistaken for an open file descriptor.
 */
#ifndef FL_PLATFORM_AT_H
#define FL_PLATFORM_AT_H
#ifndef FL_HOST
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
static __attribute__((noinline)) long fl_at_call(long number,long a,long b,long c,long d){
 register long r10 __asm__("r10")=d;long result;unsigned char failed;
 __asm__ volatile("syscall" : "=a"(result), "=@ccc"(failed), "+d"(c), "+D"(a), "+S"(b), "+r"(r10) : "0"(number) : "rcx","r8","r9","r11","memory","cc");
 if(failed){errno=(int)result;return -1;}return result;
}
static inline int fl_openat(int fd,const char *path,int flags,...){mode_t mode=0;if(flags&O_CREAT){va_list a;va_start(a,flags);mode=(mode_t)va_arg(a,int);va_end(a);}return (int)fl_at_call(SYS_openat,fd,(long)(intptr_t)path,flags,mode);}
static inline int fl_mkdirat(int fd,const char *path,mode_t mode){return (int)fl_at_call(SYS_mkdirat,fd,(long)(intptr_t)path,mode,0);}
static inline int fl_unlinkat(int fd,const char *path,int flags){return (int)fl_at_call(SYS_unlinkat,fd,(long)(intptr_t)path,flags,0);}
static inline int fl_fstatat(int fd,const char *path,struct stat *st,int flags){return (int)fl_at_call(SYS_fstatat,fd,(long)(intptr_t)path,(long)(intptr_t)st,flags);}
static inline ssize_t fl_readlinkat(int fd,const char *path,char *buf,size_t size){return (ssize_t)fl_at_call(SYS_readlinkat,fd,(long)(intptr_t)path,(long)(intptr_t)buf,(long)size);}
static inline ssize_t fl_readlink(const char *path,char *buf,size_t size){return (ssize_t)fl_at_call(SYS_readlink,(long)(intptr_t)path,(long)(intptr_t)buf,(long)size,0);}
static inline int fl_symlinkat(const char *value,int fd,const char *path){return (int)fl_at_call(SYS_symlinkat,(long)(intptr_t)value,fd,(long)(intptr_t)path,0);}
static inline int fl_dup(int fd){return (int)fl_at_call(SYS_dup,fd,0,0,0);}
#define readlinkat fl_readlinkat
#define readlink fl_readlink
#define symlinkat fl_symlinkat
#define dup fl_dup
#define openat fl_openat
#define mkdirat fl_mkdirat
#define unlinkat fl_unlinkat
#define fstatat fl_fstatat
#endif
#endif
