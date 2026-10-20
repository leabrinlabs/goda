/* SPDX-License-Identifier: GPL-3.0-or-later. Append-only diagnostics. */
#include "audit.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#ifndef FL_HOST
static pthread_mutex_t audit_lock=PTHREAD_MUTEX_INITIALIZER;
#endif
void fl_audit(const char *component,const char *format,...){
#ifdef FL_HOST
 (void)component;(void)format;
#else
 int saved=errno;struct timespec mono,wall;clock_gettime(CLOCK_MONOTONIC,&mono);clock_gettime(CLOCK_REALTIME,&wall);
 pthread_mutex_lock(&audit_lock);FILE *f=fopen("/data/ps4-folder-loader-audit.log","a");
 if(f){fprintf(f,"mono_us=%llu wall_s=%lld pid=%d component=%s ",(unsigned long long)mono.tv_sec*1000000+mono.tv_nsec/1000,(long long)wall.tv_sec,(int)getpid(),component);va_list args;va_start(args,format);vfprintf(f,format,args);va_end(args);fputc('\n',f);fflush(f);fsync(fileno(f));fclose(f);}
 pthread_mutex_unlock(&audit_lock);errno=saved;
#endif
}
