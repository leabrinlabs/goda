/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FL_LAUNCH_OBSERVATION_H
#define FL_LAUNCH_OBSERVATION_H
#include <stdint.h>
struct fl_launch_observation {int64_t pid;unsigned stable,missing,uncertain;};
/* 1 valid same application, 0 absent, -1 unreadable, 2 different app.
 * A failed sysctl snapshot is never evidence of process exit. */
static inline int fl_observe_launch(struct fl_launch_observation *s,int sample,int64_t pid){
 if(sample<0){s->uncertain++;return s->uncertain>=8?-2:0;}
 s->uncertain=0;
 if(sample==2)return -3;
 if(!sample){s->missing++;return s->missing>=8?-1:0;}
 s->missing=0;
 if(s->pid!=pid){s->pid=pid;s->stable=0;}
 return ++s->stable>=120?1:0;
}
#endif
