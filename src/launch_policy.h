/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FL_LAUNCH_POLICY_H
#define FL_LAUNCH_POLICY_H
#include <stdint.h>
#include <string.h>
#include <errno.h>
struct fl_gate_policy {char title[10];uint64_t owner,expires;int claimed,bound,reported,success;};
/* Sandbox messages carry no title: they must match the exact claimed thread. */
static int fl_gate_request(struct fl_gate_policy *p,unsigned op,const char title[32],uint64_t thread,uint64_t now){
 if(!thread)return EPERM;
 if(op==1){if(now>=p->expires||memcmp(title,p->title,10))return EPERM;if(p->claimed)return EBUSY;p->claimed=1;p->owner=thread;return 0;}
 if(op==3){if(!p->claimed||p->owner!=thread||p->bound||p->reported||now>=p->expires)return EPERM;return 0;}
 if(op==2||op==4){if(!p->claimed||p->owner!=thread||memcmp(title,p->title,10)||p->reported)return EPERM;p->reported=1;p->success=op==4&&p->bound==1;return 0;}
 return EINVAL;
}
#endif
