/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FL_LIFECYCLE_POLICY_H
#define FL_LIFECYCLE_POLICY_H
#include <stddef.h>
#include <string.h>
/* Inner layers may be released only after an observed process exit. Native
 * roots additionally require every sandbox for the title to be gone. */
static inline int fl_cleanup_allowed(int observed_exit,int live_title,int scan_ok,int sandbox_exists,int root){
 return observed_exit&&!live_title&&scan_ok&&(!root||!sandbox_exists);
}
/* Refuse another mount at the same pathname, even if its source is identical. */
static inline int fl_mount_matches(const char *type,const char *from,const char *to,
 const char *expected_from,const char *expected_to,int readonly,int same_fsid){
 return readonly&&same_fsid&&!strcmp(type,"nullfs")&&!strcmp(from,expected_from)&&!strcmp(to,expected_to);
}
#endif
