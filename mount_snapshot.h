/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FL_MOUNT_SNAPSHOT_H
#define FL_MOUNT_SNAPSHOT_H
#include <stdlib.h>
#include <errno.h>
/* getmntinfo uses libc-owned mutable storage. Give each caller its own bounded
 * snapshot; reject a full/truncated result rather than assume no child mount. */
static inline int fl_mount_snapshot(struct statfs **out){
 *out=NULL;
 for(unsigned attempt=0;attempt<3;attempt++){
  int n=getfsstat(NULL,0,MNT_NOWAIT);if(n<=0||n>8192){errno=EIO;return -1;}
  size_t capacity=(size_t)n+16;if(capacity>8192)capacity=8192;
  struct statfs *data=calloc(capacity,sizeof(*data));if(!data)return -1;
  int got=getfsstat(data,(long)(capacity*sizeof(*data)),MNT_NOWAIT);
  if(got>0&&(size_t)got<capacity){*out=data;return got;}
  free(data);if(got<0)return -1;
 }
 errno=EAGAIN;return -1;
}
#endif
