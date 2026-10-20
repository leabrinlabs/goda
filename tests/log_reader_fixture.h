#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
uint32_t kernel_get_fw_version(void);
int kernel_set_ucred_authid(int,uint64_t);
int kernel_set_ucred_caps(int,const uint8_t*);
int kernel_set_ucred_uid(int,int);
