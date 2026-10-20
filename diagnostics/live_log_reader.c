/* SPDX-License-Identifier: GPL-3.0-or-later
 * Passive, separate diagnostic ELF. No game launch, mounts, hooks, process
 * termination, game-file access or save access. Outbound log records only.
 */
#ifdef FL_LOG_READER_TEST
#include "../tests/log_reader_fixture.h"
#else
#include "sm_platform.h"
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <poll.h>
#ifndef FL_COLLECTOR_IP
#error Collector IP must be explicitly configured by prepare_live_logs.py
#endif
#ifndef FL_LIVE_TOKEN
#error Per-session authentication token is required
#endif
#ifndef FL_COLLECTOR_PORT
#define FL_COLLECTOR_PORT 19146
#endif
#define CHUNK 4096
#define QUEUE_MAX (1024u*1024u)
struct pending {struct pending *next;size_t len,off;char data[];};
static struct pending *head,*last;
static size_t queued;
static uint64_t sequence,dropped_bytes;
static volatile sig_atomic_t stopping;
struct source {const char *channel,*path;int fd;off_t offset;ino_t ino;dev_t dev;int start_at_end;};
static struct source sources[]={
 {"events","/data/ps4-folder-loader-events.log",-1,0,0,0,0},
 {"gate","/data/ps4-folder-loader-launch-gate.log",-1,0,0,0,0},
 {"lifecycle","/data/ps4-folder-loader-lifecycle.log",-1,0,0,0,0},
 {"modules","/data/ps4-folder-loader-modules.log",-1,0,0,0,0},
 {"observation","/data/ps4-folder-loader-observation.log",-1,0,0,0,0},
 {"browser","/data/ps4-folder-loader-browser.log",-1,0,0,0,0},
 {"audit","/data/ps4-folder-loader-audit.log",-1,0,0,0,0},
 /* Old runtime snapshots must never be replayed as a currently live loader. */
 {"runtime","/data/ps4-folder-loader-runtime.log",-1,0,0,0,1}
};
static uint64_t mono(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000+t.tv_nsec/1000;}
static void stop_reader(int sig){(void)sig;stopping=1;}
static void b64(const unsigned char *p,size_t n,char *out){static const char table[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";size_t at=0;for(size_t i=0;i<n;i+=3){unsigned v=(unsigned)p[i]<<16;if(i+1<n)v|=(unsigned)p[i+1]<<8;if(i+2<n)v|=p[i+2];out[at++]=table[v>>18];out[at++]=table[(v>>12)&63];out[at++]=i+1<n?table[(v>>6)&63]:'=';out[at++]=i+2<n?table[v&63]:'=';}out[at]=0;}
static int enqueue(const char *channel,const unsigned char *data,size_t n,off_t offset){
 if(n>CHUNK)return -1;size_t cap=256+((n+2)/3)*4;if(queued+cap>QUEUE_MAX)return -1;
 struct pending *p=malloc(sizeof(*p)+cap);if(!p)return -1;char encoded[((CHUNK+2)/3)*4+1];b64(data,n,encoded);
 int len=snprintf(p->data,cap,"{\"v\":1,\"seq\":%llu,\"mono_us\":%llu,\"channel\":\"%s\",\"offset\":%lld,\"data_b64\":\"%s\"}\n",(unsigned long long)(sequence+1),(unsigned long long)mono(),channel,(long long)offset,encoded);
 if(len<0||(size_t)len>=cap){free(p);return -1;}p->len=(size_t)len;p->off=0;p->next=NULL;sequence++;if(last)last->next=p;else head=p;last=p;queued+=p->len;return 0;
}
static void status(const char *text){(void)enqueue("status",(const unsigned char*)text,strlen(text),-1);}
static int connect_collector(void){
 int fd=socket(AF_INET,SOCK_STREAM,0);if(fd<0)return -1;int flags=fcntl(fd,F_GETFL,0);if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)){close(fd);return -1;}
 struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_port=htons(FL_COLLECTOR_PORT);if(inet_pton(AF_INET,FL_COLLECTOR_IP,&a.sin_addr)!=1){close(fd);return -1;}
 int rc=connect(fd,(void*)&a,sizeof(a));if(rc&&errno!=EINPROGRESS){close(fd);return -1;}
 struct pollfd p={.fd=fd,.events=POLLOUT};int error=0;socklen_t len=sizeof(error);
 if(rc&&(poll(&p,1,300)<=0||getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&len)||error)){close(fd);return -1;}
 return fd;
}
static void tail_source(struct source *s){
 struct stat pathst,st;if(lstat(s->path,&pathst)||!S_ISREG(pathst.st_mode)){if(s->fd>=0)close(s->fd);s->fd=-1;return;}
 if(s->fd<0||pathst.st_ino!=s->ino||pathst.st_dev!=s->dev){if(s->fd>=0)close(s->fd);s->fd=open(s->path,O_RDONLY|O_NOFOLLOW);if(s->fd<0)return;if(fstat(s->fd,&st)||!S_ISREG(st.st_mode)||st.st_ino!=pathst.st_ino||st.st_dev!=pathst.st_dev){close(s->fd);s->fd=-1;return;}s->ino=st.st_ino;s->dev=st.st_dev;s->offset=s->start_at_end?st.st_size:st.st_size>65536?st.st_size-65536:0;}
 if(fstat(s->fd,&st))return;if(st.st_size<s->offset){s->offset=0;status("source_truncated");}
 unsigned char bytes[CHUNK];ssize_t n=pread(s->fd,bytes,sizeof(bytes),s->offset);if(n>0&&!enqueue(s->channel,bytes,(size_t)n,s->offset))s->offset+=n;
}
int main(void){
 if((kernel_get_fw_version()>>16)!=0x1360u)return 1;const uint8_t caps[16]={[0 ... 15]=0xff};if(kernel_set_ucred_authid(-1,0x4800000000000006ull)||kernel_set_ucred_caps(-1,caps)||kernel_set_ucred_uid(-1,0))return 1;
 signal(SIGPIPE,SIG_IGN);signal(SIGTERM,stop_reader);signal(SIGINT,stop_reader);
 int klog=open("/dev/klog",O_RDONLY|O_NONBLOCK),sock=-1;uint64_t start=mono(),retry=0,heartbeat=0,tail=0;char hello[192];int h=snprintf(hello,sizeof(hello),"PS4FL-LIVE/1 %s %d-%llu\n",FL_LIVE_TOKEN,(int)getpid(),(unsigned long long)start);size_t hello_off=0;
 status(klog<0?"reader_started klog_unavailable":"reader_started klog_open_readonly ring_read_may_consume_data");
 while(!stopping){
  uint64_t now=mono();if(sock<0&&now>=retry){sock=connect_collector();retry=now+1000000;hello_off=0;for(struct pending *p=head;p;p=p->next)p->off=0;}
  if(dropped_bytes&&queued<QUEUE_MAX/2){char message[128];snprintf(message,sizeof(message),"LOSS kernel_bytes=%llu reason=queue_capacity",(unsigned long long)dropped_bytes);if(!enqueue("status",(unsigned char*)message,strlen(message),-1))dropped_bytes=0;}
  if(klog>=0)for(unsigned reads=0;reads<4;reads++){unsigned char bytes[CHUNK];ssize_t n=read(klog,bytes,sizeof(bytes));if(n<=0)break;if(enqueue("klog",bytes,(size_t)n,-1))dropped_bytes+=(uint64_t)n;}
  if(now>=tail){for(size_t i=0;i<sizeof(sources)/sizeof(sources[0]);i++)tail_source(&sources[i]);tail=now+200000;}
  if(now>=heartbeat){status("heartbeat");heartbeat=now+2000000;}
  if(sock>=0)for(unsigned writes=0;writes<32&&sock>=0;writes++){const char *data=NULL;size_t len=0;if(hello_off<(size_t)h){data=hello+hello_off;len=(size_t)h-hello_off;}else if(head){data=head->data+head->off;len=head->len-head->off;}
   if(!len)break;{ssize_t n=send(sock,data,len,0);if(n>0){if(hello_off<(size_t)h)hello_off+=(size_t)n;else{head->off+=(size_t)n;if(head->off==head->len){struct pending *old=head;head=old->next;queued-=old->len;if(!head)last=NULL;free(old);}}}else if(n==0||(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)){close(sock);sock=-1;}else break;}
  }
  usleep(20000);
 }
 if(sock>=0)close(sock);if(klog>=0)close(klog);for(size_t i=0;i<sizeof(sources)/sizeof(sources[0]);i++)if(sources[i].fd>=0)close(sources[i].fd);while(head){struct pending *p=head;head=p->next;free(p);}return 0;
}
