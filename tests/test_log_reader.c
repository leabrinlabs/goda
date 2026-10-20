/* Exercise the same base64, frame encoder and queue bound as the native ELF. */
#define FL_LOG_READER_TEST
#define FL_COLLECTOR_IP "127.0.0.1"
#define FL_LIVE_TOKEN "fixture"
#define main native_reader_main
#include "../diagnostics/live_log_reader.c"
#undef main
#include <assert.h>
int main(int argc,char **argv){assert(argc==2);unsigned char data[CHUNK];for(size_t i=0;i<sizeof(data);i++)data[i]=(unsigned char)i;
 assert(!enqueue("klog",data,sizeof(data),-1));FILE *f=fopen(argv[1],"wb");assert(f);assert(fwrite(head->data,1,head->len,f)==head->len);fclose(f);
 size_t count=1;while(!enqueue("audit",data,sizeof(data),1234))count++;assert(count>1&&queued<=QUEUE_MAX&&count<1024);assert(enqueue("audit",data,CHUNK+1,0)<0);
 while(head){struct pending *p=head;head=p->next;free(p);}last=NULL;queued=0;
 /* Runtime telemetry skips historical bytes on reader startup. Old boot or
  * dead-process snapshots cannot be relabeled as currently live. */
 char path[]="/tmp/ps4fl-reader-test-XXXXXX";int fd=mkstemp(path);assert(fd>=0);
 assert(write(fd,"historical\n",11)==11);
 struct source source={"runtime",path,-1,0,0,0,1};tail_source(&source);
 assert(!head&&source.offset==11);
 assert(write(fd,"new-state\n",10)==10);tail_source(&source);
 assert(head&&source.offset==21&&strstr(head->data,"\"channel\":\"runtime\""));
 close(fd);close(source.fd);unlink(path);
 while(head){struct pending *p=head;head=p->next;free(p);}last=NULL;queued=0;
 puts("PASS: frame encoding, bounded queue and runtime history skipped until new data");return 0;}
