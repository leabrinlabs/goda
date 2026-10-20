/* In-memory malformed input coverage; no package/output files created. */
#include <stdlib.h>
static int fixture_deny_allocation;
static void *fixture_calloc(size_t n,size_t size){return fixture_deny_allocation?NULL:calloc(n,size);}
#define calloc fixture_calloc
#include "../extract_reader.c"
#undef calloc
#include <assert.h>
static int mem_read(stream *s,uint64_t at,void *out,size_t n){memcpy(out,(uint8_t*)s->ctx+at,n);return 0;}
static void put32(uint8_t *p,uint32_t x){for(int i=0;i<4;i++)p[i]=(uint8_t)(x>>(8*i));}
static void put64(uint8_t *p,uint64_t x){for(int i=0;i<8;i++)p[i]=(uint8_t)(x>>(8*i));}
int main(void){char allocation_error[128];memset(allocation_error,0xab,sizeof(allocation_error));fixture_deny_allocation=1;assert(!fl_pkg_open("unused",allocation_error,sizeof(allocation_error)));assert(!strcmp(allocation_error,"Package reader allocation failed"));fixture_deny_allocation=0;uint8_t data[8192]={0},plain[4096],out[4096];memset(plain,0x42,sizeof(plain));put32(data,0x43534650);put32(data+12,4096);put64(data+16,4096);put64(data+24,48);put64(data+32,64);put64(data+40,4096);put64(data+48,64);uLongf packed=4096;assert(compress(data+64,&packed,plain,sizeof(plain))==Z_OK);put64(data+56,64+packed);stream src={sizeof(data),mem_read,data};pfsc p;assert(!pfsc_init(&p,&src));assert(!rd(&p.s,0,out,sizeof(out)));assert(!memcmp(out,plain,sizeof(out)));assert(rd(&p.s,4090,out,7));pfsc_free(&p);
/* Full wrapper checksum corrupted; raw-deflate-only decoder would miss it. */
data[64+packed-1]^=1;assert(!pfsc_init(&p,&src));assert(rd(&p.s,0,out,sizeof(out)));pfsc_free(&p);data[64+packed-1]^=1;
/* Extra trailing byte is forbidden even if the zlib stream itself is valid. */
put64(data+56,65+packed);assert(!pfsc_init(&p,&src));assert(rd(&p.s,0,out,sizeof(out)));pfsc_free(&p);
put64(data+56,64);assert(pfsc_init(&p,&src));put64(data+56,9000);assert(pfsc_init(&p,&src));put64(data+56,64+packed);put64(data+48,0);assert(pfsc_init(&p,&src));put64(data+48,64);put64(data+16,8192);assert(pfsc_init(&p,&src));put64(data+16,4096);
/* Valid zlib that produces too little data must not be zero padded. */
packed=4096;assert(compress(data+64,&packed,plain,123)==Z_OK);put64(data+56,64+packed);assert(!pfsc_init(&p,&src));assert(rd(&p.s,0,out,sizeof(out)));pfsc_free(&p);
fl_pkg_reader owner;memset(&owner,0,sizeof(owner));pfs fs;memset(&fs,0,sizeof(fs));fs.owner=&owner;fs.r=&src;fs.bs=4096;inode node;memset(&node,0,sizeof(node));node.blocks=2;node.db[0]=1;node.db[1]=-1;assert(make_map(&fs,&node));free(node.map);node.map=NULL;node.blocks=MAX_BLOCKS+1;assert(make_map(&fs,&node));assert(append_indirect(&fs,1,6,NULL,NULL,0));/* Directory traversal and ambiguous embedded-NUL names must be rejected. */
memset(data,0,sizeof(data));inode nodes[2];memset(nodes,0,sizeof(nodes));nodes[0].mode=0040000;nodes[0].blocks=1;nodes[0].db[0]=1;nodes[0].size=4096;nodes[1].mode=0100000;fs.nodes=nodes;fs.n=2;owner.visiting=calloc(2,1);uint8_t *ent=data+4096;put32(ent,1);put32(ent+4,2);put32(ent+8,4);put32(ent+12,24);memcpy(ent+16,"../x",4);assert(walk(&fs,0,"",0,0));memset(owner.visiting,0,2);memcpy(ent+16,"a/bx",4);assert(walk(&fs,0,"",0,0));memset(owner.visiting,0,2);memcpy(ent+16,"a\\bx",4);assert(walk(&fs,0,"",0,0));memset(owner.visiting,0,2);memcpy(ent+16,"a\0bx",4);assert(walk(&fs,0,"",0,0));free(nodes[0].map);free(owner.visiting);
puts("PASS strict PFSC checksums, lengths, maps, read bounds and PFS block bounds");return 0;}
