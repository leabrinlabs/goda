#!/usr/bin/env python3
"""Host tests against independent cryptography/hashlib implementations; no console I/O.
Optional --pkg reads metadata from an existing local fakePKG without changing it.
"""
import argparse
import ctypes as C
import hashlib
import hmac
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT=Path(__file__).resolve().parents[1]
U8=C.POINTER(C.c_ubyte)
def arr(b): return (C.c_ubyte*len(b)).from_buffer_copy(b)
def build(directory,portable=False):
    wrapper=Path(directory)/'wrapper.c'
    wrapper.write_text('''#include "pkg.h"
#include <stdlib.h>
#include <string.h>
int test_pkg(const char *path, int metadata) {
 pkg_t *p=malloc(sizeof(*p)); if(!p)return -9;
 int r=pkg_open(p,path); if(r){free(p);return -1;}
 if(metadata){size_t n=0; unsigned char *b=pkg_entry(p,0x1000,&n); sfo_t *s=malloc(sizeof(*s));
  r=(!b||!s||sfo_parse(b,n,s))?-2:0;
  if(!r){const sfo_item_t *i=sfo_get(s,"TITLE_ID");if(!i||strcmp(i->sval,p->title_id))r=-3;}
  free(b);free(s);}
 pkg_close(p);free(p);return r;
}
int test_sfo(const unsigned char *b, size_t n) {sfo_t *s=malloc(sizeof(*s));int r=sfo_parse(b,n,s);free(s);return r;}
''')
    lib=Path(directory)/('portable.dylib' if portable else 'native.dylib')
    cmd=['cc','-O2','-std=gnu11','-Wall','-Wextra','-Werror','-shared','-fPIC','-I'+str(ROOT/'vendor'),str(ROOT/'vendor/crypto.c'),str(ROOT/'vendor/pkg.c'),str(wrapper),'-o',str(lib)]
    if portable: cmd.insert(1,'-DFL_CRYPTO_FORCE_PORTABLE')
    subprocess.run(cmd,check=True)
    x=C.CDLL(str(lib));x.sha256.argtypes=[C.c_void_p,C.c_size_t,U8]
    x.fl_hmac_sha256.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,U8]
    x.fl_aes128_xts_decrypt.argtypes=[U8,U8,C.c_uint64,U8,C.c_size_t];x.fl_aes128_xts_decrypt.restype=C.c_int
    x.aes128_cbc_decrypt.argtypes=[U8,U8,U8,C.c_size_t]
    x.test_pkg.argtypes=[C.c_char_p,C.c_int];x.test_pkg.restype=C.c_int
    x.test_sfo.argtypes=[U8,C.c_size_t];x.test_sfo.restype=C.c_int
    return x

def crypto_tests(x):
    rng=random.Random(498204)
    rb=lambda n:rng.randbytes(n)
    for n in [0,1,55,56,63,64,65,4096,131073]:
        b=rb(n);out=arr(bytes(32));x.sha256(arr(b),n,out);assert bytes(out)==hashlib.sha256(b).digest()
        for klen in [0,16,64,65,131]:
            key=rb(klen);x.fl_hmac_sha256(arr(key),klen,arr(b),n,out);assert bytes(out)==hmac.digest(key,b,'sha256')
    # RFC 4231 case 1.
    out=arr(bytes(32));x.fl_hmac_sha256(arr(b'\x0b'*20),20,arr(b'Hi There'),8,out)
    assert bytes(out).hex()=='b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
    for n in [16,32,4096]:
        key,iv,plain=rb(16),rb(16),rb(n)
        enc=Cipher(algorithms.AES(key),modes.CBC(iv)).encryptor(); b=arr(enc.update(plain)+enc.finalize())
        x.aes128_cbc_decrypt(arr(key),arr(iv),b,n);assert bytes(b)==plain
    for first,sectors in [(0,1),(1,2),(256,3),(0x123456789abcdef0,5),(2**64-1,1)]:
        dk,tk,plain=rb(16),rb(16),rb(sectors*4096);cipher=bytearray()
        for i in range(sectors):
            e=Cipher(algorithms.AES(dk+tk),modes.XTS((first+i).to_bytes(16,'little'))).encryptor()
            cipher+=e.update(plain[i*4096:(i+1)*4096])+e.finalize()
        b=arr(cipher);assert x.fl_aes128_xts_decrypt(arr(dk),arr(tk),first,b,len(b))==0;assert bytes(b)==plain
    b=arr(rb(8192));before=bytes(b);key=arr(rb(16))
    for first,n in [(0,4095),(2**64-1,8192)]:
        assert x.fl_aes128_xts_decrypt(key,key,first,b,n)==-1;assert bytes(b)==before
    assert x.fl_aes128_xts_decrypt(key,key,0,b,0)==0

def fixture():
    b=bytearray(0x2000);b[:4]=b'\x7fCNT'
    def u32(o,v):struct.pack_into('>I',b,o,v)
    def u64(o,v):struct.pack_into('>Q',b,o,v)
    b[0x40:0x40+36]=b'EP0001-CUSA12345_00-ABCDEFGHIJKLMNOP'
    u64(0x430,len(b));u32(0x10,1);u32(0x18,0x1000)
    u32(0x1000,0x1000);u32(0x1010,0x1800);u32(0x1014,3);b[0x1800:0x1803]=b'abc'
    return b

def pkg_tests(x,directory):
    p=Path(directory)/'fixture.pkg';valid=fixture();p.write_bytes(valid);assert x.test_pkg(os.fsencode(p),0)==0
    cases=[]
    for cut in [0,32,4095,len(valid)-1]:cases.append(valid[:cut])
    for off,fmt,val in [(0,'>I',0),(0x430,'>Q',len(valid)+1),(0x410,'>Q',len(valid)+1),(0x418,'>Q',2**64-1),(0x10,'>I',513),(0x10,'>I',0),(0x18,'>I',4095),(0x18,'>I',len(valid)-1),(0x1010,'>I',len(valid)-1),(0x1014,'>I',2**32-1)]:
        b=bytearray(valid);struct.pack_into(fmt,b,off,val);cases.append(b)
    b=bytearray(valid);b[0x47:0x50]=b'BAD123456';cases.append(b)
    b=bytearray(valid);struct.pack_into('>I',b,0x10,2);b[0x1020:0x1040]=b[0x1000:0x1020];cases.append(b)
    for b in cases:p.write_bytes(b);assert x.test_pkg(os.fsencode(p),0)==-1
    p.write_bytes(valid);link=Path(directory)/'symlink.pkg';link.symlink_to(p);assert x.test_pkg(os.fsencode(link),0)==-1
    assert x.test_pkg(os.fsencode(directory),0)==-1
    # Valid minimal SFO plus malformed count, terminator, entry bounds.
    s=bytearray(48);struct.pack_into('<5I',s,0,0x46535000,0x101,36,40,1)
    struct.pack_into('<HHIII',s,20,0,0x204,4,8,0);s[36:40]=b'KEY\0';s[40:44]=b'abc\0'
    assert x.test_sfo(arr(s),len(s))==0
    for off,val in [(16,129),(8,20),(12,49),(24,40),(32,50)]:
        bad=bytearray(s);struct.pack_into('<I',bad,off,val);assert x.test_sfo(arr(bad),len(bad))==-1
    bad=bytearray(s);bad[39]=65;assert x.test_sfo(arr(bad),len(bad))==-1
    return len(cases)+3

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--pkg',type=Path);args=ap.parse_args()
    for portable in (False,True):
        with tempfile.TemporaryDirectory(prefix='fl-crypto-test-') as d:
            x=build(d,portable);crypto_tests(x);count=pkg_tests(x,d)
            if args.pkg:assert x.test_pkg(os.fsencode(args.pkg),1)==0,'real package metadata/SFO failed'
            print(('portable' if portable else 'native')+f': SHA256/HMAC/CBC/XTS and {count} invalid PKG cases passed'+('; real package metadata passed' if args.pkg else ''))
