/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 gasb07
 * Minimal SHA-256, AES-128 (decrypt), CRC32C and 2048-bit RSA modexp. */
/* Minimal SHA-256, AES-128 (decrypt), CRC32C and 2048-bit RSA modexp. */
#include "crypto.h"

#include <string.h>
#include <stdatomic.h>
#if defined(__x86_64__) && !defined(FL_CRYPTO_FORCE_PORTABLE)
#include <wmmintrin.h>
#endif

/* --- SHA-256 --- */

static const uint32_t k_sha[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t s[8], const uint8_t *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 | (uint32_t)p[i * 4 + 2] << 8 | p[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + k_sha[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

void sha256_init(sha256_ctx *c) {
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(c->state, iv, sizeof(iv));
    c->total = 0;
    c->used = 0;
}

void sha256_update(sha256_ctx *c, const void *data, size_t len) {
    const uint8_t *p = data;
    c->total += len;
    while (len) {
        size_t n = 64 - c->used < len ? 64 - c->used : len;
        memcpy(c->buf + c->used, p, n);
        c->used += n;
        p += n;
        len -= n;
        if (c->used == 64) {
            sha256_block(c->state, c->buf);
            c->used = 0;
        }
    }
}

void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->total * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    pad = 0;
    while (c->used != 56)
        sha256_update(c, &pad, 1);
    uint8_t len[8];
    for (int i = 0; i < 8; i++)
        len[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_update(c, len, 8);
    for (int i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(c->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)c->state[i];
    }
}

void sha256(const void *data, size_t len, uint8_t out[32]) {
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

/* --- AES-128 decrypt --- */

static uint8_t sbox[256], inv_sbox[256];

static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1)
            r ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return r;
}

static void aes_tables(void) {
    static atomic_int ready = 0;
    if (atomic_load_explicit(&ready, memory_order_acquire) == 2) return;
    int expected = 0;
    if (!atomic_compare_exchange_strong_explicit(&ready, &expected, 1, memory_order_acq_rel, memory_order_acquire)) {
        while (atomic_load_explicit(&ready, memory_order_acquire) != 2) { }
        return;
    }
    uint8_t p = 1, q = 1;
    do {
        p = p ^ (uint8_t)(p << 1) ^ (p & 0x80 ? 0x1b : 0);
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        if (q & 0x80)
            q ^= 0x09;
        uint8_t x = q ^ (uint8_t)((q << 1) | (q >> 7)) ^ (uint8_t)((q << 2) | (q >> 6)) ^
                    (uint8_t)((q << 3) | (q >> 5)) ^ (uint8_t)((q << 4) | (q >> 4));
        sbox[p] = x ^ 0x63;
    } while (p != 1);
    sbox[0] = 0x63;
    for (int i = 0; i < 256; i++)
        inv_sbox[sbox[i]] = (uint8_t)i;
    atomic_store_explicit(&ready, 2, memory_order_release);
}

static void aes_expand(const uint8_t key[16], uint8_t rk[176]) {
    memcpy(rk, key, 16);
    uint8_t rcon = 1;
    for (int i = 16; i < 176; i += 4) {
        uint8_t t[4] = {rk[i - 4], rk[i - 3], rk[i - 2], rk[i - 1]};
        if (i % 16 == 0) {
            uint8_t u = t[0];
            t[0] = sbox[t[1]] ^ rcon;
            t[1] = sbox[t[2]];
            t[2] = sbox[t[3]];
            t[3] = sbox[u];
            rcon = xtime(rcon);
        }
        for (int j = 0; j < 4; j++)
            rk[i + j] = rk[i - 16 + j] ^ t[j];
    }
}

static void aes_decrypt_block(const uint8_t rk[176], uint8_t b[16]) {
    for (int i = 0; i < 16; i++)
        b[i] ^= rk[160 + i];
    for (int round = 9; round >= 0; round--) {
        uint8_t t[16];
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++)
                t[((c + r) % 4) * 4 + r] = b[c * 4 + r];
        for (int i = 0; i < 16; i++)
            b[i] = inv_sbox[t[i]] ^ rk[round * 16 + i];
        if (round == 0)
            break;
        for (int c = 0; c < 4; c++) {
            uint8_t *s = b + c * 4, a0 = s[0], a1 = s[1], a2 = s[2], a3 = s[3];
            s[0] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
            s[1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
            s[2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
            s[3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
        }
    }
}

void aes128_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16], uint8_t *data, size_t len) {
    aes_tables();
    uint8_t rk[176], prev[16], cur[16];
    aes_expand(key, rk);
    memcpy(prev, iv, 16);
    for (size_t off = 0; off + 16 <= len; off += 16) {
        memcpy(cur, data + off, 16);
        aes_decrypt_block(rk, data + off);
        for (int i = 0; i < 16; i++)
            data[off + i] ^= prev[i];
        memcpy(prev, cur, 16);
    }
}

/* --- CRC32C --- */

uint32_t crc32c(const void *data, size_t len) {
    const uint8_t *p = data;
    uint32_t crc = 0xffffffff;
    while (len--) {
        crc ^= *p++;
        for (int i = 0; i < 8; i++)
            crc = (crc >> 1) ^ (0x82f63b78 & (0u - (crc & 1)));
    }
    return ~crc;
}

/* --- RSA-2048 modexp (Montgomery, 32-bit limbs, little-endian limb order) --- */

#define NL 64

static void from_be(uint32_t *x, const uint8_t *b) {
    for (int i = 0; i < NL; i++) {
        const uint8_t *p = b + 256 - 4 * (i + 1);
        x[i] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
    }
}

static void to_be(uint8_t *b, const uint32_t *x) {
    for (int i = 0; i < NL; i++) {
        uint8_t *p = b + 256 - 4 * (i + 1);
        p[0] = (uint8_t)(x[i] >> 24);
        p[1] = (uint8_t)(x[i] >> 16);
        p[2] = (uint8_t)(x[i] >> 8);
        p[3] = (uint8_t)x[i];
    }
}

static int geq(const uint32_t *a, const uint32_t *b) {
    for (int i = NL - 1; i >= 0; i--)
        if (a[i] != b[i])
            return a[i] > b[i];
    return 1;
}

static void sub_n(uint32_t *a, const uint32_t *b) {
    uint64_t borrow = 0;
    for (int i = 0; i < NL; i++) {
        uint64_t t = (uint64_t)a[i] - b[i] - borrow;
        a[i] = (uint32_t)t;
        borrow = (t >> 32) & 1;
    }
}

static void mont_mul(uint32_t *r, const uint32_t *a, const uint32_t *b, const uint32_t *n, uint32_t ninv) {
    uint32_t t[NL + 2] = {0};
    for (int i = 0; i < NL; i++) {
        uint64_t c = 0;
        for (int j = 0; j < NL; j++) {
            c += (uint64_t)t[j] + (uint64_t)a[j] * b[i];
            t[j] = (uint32_t)c;
            c >>= 32;
        }
        c += t[NL];
        t[NL] = (uint32_t)c;
        t[NL + 1] = (uint32_t)(c >> 32);
        uint32_t m = t[0] * ninv;
        c = ((uint64_t)t[0] + (uint64_t)m * n[0]) >> 32;
        for (int j = 1; j < NL; j++) {
            c += (uint64_t)t[j] + (uint64_t)m * n[j];
            t[j - 1] = (uint32_t)c;
            c >>= 32;
        }
        c += t[NL];
        t[NL - 1] = (uint32_t)c;
        t[NL] = t[NL + 1] + (uint32_t)(c >> 32);
        t[NL + 1] = 0;
    }
    if (t[NL] || geq(t, n))
        sub_n(t, n);
    memcpy(r, t, NL * 4);
}

void rsa2048_modexp(const uint8_t in[256], const uint8_t d[256], const uint8_t nb[256], uint8_t out[256]) {
    uint32_t n[NL], x[NL], acc[NL], r2[NL] = {0}, one[NL] = {0};
    from_be(n, nb);
    from_be(x, in);
    uint32_t inv = 1;
    for (int i = 0; i < 5; i++)
        inv *= 2 - n[0] * inv;
    uint32_t ninv = (uint32_t)0 - inv;

    /* r2 = 2^(2*2048) mod n by repeated doubling */
    r2[0] = 1;
    for (int i = 0; i < 2 * 2048; i++) {
        uint32_t carry = 0;
        for (int j = 0; j < NL; j++) {
            uint32_t v = r2[j];
            r2[j] = (v << 1) | carry;
            carry = v >> 31;
        }
        if (carry || geq(r2, n))
            sub_n(r2, n);
    }
    one[0] = 1;
    mont_mul(x, x, r2, n, ninv);   /* x in Montgomery form */
    mont_mul(acc, one, r2, n, ninv); /* 1 in Montgomery form */
    for (int i = 0; i < 256; i++)
        for (int bit = 7; bit >= 0; bit--) {
            mont_mul(acc, acc, acc, n, ninv);
            if ((d[i] >> bit) & 1)
                mont_mul(acc, acc, x, n, ninv);
        }
    mont_mul(acc, acc, one, n, ninv);
    to_be(out, acc);
}

/* Loader additions: HMAC and sector-based XTS reuse the attributed AES/SHA core. */
void fl_hmac_sha256(const void *key, size_t key_len, const void *data, size_t len, uint8_t out[32]) {
    uint8_t k[64] = {0}, pad[64], inner[32];
    if (key_len > sizeof(k)) sha256(key, key_len, k);
    else if (key_len) memcpy(k, key, key_len);
    sha256_ctx c;
    for (int i=0;i<64;i++) pad[i] = k[i] ^ 0x36;
    sha256_init(&c); sha256_update(&c,pad,64);
    if (len) sha256_update(&c,data,len);
    sha256_final(&c,inner);
    for (int i=0;i<64;i++) pad[i] = k[i] ^ 0x5c;
    sha256_init(&c); sha256_update(&c,pad,64); sha256_update(&c,inner,32); sha256_final(&c,out);
}
static void aes_encrypt_block(const uint8_t rk[176], uint8_t b[16]) {
    for (int i=0;i<16;i++) b[i] ^= rk[i];
    for (int round=1;round<=10;round++) {
        uint8_t t[16];
        for(int c=0;c<4;c++) for(int r=0;r<4;r++) t[c*4+r]=sbox[b[((c+r)%4)*4+r]];
        memcpy(b,t,16);
        if(round!=10) for(int c=0;c<4;c++) {
            uint8_t *a=b+c*4, a0=a[0],a1=a[1],a2=a[2],a3=a[3];
            uint8_t x=a0^a1^a2^a3;
            a[0]=a0^x^xtime(a0^a1); a[1]=a1^x^xtime(a1^a2);
            a[2]=a2^x^xtime(a2^a3); a[3]=a3^x^xtime(a3^a0);
        }
        for(int i=0;i<16;i++) b[i]^=rk[round*16+i];
    }
}
static void xts_next(uint8_t t[16]) {
    unsigned carry=0;
    for(int i=0;i<16;i++) { unsigned v=t[i]; t[i]=(uint8_t)((v<<1)|carry); carry=v>>7; }
    t[0]^=(uint8_t)(0x87u & (0u-carry));
}
#if defined(__x86_64__) && !defined(FL_CRYPTO_FORCE_PORTABLE)
static int fl_cpu_has_aes(void) {
    unsigned a=1,b,c,d;
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
    return (c & (1u<<25)) != 0;
}
__attribute__((target("aes,sse2")))
static void xts_aesni(const uint8_t drk[176], const uint8_t trk[176], uint64_t sector, uint8_t *data, size_t len) {
    __m128i dec[11], enc[11];
    for(int i=0;i<=10;i++) {
        enc[i]=_mm_loadu_si128((const __m128i*)(trk+16*i));
        dec[i]=_mm_loadu_si128((const __m128i*)(drk+16*(10-i)));
        if(i>0 && i<10) dec[i]=_mm_aesimc_si128(dec[i]);
    }
    for(size_t off=0;off<len;off+=4096,sector++) {
        uint8_t tweak[16]={0}; for(int i=0;i<8;i++) tweak[i]=(uint8_t)(sector>>(i*8));
        __m128i v=_mm_xor_si128(_mm_loadu_si128((const __m128i*)tweak),enc[0]);
        for(int i=1;i<10;i++) v=_mm_aesenc_si128(v,enc[i]);
        v=_mm_aesenclast_si128(v,enc[10]); _mm_storeu_si128((__m128i*)tweak,v);
        for(size_t j=0;j<4096;j+=16) {
            __m128i t=_mm_loadu_si128((const __m128i*)tweak);
            v=_mm_xor_si128(_mm_loadu_si128((const __m128i*)(data+off+j)),t);
            v=_mm_xor_si128(v,dec[0]);
            for(int i=1;i<10;i++) v=_mm_aesdec_si128(v,dec[i]);
            v=_mm_aesdeclast_si128(v,dec[10]);
            _mm_storeu_si128((__m128i*)(data+off+j),_mm_xor_si128(v,t)); xts_next(tweak);
        }
    }
}
#endif
int fl_aes128_xts_decrypt(const uint8_t data_key[16], const uint8_t tweak_key[16], uint64_t first_sector, uint8_t *data, size_t len) {
    if(!data_key || !tweak_key || (!data && len) || len%4096 ||
       (len && first_sector>UINT64_MAX-(len/4096-1))) return -1;
    if(!len) return 0;
    uint8_t drk[176],trk[176]; aes_tables(); aes_expand(data_key,drk); aes_expand(tweak_key,trk);
#if defined(__x86_64__) && !defined(FL_CRYPTO_FORCE_PORTABLE)
    if(fl_cpu_has_aes()) { xts_aesni(drk,trk,first_sector,data,len); return 0; }
#endif
    for(size_t off=0;off<len;off+=4096,first_sector++) {
        uint8_t t[16]={0}; for(int i=0;i<8;i++) t[i]=(uint8_t)(first_sector>>(i*8));
        aes_encrypt_block(trk,t);
        for(size_t j=0;j<4096;j+=16) {
            for(int i=0;i<16;i++) data[off+j+i]^=t[i];
            aes_decrypt_block(drk,data+off+j);
            for(int i=0;i<16;i++) data[off+j+i]^=t[i];
            xts_next(t);
        }
    }
    return 0;
}
