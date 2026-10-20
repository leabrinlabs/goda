/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 gasb07
 * PS4 pkg reader: header, entry table, fake-key entry decryption, param.sfo. */
/* PS4 pkg reader: header, entry table, fake-key entry decryption, param.sfo. */
#include "pkg.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto.h"
#include "keys.h"

static int unwrap_key3(pkg_t *pkg);

static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static uint64_t be64(const uint8_t *p) { return (uint64_t)be32(p) << 32 | be32(p + 4); }

static int read_at(int fd, void *buf, size_t len, uint64_t off) {
    uint8_t *p = buf;
    while (len) {
        if (off > INT64_MAX) return -1;
        ssize_t n = pread(fd, p, len, (off_t)off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0)
            return -1;
        p += n;
        len -= (size_t)n;
        off += (uint64_t)n;
    }
    return 0;
}

int pkg_fake_key(pkg_t *pkg) {
    if (!pkg || pkg->fd<0) return 0;
    if (!pkg->dk3_tried) {
        pkg->dk3_tried = 1;
        unwrap_key3(pkg);
    }
    return pkg->have_dk3;
}

static int unwrap_key3(pkg_t *pkg) {
    for (int i=0;i<pkg->nentries;i++)
        if(pkg->entries[i].id==0x10 && (pkg->entries[i].flags1 & 0x80000000u)) return -1;
    size_t len;
    uint8_t *keys = pkg_entry(pkg, 0x10, &len);
    if (!keys || len < 0x20 + 7 * 0x20 + 4 * 0x100) {
        free(keys);
        return -1;
    }
    uint8_t block[256];
    rsa2048_modexp(keys + 0x20 + 7 * 0x20 + 3 * 0x100, k_pkg_key3_d, k_pkg_key3_n, block);
    free(keys);
    if (block[0] != 0 || block[1] != 2)
        return -1;
    int i = 2;
    while (i < 256 && block[i])
        i++;
    if (i < 10 || 256 - (i + 1) != 32)
        return -1;
    memcpy(pkg->dk3, block + i + 1, 32);
    pkg->have_dk3 = 1;
    return 0;
}

int pkg_open(pkg_t *pkg, const char *path) {
    if (!pkg || !path) return -1;
    memset(pkg, 0, sizeof(*pkg));
    pkg->fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (pkg->fd < 0)
        return -1;
    struct stat st;
    if (fstat(pkg->fd, &st) || !S_ISREG(st.st_mode) || st.st_size < (off_t)sizeof(pkg->header)) goto fail;
    if (read_at(pkg->fd, pkg->header, sizeof(pkg->header), 0) || be32(pkg->header) != 0x7f434e54)
        goto fail;
    memcpy(pkg->content_id, pkg->header + 0x40, 36);
    memcpy(pkg->title_id, pkg->content_id + 7, 9);
    pkg->pfs_offset = be64(pkg->header + 0x410);
    pkg->pfs_size = be64(pkg->header + 0x418);
    pkg->pkg_size = be64(pkg->header + 0x430);
    if (pkg->pkg_size < sizeof(pkg->header) || pkg->pkg_size > (uint64_t)st.st_size ||
        pkg->pfs_offset > pkg->pkg_size || pkg->pfs_size > pkg->pkg_size - pkg->pfs_offset) goto fail;
    /* Identity is metadata, never inferred from a path or accepted with embedded separators. */
    for (int i=0;i<36;i++) {
        unsigned char c=(unsigned char)pkg->content_id[i];
        if (!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_')) goto fail;
    }
    if (memcmp(pkg->title_id,"CUSA",4)) goto fail;
    for(int i=4;i<9;i++) if(pkg->title_id[i]<'0'||pkg->title_id[i]>'9') goto fail;
    memcpy(pkg->digest, pkg->header + 0xfe0, 32);
    uint32_t count = be32(pkg->header + 0x10), table = be32(pkg->header + 0x18);
    if (!count || count > PKG_MAX_ENTRIES || table < sizeof(pkg->header) ||
        table > pkg->pkg_size || (uint64_t)count * 32u > pkg->pkg_size - table)
        goto fail;
    uint8_t *tbl = malloc(count * 32u);
    if (!tbl || read_at(pkg->fd, tbl, count * 32u, table)) {
        free(tbl);
        goto fail;
    }
    for (uint32_t i = 0; i < count; i++) {
        pkg_entry_t *e = &pkg->entries[i];
        memcpy(e->raw, tbl + i * 32, 32);
        e->id = be32(e->raw);
        e->flags1 = be32(e->raw + 8);
        e->flags2 = be32(e->raw + 12);
        e->offset = be32(e->raw + 16);
        e->size = be32(e->raw + 20);
        uint64_t need = e->size;
        if (e->flags1 & 0x80000000u) need=(need+15u)&~UINT64_C(15);
        if (e->offset > pkg->pkg_size || need > pkg->pkg_size-e->offset) { free(tbl); goto fail; }
        for (uint32_t j=0;j<i;j++) if(pkg->entries[j].id==e->id) { free(tbl); goto fail; }
    }
    free(tbl);
    pkg->nentries = (int)count;
    return 0;
fail:
    close(pkg->fd);
    pkg->fd = -1;
    return -1;
}

void pkg_close(pkg_t *pkg) {
    if (!pkg) return;
    if (pkg->fd >= 0)
        close(pkg->fd);
    pkg->fd = -1;
}

uint8_t *pkg_entry(pkg_t *pkg, uint32_t id, size_t *len) {
    if (!len) return NULL;
    *len=0;
    if (!pkg || pkg->fd<0) return NULL;
    for (int i = 0; i < pkg->nentries; i++) {
        pkg_entry_t *e = &pkg->entries[i];
        if (e->id != id)
            continue;
        /* the size comes from the file: the entries read here (param.sfo, artwork, sound,
         * PlayGo data) are far smaller, and a bigger one is a damaged pkg */
        if (e->size > PKG_MAX_ENTRY_SIZE)
            return NULL;
        size_t padded = (e->flags1 & 0x80000000u) ? (((size_t)e->size + 15u) & ~(size_t)15u) : e->size;
        if (e->offset > pkg->pkg_size || padded > pkg->pkg_size-e->offset) return NULL;
        uint8_t *buf = malloc(padded + 1);
        if (!buf || read_at(pkg->fd, buf, padded, e->offset)) {
            free(buf);
            return NULL;
        }
        if (e->flags1 & 0x80000000u) {
            if (!pkg_fake_key(pkg) || ((e->flags2 >> 12) & 0xf) != 3) {
                free(buf);
                return NULL;
            }
            uint8_t seed[64], ivk[32];
            memcpy(seed, e->raw, 32);
            memcpy(seed + 32, pkg->dk3, 32);
            sha256(seed, sizeof(seed), ivk);
            aes128_cbc_decrypt(ivk + 16, ivk, buf, padded);
        }
        buf[e->size] = 0;
        *len = e->size;
        return buf;
    }
    return NULL;
}

static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }

int sfo_parse(const uint8_t *d, size_t len, sfo_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!d || len < 20 || le32(d) != 0x46535000)
        return -1;
    uint32_t ko = le32(d + 8), dof = le32(d + 12), n = le32(d + 16);
    if (n > 128 || n > (len-20)/16 || ko < 20+n*16 || ko > dof || dof > len) return -1;
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *ent = d + 20 + i * 16;
        if ((size_t)(ent - d) + 16 > len)
            return -1;
        uint16_t kof = le16(ent), fmt = le16(ent + 2);
        uint32_t ln = le32(ent + 4), cap = le32(ent + 8), vof = le32(ent + 12);
        /* offsets and lengths come from the file: everything must lie inside it */
        uint64_t key = (uint64_t)ko + kof, val = (uint64_t)dof + vof;
        if (key >= dof || val > len || (fmt == 0x404 ? 4 : ln) > len - val ||
            ln > cap || cap > len-val || (fmt == 0x404 && ln != 4) ||
            (fmt != 0x404 && fmt != 0x204 && fmt != 0x004))
            return -1;
        sfo_item_t *it = &out->items[out->count++];
        size_t kl = strnlen((const char *)d + key, dof - key);
        if (!kl || kl >= dof-key || kl >= sizeof(it->key)) return -1;
        memcpy(it->key, d + key, kl);
        it->key[kl] = 0;
        for (int j=0;j<out->count-1;j++) if(!strcmp(out->items[j].key,it->key)) return -1;
        const uint8_t *v = d + val;
        if (fmt == 0x404) {
            it->is_int = 1;
            it->ival = le32(v);
        } else {
            size_t l = ln < sizeof(it->sval) - 1 ? ln : sizeof(it->sval) - 1;
            memcpy(it->sval, v, l);
            it->sval[l] = 0;
        }
    }
    return 0;
}

const sfo_item_t *sfo_get(const sfo_t *sfo, const char *key) {
    for (int i = 0; i < sfo->count; i++)
        if (!strcmp(sfo->items[i].key, key))
            return &sfo->items[i];
    return NULL;
}
