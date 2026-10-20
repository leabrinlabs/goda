/* Offline boundary checks; no network, credentials or console access. */
#include "../http_policy.h"
#include <assert.h>
#include <stdio.h>
static int allowed(const char *s){const char *end=strstr(s,"\r\n\r\n");assert(end);return fl_http_local_request(s,end);}
int main(void){
 assert(allowed("GET / HTTP/1.1\r\nHost: 127.0.0.1:9134\r\n\r\n"));
 assert(allowed("POST /api HTTP/1.1\r\nHost: localhost:9134\r\nOrigin: http://localhost:9134\r\nSec-Fetch-Site: same-origin\r\n\r\n"));
 assert(!allowed("GET / HTTP/1.1\r\nHost: example.invalid:9134\r\n\r\n"));
 assert(!allowed("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"));
 assert(!allowed("GET / HTTP/1.1\r\nHost: 127.0.0.1:9134\r\nHost: 127.0.0.1:9134\r\n\r\n"));
 assert(!allowed("POST /api HTTP/1.1\r\nHost: 127.0.0.1:9134\r\nOrigin: http://example.invalid\r\n\r\n"));
 assert(!allowed("POST /api HTTP/1.1\r\nHost: 127.0.0.1:9134\r\nOrigin: null\r\n\r\n"));
 assert(!allowed("POST /api HTTP/1.1\r\nHost: localhost:9134\r\nOrigin: http://localhost:9134\r\nOrigin: http://localhost:9134\r\n\r\n"));
 assert(!allowed("GET / HTTP/1.1\r\nHost: localhost:9134\r\nSec-Fetch-Site: cross-site\r\n\r\n"));
 assert(!allowed("GET / HTTP/1.1\r\n Host: localhost:9134\r\n\r\n"));
 assert(!allowed("GET / HTTP/1.1\r\nHost: localhost:91340\r\n\r\n"));
 puts("PASS local authority, matching origin, DNS-rebinding boundary, duplicate/folded header and cross-site rejection");
}
