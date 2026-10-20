/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef GODA_HTTP_POLICY_H
#define GODA_HTTP_POLICY_H
#include <string.h>
#include <strings.h>
/* Loopback binding alone does not validate a browser's request origin. Check
 * Host before serving the UI/token, and require any Origin to match it. Raw
 * local clients may omit Origin; the API still requires the per-run token. */
static inline int fl_local_authority(const char *s,size_t n){
 return (n==14&&!strncasecmp(s,"127.0.0.1:9134",14))||
        (n==14&&!strncasecmp(s,"localhost:9134",14));
}
static inline int fl_http_local_request(const char *headers,const char *end){
 const char *line=strstr(headers,"\r\n"),*host=NULL,*origin=NULL;size_t hn=0,on=0;int hosts=0,origins=0,sites=0;
 if(!line||line>end)return 0;line+=2;
 while(line<end){
  const char *next=strstr(line,"\r\n");if(!next||next>end||*line==' '||*line=='\t')return 0;
  const char *colon=memchr(line,':',(size_t)(next-line));if(!colon||colon==line)return 0;
  size_t key=(size_t)(colon-line);for(size_t i=0;i<key;i++)if(!((line[i]>='A'&&line[i]<='Z')||(line[i]>='a'&&line[i]<='z')||(line[i]>='0'&&line[i]<='9')||line[i]=='-'))return 0;
  const char *v=colon+1,*tail=next;while(v<tail&&(*v==' '||*v=='\t'))v++;while(tail>v&&(tail[-1]==' '||tail[-1]=='\t'))tail--;size_t n=(size_t)(tail-v);
  if(key==4&&!strncasecmp(line,"Host",key)){if(hosts++)return 0;host=v;hn=n;}
  else if(key==6&&!strncasecmp(line,"Origin",key)){if(origins++)return 0;origin=v;on=n;}
  else if(key==14&&!strncasecmp(line,"Sec-Fetch-Site",key)){if(sites++)return 0;if(!((n==4&&!memcmp(v,"none",4))||(n==11&&!memcmp(v,"same-origin",11))||(n==9&&!memcmp(v,"same-site",9))))return 0;}
  line=next+2;
 }
 return hosts==1&&fl_local_authority(host,hn)&&(!origin||(on==hn+7&&!memcmp(origin,"http://",7)&&!strncasecmp(origin+7,host,hn)));
}
#endif
