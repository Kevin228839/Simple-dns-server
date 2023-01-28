#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <resolv.h>
#define err_quit(m) { perror(m); exit(0); }
#define MAXLINE 1024
#define TYPEMAX 10

void soa(char* domain_name, char* query_class, char* zoneline, char* soa_section, int* soa_len) {
  char* token3; // for strtok (fill up rdata)
  char* token4; // for strtok (fill up rdata)
  char domain_name_revised[MAXLINE];
  int count, cnt, name_cnt;
  struct soastruct{
    char name[MAXLINE];
    char type[3];
    char clas[3];
    char ttl[5];
    char datalen[3];
    char ns[MAXLINE];
    char rmail[MAXLINE];
    char serial[5];
    char refresh[5];
    char retry[5];
    char expire[5];
    char min[5];
  } soa;
  memset(&soa, 0, sizeof(soa));
  // name
  memset(domain_name_revised, 0, MAXLINE);
  memset(domain_name_revised, '.', 1);
  memcpy(domain_name_revised+1, domain_name, strlen(domain_name));
  name_cnt = 0;
  for(int i=1; i<strlen(domain_name_revised); i++) {
    if(i+1 == strlen(domain_name_revised)) {
      domain_name_revised[i-name_cnt-1] = name_cnt;
      memset(domain_name_revised+i, 0, 1);
    } else {
      if(domain_name_revised[i] != '.') {
        name_cnt++;
      } else {
        domain_name_revised[i-name_cnt-1] = name_cnt;
        name_cnt = 0;
      }
    }
  }
  memcpy(soa.name, domain_name_revised, strlen(domain_name_revised));
  // type
  soa.type[1] = 6;
  // class
  memcpy(soa.clas, query_class, sizeof(query_class));
  token3 = strtok(zoneline, ",");
  // ttl
  token3 = strtok(NULL, ",");
  soa.ttl[0] = atoi(token3)/pow(256, 3);
  soa.ttl[1] = atoi(token3)/pow(256, 2);
  soa.ttl[2] = atoi(token3)/pow(256, 1);
  soa.ttl[3] = atoi(token3)%256;
  //ns
  token3 = strtok(NULL, ",");
  token3 = strtok(NULL, ",");
  token3 = strtok(NULL, ",");
  token4 = strtok(token3, " ");
  memcpy(soa.ns, token4, strlen(token4));
  // rmail
  token4 = strtok(NULL, " ");
  memcpy(soa.rmail, token4, strlen(token4));
  // serial 
  token4 = strtok(NULL, " ");
  soa.serial[0] = atoi(token4)/pow(256,3);
  soa.serial[1] = atoi(token4)/pow(256,2);
  soa.serial[2] = atoi(token4)/pow(256,1);
  soa.serial[3] = atoi(token4)%256;
  // refresh
  token4 = strtok(NULL, " ");
  soa.refresh[0] = atoi(token4)/pow(256,3);
  soa.refresh[1] = atoi(token4)/pow(256,2);
  soa.refresh[2] = atoi(token4)/pow(256,1);
  soa.refresh[3] = atoi(token4)%256;
  // retry
  token4 = strtok(NULL, " ");
  soa.retry[0] = atoi(token4)/pow(256,3);
  soa.retry[1] = atoi(token4)/pow(256,2);
  soa.retry[2] = atoi(token4)/pow(256,1);
  soa.retry[3] = atoi(token4)%256;
  // retry
  token4 = strtok(NULL, " ");
  soa.expire[0] = atoi(token4)/pow(256,3);
  soa.expire[1] = atoi(token4)/pow(256,2);
  soa.expire[2] = atoi(token4)/pow(256,1);
  soa.expire[3] = atoi(token4)%256;
  // min
  token4 = strtok(NULL, " ");
  soa.min[0] = atoi(token4)/pow(256,3);
  soa.min[1] = atoi(token4)/pow(256,2);
  soa.min[2] = atoi(token4)/pow(256,1);
  soa.min[3] = atoi(token4)%256;
  // datalen
  int datalength = strlen(soa.ns) + 1 + strlen(soa.rmail) + 1 + 20;
  soa.datalen[0] = datalength/256;
  soa.datalen[1] = datalength%256;

  /* copy data to soa_section*/
  count = 0;
  memcpy(soa_section, soa.name, strlen(soa.name));
  count = count + strlen(soa.name) + 1;
  memcpy(soa_section + count, soa.type, 2);
  count += 2;
  memcpy(soa_section + count, soa.clas, 2);
  count += 2;
  memcpy(soa_section + count, soa.ttl, 4);
  count += 4;
  memcpy(soa_section + count, soa.datalen, 2);
  count += 2;
  count += 1;
  memcpy(soa_section + count , soa.ns, strlen(soa.ns));
  cnt = 0;
  for(int i=0; i<strlen(soa.ns); i++) {
    if(i+1 == strlen(soa.ns)) {
      memset(soa_section+count+i-cnt-1, cnt, 1);
      memset(soa_section+count+i, 0, 1);
    } else {  
      if(soa.ns[i] != '.') {
      cnt++;
      } else {
        memset(soa_section+count+i-cnt-1, cnt, 1);
        cnt = 0;
      }
    }
  }
  count = count + strlen(soa.ns);
  count += 1;
  memcpy(soa_section + count, soa.rmail, strlen(soa.rmail));
  cnt = 0;
  for(int i=0; i<strlen(soa.rmail); i++) {
    if(i+1 == strlen(soa.rmail)) {
      memset(soa_section+count+i-cnt-1, cnt, 1);
      memset(soa_section+count+i, 0, 1);
    } else {  
      if(soa.rmail[i] != '.') {
        cnt++;
      } else {
        memset(soa_section+count+i-cnt-1, cnt, 1);
        cnt = 0;
      }
    }
  }
  count = count + strlen(soa.rmail);
  memcpy(soa_section + count, soa.serial, 4);
  count += 4;
  memcpy(soa_section + count, soa.refresh, 4);
  count += 4;
  memcpy(soa_section+ count, soa.retry, 4);
  count += 4;
  memcpy(soa_section + count, soa.expire, 4);
  count += 4;
  memcpy(soa_section + count, soa.min, 4);
  count += 4;
  *soa_len = count;

}

void ns(char* domain_name, char* query_class, char* zoneline, char* ns_section, char* ns_section_name, int* ns_len, int* ns_count) {
  char* token3;
  char* token4;
  char domain_name_revised[MAXLINE];
  int count, cnt, name_cnt;
  struct nsstruct {
    char name[MAXLINE];
    char type[3];
    char clas[3];
    char ttl[5];
    char datalen[3];
    char ns[MAXLINE];
  } ns;
  memset(&ns, 0, sizeof(ns));
  // save name to ns_section_name (ex: @, dns, mail...)
  token3 = strtok(zoneline, ",");
  memcpy(ns_section_name, token3, strlen(token3));
  // name
  memset(domain_name_revised, 0, MAXLINE);
  memset(domain_name_revised, '.', 1);
  memcpy(domain_name_revised+1, domain_name, strlen(domain_name));
  name_cnt = 0;
  for(int i=1; i<strlen(domain_name_revised); i++) {
    if(i+1 == strlen(domain_name_revised)) {
      domain_name_revised[i-name_cnt-1] = name_cnt;
      memset(domain_name_revised+i, 0, 1);
    } else {
      if(domain_name_revised[i] != '.') {
      name_cnt++;
      } else {
        domain_name_revised[i-name_cnt-1] = name_cnt;
        name_cnt = 0;
      }
    }
  }

  if(memcmp(token3, "@", 1) ==0) {
    memcpy(ns.name, domain_name_revised, strlen(domain_name_revised));
  } else {
    memset(ns.name, strlen(ns_section_name), 1);
    memcpy(ns.name+1, ns_section_name, strlen(ns_section_name));
    memcpy(ns.name+1+strlen(ns_section_name), domain_name_revised, strlen(domain_name_revised));
  }
  // type
  ns.type[1] = 2;
  // class
  memcpy(ns.clas, query_class, sizeof(query_class));
  // ttl
  token3 = strtok(NULL, ",");
  ns.ttl[0] = atoi(token3)/pow(256, 3);
  ns.ttl[1] = atoi(token3)/pow(256, 2);
  ns.ttl[2] = atoi(token3)/pow(256, 1);
  ns.ttl[3] = atoi(token3)%256;
  // ns
  token3 = strtok(NULL, ",");
  token3 = strtok(NULL, ",");
  token3 = strtok(NULL, ",");
  token4 = strtok(token3, "\n\r");
  memcpy(ns.ns, token4, strlen(token4));
  // datalen
  int datalength = strlen(ns.ns) + 1;
  ns.datalen[0] = datalength/256;
  ns.datalen[1] = datalength%256;

  /* copy data to ns section */
  count = 0;
  memcpy(ns_section + count, ns.name, strlen(ns.name));
  count = count + strlen(ns.name);
  memset(ns_section + count, 0, 1);
  count += 1;
  memcpy(ns_section + count, ns.type, 2);
  count += 2;
  memcpy(ns_section + count, ns.clas, 2);
  count += 2;
  memcpy(ns_section + count, ns.ttl, 4);
  count += 4;
  memcpy(ns_section + count, ns.datalen, 2);
  count += 2;
  count += 1;
  memcpy(ns_section + count, ns.ns, strlen(ns.ns));
  cnt = 0;
  for(int i=0; i<strlen(ns.ns); i++) {
    if(i+1 == strlen(ns.ns)) {
      memset(ns_section+count+i-cnt-1, cnt, 1);
      memset(ns_section+count+i, 0, 1);
    } else {  
      if(ns.ns[i] != '.') {
        cnt++;
      } else {
        memset(ns_section+count+i-cnt-1, cnt, 1);
        cnt = 0;
      }
    }
  }
  count = count + strlen(ns.ns);
  ns_len[*ns_count] = count;
}

void mx(char* domain_name, char* query_class, char* zoneline, char* mx_section, char* mx_section_name, int* mx_len, int* mx_count) {
  char* token3;
  char* token4;
  char domain_name_revised[MAXLINE];
  int count, cnt, name_cnt;
  struct mxstruct {
    char name[MAXLINE];
    char type[3];
    char clas[3];
    char ttl[5];
    char datalen[3];
    char preference[3];
    char exchange[MAXLINE];
  } mx;
  memset(&mx, 0, sizeof(mx));
  // save name to mx_section _name (ex: @, dns, www...)
  token3 = strtok(zoneline, ",");
  memcpy(mx_section_name, token3, strlen(token3));
  // name
  memset(domain_name_revised, 0, MAXLINE);
  memset(domain_name_revised, '.', 1);
  memcpy(domain_name_revised+1, domain_name, strlen(domain_name));
  name_cnt = 0;
  for(int i=1; i<strlen(domain_name_revised); i++) {
    if(i+1 == strlen(domain_name_revised)) {
      domain_name_revised[i-name_cnt-1] = name_cnt;
      memset(domain_name_revised+i, 0, 1);
    } else {
      if(domain_name_revised[i] != '.') {
      name_cnt++;
      } else {
        domain_name_revised[i-name_cnt-1] = name_cnt;
        name_cnt = 0;
      }
    }
  }

  if(memcmp(token3, "@", 1) ==0) {
    memcpy(mx.name, domain_name_revised, strlen(domain_name_revised));
  } else {
    memset(mx.name, strlen(mx_section_name), 1);
    memcpy(mx.name+1, mx_section_name, strlen(mx_section_name));
    memcpy(mx.name+1+strlen(mx_section_name), domain_name_revised, strlen(domain_name_revised));
  }
  // type
  mx.type[1] = 15;
  // class
  memcpy(mx.clas, query_class, sizeof(query_class));
  // ttl
  token3 = strtok(NULL, ",");
  mx.ttl[0] = atoi(token3)/pow(256, 3);
  mx.ttl[1] = atoi(token3)/pow(256, 2);
  mx.ttl[2] = atoi(token3)/pow(256, 1);
  mx.ttl[3] = atoi(token3)%256;
  // preference
  token3 = strtok(NULL, ",");
  token3 = strtok(NULL, ",");
  token3 = strtok(NULL, ",");
  token4 = strtok(token3, " ");
  mx.preference[0] = atoi(token4)/256;
  mx.preference[1] = atoi(token4)%256;
  // mail exchange
  token4 = strtok(NULL, "\r\n");
  memcpy(mx.exchange, token4, strlen(token4));
  // datalen
  int datalength = 2+strlen(mx.exchange)+1;
  mx.datalen[0] = datalength/256;
  mx.datalen[1] = datalength%256;

  // copy data to mx_section
  count = 0;
  memcpy(mx_section + count, mx.name, strlen(mx.name));
  count = count + strlen(mx.name);
  memset(mx_section + count, 0, 1);
  count += 1;
  memcpy(mx_section + count, mx.type, 2);
  count += 2;
  memcpy(mx_section + count, mx.clas, 2);
  count += 2;
  memcpy(mx_section + count, mx.ttl, 4);
  count += 4;
  memcpy(mx_section + count, mx.datalen, 2);
  count += 2;
  memcpy(mx_section + count, mx.preference, 2);
  count += 2;
  count += 1;
  memcpy(mx_section + count, mx.exchange, strlen(mx.exchange));
  cnt = 0;
  for(int i=0; i<strlen(mx.exchange); i++) {
    if(i+1 == strlen(mx.exchange)) {
      memset(mx_section+count+i-cnt-1, cnt, 1);
      memset(mx_section+count+i, 0, 1);
    } else {  
      if(mx.exchange[i] != '.') {
        cnt++;
      } else {
        memset(mx_section+count+i-cnt-1, cnt, 1);
        cnt = 0;
      }
    }
  }
  count = count + strlen(mx.exchange);
  mx_len[*mx_count] = count;
}

void a(char* domain_name, char* query_class, char* zoneline, char* a_section, char* a_section_name, int* a_len, int* a_count) {
  char* token3;
  char* token4;
  char domain_name_revised[MAXLINE];
  int count, cnt, name_cnt;
  struct astruct {
    char name[MAXLINE];
    char type[3];
    char clas[3];
    char ttl[5];
    char datalen[3];
    char address[5];
  } a;
  memset(&a, 0, sizeof(a));
  // save name to a_section _name (ex: @, dns, www...)
  token3 = strtok(zoneline, ",");
  memcpy(a_section_name, token3, strlen(token3));
    // name
  memset(domain_name_revised, 0, MAXLINE);
  memset(domain_name_revised, '.', 1);
  memcpy(domain_name_revised+1, domain_name, strlen(domain_name));
  name_cnt = 0;
  for(int i=1; i<strlen(domain_name_revised); i++) {
    if(i+1 == strlen(domain_name_revised)) {
      domain_name_revised[i-name_cnt-1] = name_cnt;
      memset(domain_name_revised+i, 0, 1);
    } else {
      if(domain_name_revised[i] != '.') {
      name_cnt++;
      } else {
        domain_name_revised[i-name_cnt-1] = name_cnt;
        name_cnt = 0;
      }
    }
  }

  if(memcmp(token3, "@", 1) ==0) {
    memcpy(a.name, domain_name_revised, strlen(domain_name_revised));
  } else {
    memset(a.name, strlen(a_section_name), 1);
    memcpy(a.name+1, a_section_name, strlen(a_section_name));
    memcpy(a.name+1+strlen(a_section_name), domain_name_revised, strlen(domain_name_revised));
  }
  // type
  a.type[1] = 1;
  // class
  memcpy(a.clas, query_class, sizeof(query_class));
  // ttl
  token3 = strtok(NULL, ",");
  a.ttl[0] = atoi(token3)/pow(256, 3);
  a.ttl[1] = atoi(token3)/pow(256, 2);
  a.ttl[2] = atoi(token3)/pow(256, 1);
  a.ttl[3] = atoi(token3)%256;
  // address
  token3 = strtok(NULL, ",");
  token3 = strtok(NULL, ",");
  token3 = strtok(NULL, ",");
  token4 = strtok(token3, ".");
  a.address[0] = atoi(token4);
  token4 = strtok(NULL, ".");
  a.address[1] = atoi(token4);
  token4 = strtok(NULL, ".");
  a.address[2] = atoi(token4);
  token4 = strtok(NULL, "\r\n");
  a.address[3] = atoi(token4);
  // datalen
  int datalength = 4;
  a.datalen[0] = datalength/256;
  a.datalen[1] = datalength%256;

  // copy data to a_section
  count = 0;
  memcpy(a_section + count, a.name, strlen(a.name));
  count = count + strlen(a.name);
  memset(a_section + count, 0, 1);
  count += 1;
  memcpy(a_section + count, a.type, 2);
  count += 2;
  memcpy(a_section + count, a.clas, 2);
  count += 2;
  memcpy(a_section + count, a.ttl, 4);
  count += 4;
  memcpy(a_section + count, a.datalen, 2);
  count += 2;
  memcpy(a_section + count, a.address, 4);
  count += 4;
  a_len[*a_count] = count;
}

void cname(char* domain_name, char* query_class, char* zoneline, char* cname_section, char* cname_section_name, int* cname_len, int* cname_count) {
  char* token3;
  char* token4;
  char domain_name_revised[MAXLINE];
  int count, cnt, name_cnt;
  struct cnamestruct {
    char name[MAXLINE];
    char type[3];
    char clas[3];
    char ttl[5];
    char datalen[3];
    char cname[MAXLINE];
  } cname;
  memset(&cname, 0, sizeof(cname));
  // save name to cname_section_name (ex: @, dns, mail...)
  token3 = strtok(zoneline, ",");
  memcpy(cname_section_name, token3, strlen(token3));
  // name
  memset(domain_name_revised, 0, MAXLINE);
  memset(domain_name_revised, '.', 1);
  memcpy(domain_name_revised+1, domain_name, strlen(domain_name));
  name_cnt = 0;
  for(int i=1; i<strlen(domain_name_revised); i++) {
    if(i+1 == strlen(domain_name_revised)) {
      domain_name_revised[i-name_cnt-1] = name_cnt;
      memset(domain_name_revised+i, 0, 1);
    } else {
      if(domain_name_revised[i] != '.') {
      name_cnt++;
      } else {
        domain_name_revised[i-name_cnt-1] = name_cnt;
        name_cnt = 0;
      }
    }
  }

  if(memcmp(token3, "@", 1) ==0) {
    memcpy(cname.name, domain_name_revised, strlen(domain_name_revised));
  } else {
    memset(cname.name, strlen(cname_section_name), 1);
    memcpy(cname.name+1, cname_section_name, strlen(cname_section_name));
    memcpy(cname.name+1+strlen(cname_section_name), domain_name_revised, strlen(domain_name_revised));
  }
  // type
  cname.type[1] = 5;
  // class
  memcpy(cname.clas, query_class, sizeof(query_class));
  // ttl
  token3 = strtok(NULL, ",");
  cname.ttl[0] = atoi(token3)/pow(256, 3);
  cname.ttl[1] = atoi(token3)/pow(256, 2);
  cname.ttl[2] = atoi(token3)/pow(256, 1);
  cname.ttl[3] = atoi(token3)%256;
  // cname
  token3 = strtok(NULL, ",");
  token3 = strtok(NULL, ",");
  token3 = strtok(NULL, ",");
  token4 = strtok(token3, "\n\r");
  memcpy(cname.cname, token4, strlen(token4));
  // datalen
  int datalength = strlen(cname.cname) + 1;
  cname.datalen[0] = datalength/256;
  cname.datalen[1] = datalength%256;

  /* copy data to cname section */
  count = 0;
  memcpy(cname_section + count, cname.name, strlen(cname.name));
  count = count + strlen(cname.name);
  memset(cname_section + count, 0, 1);
  count += 1;
  memcpy(cname_section + count, cname.type, 2);
  count += 2;
  memcpy(cname_section + count, cname.clas, 2);
  count += 2;
  memcpy(cname_section + count, cname.ttl, 4);
  count += 4;
  memcpy(cname_section + count, cname.datalen, 2);
  count += 2;
  count += 1;
  memcpy(cname_section + count, cname.cname, strlen(cname.cname));
  cnt = 0;
  for(int i=0; i<strlen(cname.cname); i++) {
    if(i+1 == strlen(cname.cname)) {
      memset(cname_section+count+i-cnt-1, cnt, 1);
      memset(cname_section+count+i, 0, 1);
    } else {  
      if(cname.cname[i] != '.') {
        cnt++;
      } else {
        memset(cname_section+count+i-cnt-1, cnt, 1);
        cnt = 0;
      }
    }
  }
  count = count + strlen(cname.cname);
  cname_len[*cname_count] = count;
}

void txt(char* domain_name, char* query_class, char* zoneline, char* txt_section, char* txt_section_name, int* txt_len, int* txt_count) {
  char* token3;
  char* token4;
  char domain_name_revised[MAXLINE];
  int count, cnt, name_cnt;
  struct txtstruct {
    char name[MAXLINE];
    char type[3];
    char clas[3];
    char ttl[5];
    char datalen[3];
    char txtlen[2];
    char txt[MAXLINE];
  } txt;
  memset(&txt, 0, sizeof(txt));
  // save name to txt_section_name (ex: @, dns, mail...)
  token3 = strtok(zoneline, ",");
  memcpy(txt_section_name, token3, strlen(token3));
  // name
  memset(domain_name_revised, 0, MAXLINE);
  memset(domain_name_revised, '.', 1);
  memcpy(domain_name_revised+1, domain_name, strlen(domain_name));
  name_cnt = 0;
  for(int i=1; i<strlen(domain_name_revised); i++) {
    if(i+1 == strlen(domain_name_revised)) {
      domain_name_revised[i-name_cnt-1] = name_cnt;
      memset(domain_name_revised+i, 0, 1);
    } else {
      if(domain_name_revised[i] != '.') {
      name_cnt++;
      } else {
        domain_name_revised[i-name_cnt-1] = name_cnt;
        name_cnt = 0;
      }
    }
  }

  if(memcmp(token3, "@", 1) ==0) {
    memcpy(txt.name, domain_name_revised, strlen(domain_name_revised));
  } else {
    memset(txt.name, strlen(txt_section_name), 1);
    memcpy(txt.name+1, txt_section_name, strlen(txt_section_name));
    memcpy(txt.name+1+strlen(txt_section_name), domain_name_revised, strlen(domain_name_revised));
  }
  // type
  txt.type[1] = 16;
  // class
  memcpy(txt.clas, query_class, sizeof(query_class));
  // ttl
  token3 = strtok(NULL, ",");
  txt.ttl[0] = atoi(token3)/pow(256, 3);
  txt.ttl[1] = atoi(token3)/pow(256, 2);
  txt.ttl[2] = atoi(token3)/pow(256, 1);
  txt.ttl[3] = atoi(token3)%256;
  // txt
  token3 = strtok(NULL, ",");
  token3 = strtok(NULL, ",");
  token3 = strtok(NULL, ",");
  token4 = strtok(token3, "\n\r");
  memcpy(txt.txt, token4, strlen(token4));
  int txtlength = 0;
  for(int i=1; i<MAXLINE; i++) {
    if(txt.txt[i] == '"') {
      txtlength = i+1-2;
      break;
    }
  }
  memset(txt.txt, 0, MAXLINE);
  memcpy(txt.txt, token4+1, txtlength);
  // txtlength
  txt.txtlen[0] = txtlength;
  // datalen
  int datalength = txtlength + 1;
  txt.datalen[0] = datalength/256;
  txt.datalen[1] = datalength%256;

  /* copy data to txt section */
  count = 0;
  memcpy(txt_section + count, txt.name, strlen(txt.name));
  count = count + strlen(txt.name);
  memset(txt_section + count, 0, 1);
  count += 1;
  memcpy(txt_section + count, txt.type, 2);
  count += 2;
  memcpy(txt_section + count, txt.clas, 2);
  count += 2;
  memcpy(txt_section + count, txt.ttl, 4);
  count += 4;
  memcpy(txt_section + count, txt.datalen, 2);
  count += 2;
  memcpy(txt_section + count, txt.txtlen, 1);
  count += 1;
  memcpy(txt_section + count, txt.txt, txtlength);
  count += txtlength;
  txt_len[*txt_count] = count;
}

void aaaa(char* domain_name, char* query_class, char* zoneline, char* aaaa_section, char* aaaa_section_name, int* aaaa_len, int* aaaa_count) {
  char* token3;
  char* token4;
  char* token5;
  char domain_name_revised[MAXLINE];
  int count, cnt, name_cnt;
  struct aaaastruct {
    char name[MAXLINE];
    char type[3];
    char clas[3];
    char ttl[5];
    char datalen[3];
    char address[17];
  } aaaa;
  memset(&aaaa, 0, sizeof(aaaa));
  // save name to aaaa_section _name (ex: @, dns, www...)
  token3 = strtok(zoneline, ",");
  memcpy(aaaa_section_name, token3, strlen(token3));
    // name
  memset(domain_name_revised, 0, MAXLINE);
  memset(domain_name_revised, '.', 1);
  memcpy(domain_name_revised+1, domain_name, strlen(domain_name));
  name_cnt = 0;
  for(int i=1; i<strlen(domain_name_revised); i++) {
    if(i+1 == strlen(domain_name_revised)) {
      domain_name_revised[i-name_cnt-1] = name_cnt;
      memset(domain_name_revised+i, 0, 1);
    } else {
      if(domain_name_revised[i] != '.') {
      name_cnt++;
      } else {
        domain_name_revised[i-name_cnt-1] = name_cnt;
        name_cnt = 0;
      }
    }
  }

  if(memcmp(token3, "@", 1) ==0) {
    memcpy(aaaa.name, domain_name_revised, strlen(domain_name_revised));
  } else {
    memset(aaaa.name, strlen(aaaa_section_name), 1);
    memcpy(aaaa.name+1, aaaa_section_name, strlen(aaaa_section_name));
    memcpy(aaaa.name+1+strlen(aaaa_section_name), domain_name_revised, strlen(domain_name_revised));
  }
  // type
  aaaa.type[1] = 28;
  // class
  memcpy(aaaa.clas, query_class, sizeof(query_class));
  // ttl
  token3 = strtok(NULL, ",");
  aaaa.ttl[0] = atoi(token3)/pow(256, 3);
  aaaa.ttl[1] = atoi(token3)/pow(256, 2);
  aaaa.ttl[2] = atoi(token3)/pow(256, 1);
  aaaa.ttl[3] = atoi(token3)%256;
  // address
  token3 = strtok(NULL, ",");
  token3 = strtok(NULL, ",");
  token3 = strtok(NULL, ",");
  token4 = strtok(token3, "\r\n");
  int colonnum = 0;
  int allzero = -1;
  for(int i=0; i<strlen(token4); i++) {
    if(token4[i] == ':') {
      colonnum++;
    }
    if(token4[i] == ':' && token4[i+1] == ':') {
      allzero = i+1;
    }
  }
  char fulladdress[MAXLINE];
  memset(fulladdress, 0, MAXLINE);
  if(allzero == -1) {
    memcpy(fulladdress, token4, strlen(token4));
  } else {
    if(allzero == 1) {
      count = 0;
      for(int i=0; i<8-colonnum+1; i++) {
        memcpy(fulladdress + count, "0000:", 5);
        count += 5;
      }
      memcpy(fulladdress + count, token4 + allzero + 1, strlen(token4) - allzero -1);
    } else if(allzero == strlen(token4)-1){
      count = 0;
      memcpy(fulladdress, token4, allzero-1);
      count += allzero-1;
      for(int i=0; i<8-colonnum+1; i++) {
        memcpy(fulladdress + count, ":0000", 5);
        count += 5;
      }
    } else {
      count = 0;
      memcpy(fulladdress, token4, allzero-1);
      count += allzero-1;
      for(int i=0; i<8-colonnum; i++) {
        memcpy(fulladdress + count, ":0000", 5);
        count += 5;
      }
      memcpy(fulladdress + count, token4 + allzero, strlen(token4) - allzero);
    }
  }
  char subaddr[5];
  char subaddr1[3];
  char subaddr2[3];
  int val;
  token5 = strtok(fulladdress, ":");
  for(int i=0; i<8; i++) {
    memset(subaddr, 0, 5);
    memset(subaddr1, 0, 3);
    memset(subaddr2, 0, 3);
    if(strlen(token5) != 4) {
      count = 0;
      for(int j=0; j<4-strlen(token5); j++) {
        memcpy(subaddr + count, "0", 1);
        count++;
      }
      memcpy(subaddr + count, token5, strlen(token5));
    } else {
      memcpy(subaddr, token5, 4);
    }
    memcpy(subaddr1, subaddr, 2);
    memcpy(subaddr2, subaddr+2, 2);
    token5 = strtok(NULL, ":");
    aaaa.address[2*i] = strtol(subaddr1, NULL, 16);
    aaaa.address[2*i+1] = strtol(subaddr2, NULL, 16);
  }
  // datalen
  aaaa.datalen[1] = 16;

  // copy data to a_section
  count = 0;
  memcpy(aaaa_section + count, aaaa.name, strlen(aaaa.name));
  count = count + strlen(aaaa.name);
  memset(aaaa_section + count, 0, 1);
  count += 1;
  memcpy(aaaa_section + count, aaaa.type, 2);
  count += 2;
  memcpy(aaaa_section + count, aaaa.clas, 2);
  count += 2;
  memcpy(aaaa_section + count, aaaa.ttl, 4);
  count += 4;
  memcpy(aaaa_section + count, aaaa.datalen, 2);
  count += 2;
  memcpy(aaaa_section + count, aaaa.address, 16);
  count += 16;
  aaaa_len[*aaaa_count] = count;
}


void interactwithclient(int sockfd, sockaddr* pcliaddr, socklen_t clilen, char** argv) {
  int rcvlen;
  socklen_t len;
  char recvline[MAXLINE]; // for recv message from dig client
  char sendline[MAXLINE];
  FILE *configfile, *zonefile;
  char line[MAXLINE]; // for fgets config line
  char zoneline[MAXLINE], zoneline2[MAXLINE]; // for fgets zonefile line 
  char foreigndns[MAXLINE]; // for storing foreign dns data
  char* token; // for strtok (line)
  char* token2; // for strtok (zoneline)
  int local_flag;
  char zonelineentrytype[MAXLINE];
  char domain[MAXLINE];
  char domain_name[MAXLINE];
  char zonefilename[MAXLINE];

  while(1) {
    /* dns resolve */
    memset(recvline, 0, MAXLINE);
    len = clilen;
    if((rcvlen = recvfrom(sockfd, recvline, sizeof(recvline), 0, pcliaddr, &len)) < 0) {
      perror("recvfrom");
      exit(1);
    }
    char header[13];
    char query_section[MAXLINE];
    int query_len;
    char query_name[MAXLINE];
    char query_name2[MAXLINE];
    char query_type[3];
    char query_class[3];
    char additional[MAXLINE];
    int additional_len;
    char soa_section[MAXLINE];
    int soa_len = 0;
    char ns_section[TYPEMAX][MAXLINE];
    char ns_section_name[TYPEMAX][MAXLINE];
    int ns_len[TYPEMAX];
    int ns_count = 0;
    char mx_section[TYPEMAX][MAXLINE];
    char mx_section_name[TYPEMAX][MAXLINE];
    int mx_len[TYPEMAX];
    int mx_count = 0;
    char a_section[TYPEMAX][MAXLINE];
    char a_section_name[TYPEMAX][MAXLINE];
    int a_len[TYPEMAX];
    int a_count = 0;
    char cname_section[TYPEMAX][MAXLINE];
    char cname_section_name[TYPEMAX][MAXLINE];
    int cname_len[TYPEMAX];
    int cname_count = 0;
    char txt_section[TYPEMAX][MAXLINE];
    char txt_section_name[TYPEMAX][MAXLINE];
    int txt_len[TYPEMAX];
    int txt_count = 0;
    char aaaa_section[TYPEMAX][MAXLINE];
    char aaaa_section_name[TYPEMAX][MAXLINE];
    int aaaa_len[TYPEMAX];
    int aaaa_count = 0;
    memset(header, 0, 13);
    memset(query_section, 0, MAXLINE);
    memset(query_name, 0, MAXLINE);
    memset(query_name2, 0, MAXLINE); // for matching zonefile's name
    memset(query_type, 0, sizeof(query_type));
    memset(query_class, 0, sizeof(query_class));
    memset(additional, 0, MAXLINE);
    memset(ns_len, 0, sizeof(ns_len)/sizeof(ns_len[0]));
    memset(mx_len, 0, sizeof(mx_len)/sizeof(mx_len[0]));
    memset(a_len, 0, sizeof(a_len)/sizeof(a_len[0]));
    memset(cname_len, 0, sizeof(cname_len)/sizeof(cname_len[0]));
    memset(txt_len, 0, sizeof(txt_len)/sizeof(txt_len[0]));
    memset(aaaa_len, 0, sizeof(aaaa_len)/sizeof(aaaa_len[0]));
    memcpy(header, recvline, 12);
    int pointer=12;
    for(int i=pointer; i<MAXLINE; i++) {
      if(recvline[i] == '\0') {
        pointer = i;
        break;
      }
    }
    /* save query section */
    memcpy(query_section, recvline+12, pointer+1-12+4);
    query_len = pointer+1-12+4;
    // save query_name
    memcpy(query_name, recvline+12, pointer+1-12);
    memcpy(query_name2, recvline+12, pointer+1-12);
    // convert query_name2 (->.)
    int start = 0;
    while (start < strlen(query_name)) {
      start = start + query_name[start] + 1;
      query_name2[start] = '.';
    }
    // save query_type
    memcpy(query_type, recvline+pointer+1, 2);
    pointer += 2;
    // save query_class
    memcpy(query_class, recvline+pointer+1, 2);
    pointer += 2;

    /* save additional section */
    memcpy(additional, recvline+pointer+1, MAXLINE-pointer-1);
    for(int i=0; i<MAXLINE; i++) {
      int flag = 0;
      for(int j=0; j<50; j++) {
        if(additional[i+j] != 0) {
          flag = 1;
        }
      }
      if(flag == 0) {
        additional_len = i;
        break;
      }
    }

    /* save local config */ 
    local_flag = 0;
    configfile = fopen(argv[2], "r");
    if(configfile == NULL) {
      printf("open config error\n");
      exit(1);
    }
    // get foreign dns
    fgets(line, MAXLINE, configfile);
    token = strtok(line, "\r\n");
    memset(foreigndns, 0, sizeof(foreigndns));
    memcpy(foreigndns, token, strlen(token));
    // get zonefile name
    memset(line, 0, MAXLINE);
    memset(domain, 0, MAXLINE);
    memset(domain_name, 0, MAXLINE);
    memset(zonefilename, 0, MAXLINE);
    while(fgets(line, MAXLINE, configfile)) {
      token = strtok(line, ",\r\n");
      memcpy(domain_name, token, strlen(token));
      if(memcmp(query_name2+1, token, strlen(token)) == 0) { // matching domain @
        local_flag = 1; // local dns resolved;
        memcpy(domain, "@", 1); // domain level: @
        token = strtok(NULL, ",\r\n");
        memcpy(zonefilename, token, strlen(token));
        break;
      }
      if(memcmp(query_name2+(strlen(query_name2)-strlen(token)), token, strlen(token)) == 0 ) { // matching domain dns, www, etc..
        local_flag = 1; // local dns resolved;
        memcpy(domain, query_name2+1, strlen(query_name2)-strlen(token)-2); // domain level: dns, www, etc..
        token = strtok(NULL, ",\r\n");
        memcpy(zonefilename, token, strlen(token));
        break;
      }
      memset(line, 0, MAXLINE);
    }
    fclose(configfile);

    /* local resolve start */
    if(local_flag == 1) {
      /* save zonefile entries */ 
      zonefile = fopen(zonefilename, "r");
      if(zonefile == NULL) {
        printf("open zonefile error\n");
        exit(1);
      }
      memset(zoneline, 0, MAXLINE);
      memset(zoneline2, 0, MAXLINE);
      int count = 0;
      while(fgets(zoneline, MAXLINE, zonefile)) {
        memcpy(zoneline2, zoneline, MAXLINE);
        if(count >0) {
          token2 = strtok(zoneline2, ",");
          token2 = strtok(NULL, ",");
          token2 = strtok(NULL, ",");
          token2 = strtok(NULL, ",");
          // save SOA entry
          if(memcmp(token2, "SOA", 3) == 0) {
            memset(soa_section, 0, MAXLINE);
            soa(domain_name, query_class, zoneline, soa_section, &soa_len);
            // printf("%d\n", soa_len);
          } else if(memcmp(token2, "NS", 2) == 0) {
            memset(ns_section[ns_count], 0, MAXLINE);
            memset(ns_section_name[ns_count], 0, MAXLINE);
            ns(domain_name, query_class, zoneline, ns_section[ns_count], ns_section_name[ns_count], ns_len, &ns_count);
            ns_count++;
          } else if(memcmp(token2, "MX", 2) == 0) {
            memset(mx_section[mx_count], 0, MAXLINE);
            memset(mx_section_name[mx_count], 0, MAXLINE);
            mx(domain_name, query_class, zoneline, mx_section[mx_count], mx_section_name[mx_count], mx_len, &mx_count);
            mx_count++;
          } else if(memcmp(token2, "A", 1) == 0 && (strlen(token2) == 1)) {
            memset(a_section[a_count], 0, MAXLINE);
            memset(a_section_name[a_count], 0, MAXLINE);
            a(domain_name, query_class, zoneline, a_section[a_count], a_section_name[a_count], a_len, &a_count);
            a_count++;
          } else if(memcmp(token2, "CNAME", 5) == 0) {
            memset(cname_section[cname_count], 0, MAXLINE);
            memset(cname_section_name[cname_count], 0, MAXLINE);
            cname(domain_name, query_class, zoneline, cname_section[cname_count], cname_section_name[cname_count], cname_len, &cname_count);
            cname_count++;
          } else if(memcmp(token2, "TXT", 3) == 0) {
            memset(txt_section[txt_count], 0, MAXLINE);
            memset(txt_section_name[txt_count], 0, MAXLINE);
            txt(domain_name, query_class, zoneline, txt_section[txt_count], txt_section_name[txt_count], txt_len, &txt_count);
            txt_count++;
          } else if(memcmp(token2, "AAAA", 4) == 0) {
            memset(aaaa_section[aaaa_count], 0, MAXLINE);
            memset(aaaa_section_name[aaaa_count], 0, MAXLINE);
            aaaa(domain_name, query_class, zoneline, aaaa_section[aaaa_count], aaaa_section_name[aaaa_count], aaaa_len, &aaaa_count);
            aaaa_count++;
          }
        }
        memset(zoneline, 0, MAXLINE);
        count++;
      }
      fclose(zonefile);

      /* send to client!!!! */
      int additional_no = 1;
      memset(sendline, 0, MAXLINE);
      count = 0;
      if(16*query_type[0] + query_type[1] == 6) { // SOA
        /* header section */
        header[2] |= 1 << 7; // set QR to 1
        header[2] |= 1 << 2; // set AA to 1
        header[3] &= 0;
        header[7] = 1; // set Answer to 1
        header[8] = ns_count/256; // set Authority to ns_count
        header[9] = ns_count%256;
        for(int i=0; i<a_count; i++) { // set additional no
          if(memcmp(a_section_name[i], "@", 1) == 0) {
            additional_no++;
          }
        }
        for(int i=0; i<aaaa_count; i++) { // set additional no
          if(memcmp(aaaa_section_name[i], "@", 1) == 0) {
            additional_no++;
          }
        }
        header[10] = additional_no/256;
        header[11] = additional_no%256;
        // fill up sendline
        memcpy(sendline+count, header, 12);
        count += 12;
        memcpy(sendline+count, query_section, query_len);
        count += query_len;
        memcpy(sendline+count, soa_section, soa_len);
        count += soa_len;
        for(int i=0; i<ns_count; i++) {
          memcpy(sendline+count, ns_section[i], ns_len[i]);
          count += ns_len[i];
        }
        // additional (a rr)
        for(int i=0; i<a_count; i++) {
          if(memcmp(a_section_name[i], "@", 1) == 0) {
            memcpy(sendline+count, a_section[i], a_len[i]);
            count += a_len[i];
          }
        }
        // additional (aaaa rr)
        for(int i=0; i<aaaa_count; i++) {
          if(memcmp(aaaa_section_name[i], "@", 1) == 0) {
            memcpy(sendline+count, aaaa_section[i], aaaa_len[i]);
            count += aaaa_len[i];
          }
        }
        memcpy(sendline+count, additional, additional_len);
        count += additional_len;
        // send
        sendto(sockfd, sendline, count, 0, pcliaddr, len);
      } else if(16*query_type[0] + query_type[1] == 2) { // NS
        /* header section */
        header[2] |= 1 << 7; // set QR to 1
        header[2] |= 1 << 2; // set AA to 1
        header[3] &= 0;
        int ns_answer = 0;
        for(int i=0 ;i<ns_count; i++) {
          if(memcmp(ns_section_name[i], domain, strlen(domain)) == 0) {
            ns_answer++;
          }
        }
        header[6] = ns_answer/256;
        header[7] = ns_answer%256;
        if(ns_answer == 0) {
          header[9] = 1; // if no answer found, set authority to soa
        }
        for(int i=0; i<a_count; i++) { // set additional no
          if(memcmp(a_section_name[i], "dns", 3) == 0) {
            additional_no++;
          }
        }
        for(int i=0; i<aaaa_count; i++) { // set additional no
          if(memcmp(aaaa_section_name[i], "dns", 3) == 0) {
            additional_no++;
          }
        }
        header[10] = additional_no/256;
        header[11] = additional_no%256;
        // fill up sendline
        memcpy(sendline+count, header, 12);
        count += 12;
        memcpy(sendline+count, query_section, query_len);
        count += query_len;
        for(int i=0; i<ns_count; i++) {
          if(memcmp(ns_section_name[i], domain, strlen(domain)) == 0) {
            memcpy(sendline+count, ns_section[i], ns_len[i]);
            count += ns_len[i];
          }
        }
        if(ns_answer == 0) {
          memcpy(sendline+count, soa_section, soa_len);
          count += soa_len;
        }
        // additional (a rr)
        for(int i=0; i<a_count; i++) {
          if(memcmp(a_section_name[i], "dns", 3) == 0) {
            memcpy(sendline+count, a_section[i], a_len[i]);
            count += a_len[i];
          }
        }
        // additional (aaaa rr)
        for(int i=0; i<aaaa_count; i++) {
          if(memcmp(aaaa_section_name[i], "dns", 3) == 0) {
            memcpy(sendline+count, aaaa_section[i], aaaa_len[i]);
            count += aaaa_len[i];
          }
        }
        memcpy(sendline+count, additional, additional_len);
        count += additional_len;
        // send
        sendto(sockfd, sendline, count, 0, pcliaddr, len);
      } else if(16*query_type[0] + query_type[1] == 15) { // MX
        /* header section */
        header[2] |= 1 << 7; // set QR to 1
        header[2] |= 1 << 2; // set AA to 1
        header[3] &= 0;
        int mx_answer = 0;
        for(int i=0 ;i<mx_count; i++) {
          if(memcmp(mx_section_name[i], domain, strlen(domain)) == 0) {
            mx_answer++;
          }
        }
        header[7] = mx_answer; // set Answer to mx_answer
        if(mx_answer == 0) { // set Authority number
          header[9] = 1;
        } else {
          header[8] = ns_count/256;
          header[9] = ns_count%256;
        }
        for(int i=0; i<a_count; i++) { // set additional no
          if(memcmp(a_section_name[i], "mail", 4) == 0) {
            additional_no++;
          }
        }
        for(int i=0; i<aaaa_count; i++) { // set additional no
          if(memcmp(aaaa_section_name[i], "mail", 4) == 0) {
            additional_no++;
          }
        }
        header[10] = additional_no/256;
        header[11] = additional_no%256;
        // fill up sendline
        memcpy(sendline+count, header, 12);
        count += 12;
        memcpy(sendline+count, query_section, query_len);
        count += query_len;
        // answer
        for(int i=0; i<mx_count; i++) {
          if(memcmp(mx_section_name[i], domain, strlen(domain)) == 0) {
            memcpy(sendline+count, mx_section[i], mx_len[i]);
            count += mx_len[i];
          }
        }
        // authority
        if(mx_answer == 0) { // no mx rr found (authority return soa)
          memcpy(sendline+count, soa_section, soa_len);
          count += soa_len;
        } else {
          for(int i=0; i<ns_count; i++) {
            memcpy(sendline+count, ns_section[i], ns_len[i]);
            count += ns_len[i];
          }
        }
        // additional
        // additional (a rr)
        for(int i=0; i<a_count; i++) {
          if(memcmp(a_section_name[i], "mail", 4) == 0) {
            memcpy(sendline+count, a_section[i], a_len[i]);
            count += a_len[i];
          }
        }
        // additional (aaaa rr)
        for(int i=0; i<aaaa_count; i++) {
          if(memcmp(aaaa_section_name[i], "mail", 4) == 0) {
            memcpy(sendline+count, aaaa_section[i], aaaa_len[i]);
            count += aaaa_len[i];
          }
        }
        memcpy(sendline+count, additional, additional_len);
        count += additional_len;
        // send
        sendto(sockfd, sendline, count, 0, pcliaddr, len);
      } else if(16*query_type[0] + query_type[1] == 1) { // A
        /* header section */
        header[2] |= 1 << 7; // set QR to 1
        header[2] |= 1 << 2; // set AA to 1
        header[3] &= 0;
        int a_answer = 0;
        for(int i=0 ;i<a_count; i++) {
          if(memcmp(a_section_name[i], domain, strlen(domain)) == 0) {
            a_answer++;
          }
        }
        header[7] = a_answer; // set Answer to a_answer
        if(a_answer == 0) { // set Authority number
          header[9] = 1;
        } else {
          header[8] = ns_count/256;
          header[9] = ns_count%256;
        }
        // fill up sendline
        memcpy(sendline+count, header, 12);
        count += 12;
        memcpy(sendline+count, query_section, query_len);
        count += query_len;
        // answer
        for(int i=0; i<a_count; i++) {
          if(memcmp(a_section_name[i], domain, strlen(domain)) == 0) {
            memcpy(sendline+count, a_section[i], a_len[i]);
            count += a_len[i];
          }
        }
        // authority
        if(a_answer == 0) { // no a rr found (authority return soa)
          memcpy(sendline+count, soa_section, soa_len);
          count += soa_len;
        } else {
          for(int i=0; i<ns_count; i++) {
            memcpy(sendline+count, ns_section[i], ns_len[i]);
            count += ns_len[i];
          }
        }
        // additional
        memcpy(sendline+count, additional, additional_len);
        count += additional_len;
        // send
        sendto(sockfd, sendline, count, 0, pcliaddr, len);
      } else if(16*query_type[0] + query_type[1] == 5) { // cname
        /* header section */
        header[2] |= 1 << 7; // set QR to 1
        header[2] |= 1 << 2; // set AA to 1
        header[3] &= 0;
        int cname_answer = 0;
        for(int i=0 ;i<cname_count; i++) {
          if(memcmp(cname_section_name[i], domain, strlen(domain)) == 0) {
            cname_answer++;
          }
        }
        header[7] = cname_answer; // set Answer to txt_answer
        if(cname_answer == 0) { // set Authority number
          header[9] = 1;
        } else {
          header[8] = ns_count/256;
          header[9] = ns_count%256;
        }
        // fill up sendline
        memcpy(sendline+count, header, 12);
        count += 12;
        memcpy(sendline+count, query_section, query_len);
        count += query_len;
        // answer
        for(int i=0; i<cname_count; i++) {
          if(memcmp(cname_section_name[i], domain, strlen(domain)) == 0) {
            memcpy(sendline+count, cname_section[i], cname_len[i]);
            count += cname_len[i];
          }
        }
        // authority
        if(cname_answer == 0) { // no cname rr found (authority return soa)
          memcpy(sendline+count, soa_section, soa_len);
          count += soa_len;
        } else {
          for(int i=0; i<ns_count; i++) {
            memcpy(sendline+count, ns_section[i], ns_len[i]);
            count += ns_len[i];
          }
        }
        // additional
        memcpy(sendline+count, additional, additional_len);
        count += additional_len;
        // send
        sendto(sockfd, sendline, count, 0, pcliaddr, len);
      } else if(16*query_type[0] + query_type[1] == 16) { // txt
        /* header section */
        header[2] |= 1 << 7; // set QR to 1
        header[2] |= 1 << 2; // set AA to 1
        header[3] &= 0;
        int txt_answer = 0;
        for(int i=0 ;i<txt_count; i++) {
          if(memcmp(txt_section_name[i], domain, strlen(domain)) == 0) {
            txt_answer++;
          }
        }
        header[7] = txt_answer; // set Answer to txt_answer
        if(txt_answer == 0) { // set Authority number
          header[9] = 1;
        } else {
          header[8] = ns_count/256;
          header[9] = ns_count%256;
        }
        // fill up sendline
        memcpy(sendline+count, header, 12);
        count += 12;
        memcpy(sendline+count, query_section, query_len);
        count += query_len;
        // answer
        for(int i=0; i<txt_count; i++) {
          if(memcmp(txt_section_name[i], domain, strlen(domain)) == 0) {
            memcpy(sendline+count, txt_section[i], txt_len[i]);
            count += txt_len[i];
          }
        }
        // authority
        if(txt_answer == 0) { // no cname rr found (authority return soa)
          memcpy(sendline+count, soa_section, soa_len);
          count += soa_len;
        } else {
          for(int i=0; i<ns_count; i++) {
            memcpy(sendline+count, ns_section[i], ns_len[i]);
            count += ns_len[i];
          }
        }
        // additional
        memcpy(sendline+count, additional, additional_len);
        count += additional_len;
        // send
        sendto(sockfd, sendline, count, 0, pcliaddr, len);
      } else if(16*query_type[0] + query_type[1] == 28) { // aaaa
        /* header section */
        header[2] |= 1 << 7; // set QR to 1
        header[2] |= 1 << 2; // set AA to 1
        header[3] &= 0;
        int aaaa_answer = 0;
        for(int i=0 ;i<aaaa_count; i++) {
          if(memcmp(aaaa_section_name[i], domain, strlen(domain)) == 0) {
            aaaa_answer++;
          }
        }
        header[7] = aaaa_answer; // set Answer to aaaa_answer
        if(aaaa_answer == 0) { // set Authority number
          header[9] = 1;
        } else {
          header[8] = ns_count/256;
          header[9] = ns_count%256;
        }
        // fill up sendline
        memcpy(sendline+count, header, 12);
        count += 12;
        memcpy(sendline+count, query_section, query_len);
        count += query_len;
        // answer
        for(int i=0; i<aaaa_count; i++) {
          if(memcmp(aaaa_section_name[i], domain, strlen(domain)) == 0) {
            memcpy(sendline+count, aaaa_section[i], aaaa_len[i]);
            count += aaaa_len[i];
          }
        }
        // authority
        if(aaaa_answer == 0) { // no a rr found (authority return soa)
          memcpy(sendline+count, soa_section, soa_len);
          count += soa_len;
        } else {
          for(int i=0; i<ns_count; i++) {
            memcpy(sendline+count, ns_section[i], ns_len[i]);
            count += ns_len[i];
          }
        }
        // additional
        memcpy(sendline+count, additional, additional_len);
        count += additional_len;
        // send
        sendto(sockfd, sendline, count, 0, pcliaddr, len);
      }
      /*foreign query */
    } else { 
      char sendforeign[MAXLINE];
      char recvforeign[MAXLINE];
      int dnsfd;
      int recvforeignlen;
      struct sockaddr_in dnsaddr;
      memset(&dnsaddr, 0, sizeof(dnsaddr));
      dnsaddr.sin_family = AF_INET;
      dnsaddr.sin_port = htons(53);
      inet_pton(AF_INET, foreigndns, &dnsaddr.sin_addr);
      if((dnsfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        err_quit("socket");
      }
      memset(sendforeign, 0, MAXLINE);
      memset(recvforeign, 0, MAXLINE);
      memcpy(sendforeign, header, 12);
      memcpy(sendforeign+12, query_section, query_len);
      memcpy(sendforeign+12+query_len, additional, additional_len);
      sendto(dnsfd, sendforeign, 12+query_len+additional_len, 0, (sockaddr*) &dnsaddr, sizeof(dnsaddr));
      recvforeignlen = recvfrom(dnsfd, recvforeign, MAXLINE, 0, NULL, NULL);
      sendto(sockfd, recvforeign, recvforeignlen, 0, pcliaddr, len);
      close(dnsfd);
    }
  }
}


int main(int argc, char* argv[]) {
  if(argc != 3) {
    printf("usage: ./dns <port> <config file path>\n");
    exit(1);
  }
  int sockfd;
  struct sockaddr_in servaddr, cliaddr;

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(atoi(argv[1]));
  if((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    err_quit("socket");
  }
  if(bind(sockfd, (sockaddr*) &servaddr, sizeof(servaddr)) < 0) {
    err_quit("bind");
  }
  interactwithclient(sockfd, (struct sockaddr*) &cliaddr, sizeof(cliaddr), argv);
  close(sockfd);

  return 0;
}