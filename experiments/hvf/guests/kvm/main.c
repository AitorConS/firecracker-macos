// SPDX-License-Identifier: Apache-2.0
// Small generic Linux/KVM smoke guest; built statically with host GCC.
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <unistd.h>
static int count;
static int listener(int port,int type){int fd=socket(AF_INET,type,0);assert(fd>=0);int one=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(port),.sin_addr.s_addr=INADDR_ANY};assert(bind(fd,(void*)&a,sizeof(a))==0);return fd;}
static void all(int fd,const void *buffer,size_t len){const char *p=buffer;while(len){ssize_t n=write(fd,p,len);assert(n>0);p+=n;len-=n;}}
static void *udp(void *unused){(void)unused;int fd=listener(9001,SOCK_DGRAM);for(;;){char b[2048];struct sockaddr_in a;socklen_t size=sizeof(a);ssize_t n=recvfrom(fd,b,sizeof(b),0,(void*)&a,&size);assert(n>=0);assert(sendto(fd,b,n,0,(void*)&a,size)==n);}return NULL;}
int main(void){
 int disk=open("/dev/vda",O_RDWR);assert(disk>=0);char b[512]={0};assert(pread(disk,b,512,0)==512);assert(!memcmp(b,"HVF_GENERIC_BLOCK_V1",20));assert(pread(disk,b,512,512)==512);b[511]=0;count=atoi(b)+1;memset(b,0,sizeof(b));snprintf(b,sizeof(b),"%d",count);assert(pwrite(disk,b,512,512)==512);assert(fsync(disk)==0);close(disk);
 pthread_t thread;assert(pthread_create(&thread,NULL,udp,NULL)==0);int server=listener(9000,SOCK_STREAM);assert(listen(server,16)==0);puts("LINUX_GENERIC_READY");fflush(stdout);
 for(;;){int fd=accept(server,NULL,NULL);assert(fd>=0);char header[8192]={0};size_t used=0;while(used<sizeof(header)-1){assert(read(fd,header+used,1)==1);used++;if(used>=4&&!memcmp(header+used-4,"\r\n\r\n",4))break;}
  int stop=!strncmp(header,"GET /exit ",10);char *body=NULL;size_t len=0;
  if(!strncmp(header,"POST /echo ",11)){char *p=strcasestr(header,"\r\nContent-Length:");assert(p);len=strtoul(p+17,NULL,10);assert(len<=(16<<20));body=malloc(len?len:1);assert(body);size_t got=0;while(got<len){ssize_t n=read(fd,body+got,len-got);assert(n>0);got+=n;}}
  else{body=malloc(256);assert(body);len=snprintf(body,256,stop?"bye":"{\"arch\":\"x86_64\",\"count\":%d,\"cpus\":%ld}\n",count,sysconf(_SC_NPROCESSORS_ONLN));}
  char response[256];int n=snprintf(response,sizeof(response),"HTTP/1.1 200 OK\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",len);all(fd,response,n);all(fd,body,len);free(body);close(fd);
  if(stop){sync();usleep(100000);puts("GUEST_SYNCED_EXIT_I8042");fflush(stdout);reboot(RB_AUTOBOOT);abort();}
 }
}
