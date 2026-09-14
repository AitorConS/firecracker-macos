// SPDX-License-Identifier: Apache-2.0
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>
#include "seatbelt.h"
int main(void){
 char temp[]="/private/tmp/hvf-stream-policy-XXXXXX";assert(mkdtemp(temp));
 struct sockaddr_un address={.sun_family=AF_UNIX};snprintf(address.sun_path,sizeof(address.sun_path),"%s/link",temp);
 int server=socket(AF_UNIX,SOCK_STREAM,0);assert(server>=0);assert(!bind(server,(void*)&address,sizeof(address)));assert(!listen(server,2));
 struct sockaddr_in internet={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
 int host=socket(AF_INET,SOCK_STREAM,0);assert(!bind(host,(void*)&internet,sizeof(internet)));assert(!listen(host,1));socklen_t length=sizeof(internet);assert(!getsockname(host,(void*)&internet,&length));
 pid_t child=fork();assert(child>=0);
 if(!child){
  close(server);close(host);
  char profile[1024];snprintf(profile,sizeof(profile),"(version 1)(deny default)(allow file-read-metadata (literal \"%s\"))(allow network-outbound (remote unix-socket (path \"%s\")))",address.sun_path,address.sun_path);
  assert(!hvf_sandbox_install(profile));
  int fd=socket(AF_UNIX,SOCK_STREAM,0);assert(fd>=0);assert(!connect(fd,(void*)&address,sizeof(address)));close(fd);
  fd=socket(AF_INET,SOCK_STREAM,0);assert(fd>=0);assert(connect(fd,(void*)&internet,sizeof(internet))<0);assert(errno==EPERM||errno==EACCES);close(fd);
  assert(open("/etc/passwd",O_RDONLY)<0);
  address.sun_path[strlen(address.sun_path)-1]='X';fd=socket(AF_UNIX,SOCK_STREAM,0);assert(connect(fd,(void*)&address,sizeof(address))<0);close(fd);
  _exit(0);
 }
 int status;assert(waitpid(child,&status,0)==child);assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);
 close(server);close(host);unlink(address.sun_path);rmdir(temp);
 puts("PASS Seatbelt stream capability: selected Unix socket allowed; Internet, other path and host file denied");
}
