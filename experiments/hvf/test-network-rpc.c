// SPDX-License-Identifier: Apache-2.0
// Deterministic transport failures around the real socket gate RPC.
#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
static int inject_timeout,inject_ack,inject_eintr,received_fd=-1;
static ssize_t test_send(int fd,const void *b,size_t n,int flags){uint32_t op=0;if(n>=8)memcpy(&op,(const char *)b+4,4);if(inject_ack&&op==6){errno=EAGAIN;return -1;}return send(fd,b,n,flags);}
static int test_poll(struct pollfd *p,nfds_t n,int ms){if(inject_timeout){usleep(10000);return 0;}if(inject_eintr-->0){errno=EINTR;return -1;}return poll(p,n,ms);}
static ssize_t test_recvmsg(int fd,struct msghdr *m,int flags){ssize_t n=recvmsg(fd,m,flags);for(struct cmsghdr *c=CMSG_FIRSTHDR(m);c;c=CMSG_NXTHDR(m,c))if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_RIGHTS)memcpy(&received_fd,CMSG_DATA(c),sizeof(received_fd));return n;}
#define send test_send
#define poll test_poll
#define recvmsg test_recvmsg
#include GATE_SOURCE
#undef send
#undef poll
#undef recvmsg
#include <assert.h>
int main(int argc,char **argv){
 assert(argc==2);const char *scenario=argv[1];
 if(!strcmp(scenario,"authority")){
  int q[2];assert(!socketpair(AF_UNIX,SOCK_DGRAM,0,q));held=q[0];held_id=10;uint32_t token=0;
  struct request req={.magic=MAGIC,.op=3,.id=11};int pass=handle(-1,&req,&token)==-1&&held==q[0]&&fcntl(held,F_GETFD)>=0;
  req.op=6;pass &= handle(-1,&req,&token)==-1&&held==q[0];req.id=10;pass &= handle(-1,&req,&token)==0&&held==-1;
  close(q[1]);printf("RESULT scenario=authority passed=%d\n",pass);return pass?0:1;
 }
 int p[2];assert(!socketpair(AF_UNIX,SOCK_DGRAM,0,p));pid_t child=fork();assert(child>=0);
 if(!child){close(p[0]);struct request req;assert(recv(p[1],&req,sizeof(req),0)==sizeof(req));int q[2];assert(!socketpair(AF_UNIX,SOCK_DGRAM,0,q));struct reply r={.magic=MAGIC,.id=req.id};if(!strcmp(scenario,"malformed"))r.id++;assert(!send_reply(p[1],&r,q[0]));usleep(1000000);_exit(0);}
 close(p[1]);channel=p[0];inject_timeout=!strcmp(scenario,"timeout");inject_ack=!strcmp(scenario,"ack");inject_eintr=!strcmp(scenario,"eintr")?3:0;
 struct reply r;int descriptor;int rc=rpc(3,0,NULL,&r,&descriptor);int error=errno;
 int fail_expected=strcmp(scenario,"eintr")!=0;
 int pass=fail_expected?(rc==-1&&gate_failed&&descriptor==-1):(rc==0&&!gate_failed&&descriptor>=0);
 if(inject_ack&&received_fd>=0)pass &= fcntl(received_fd,F_GETFD)<0&&errno==EBADF;
 if(fail_expected){inject_timeout=0;inject_ack=0;int extra;pass &= rpc(3,0,NULL,&r,&extra)==-1&&errno==ENOTCONN&&extra==-1;pass &= hvf_gate_check()==-1;}
 if(descriptor>=0)close(descriptor);kill(child,SIGKILL);waitpid(child,NULL,0);close(channel);
 printf("RESULT scenario=%s rc=%d error=%d fatal=%d passed=%d\n",scenario,rc,error,gate_failed,pass);return pass?0:1;
}
