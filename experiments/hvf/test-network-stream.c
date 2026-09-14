// SPDX-License-Identifier: Apache-2.0
#include <assert.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include "net_backend_stream.h"
static unsigned received;
static ssize_t deliver(const void *data,size_t size,void *unused){
    (void)unused;assert(size==14 || size==STREAM_FRAME);assert(((const uint8_t*)data)[0]==42);received++;return size;
}
static int pair(void){
    int fds[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,fds)==0);
    assert(fcntl(fds[0],F_SETFL,O_NONBLOCK)==0);
    stream.fd=fds[0];stream.receive=deliver;stream.used=0;stream.need=4;stream.connecting=0;
    return fds[1];
}
int main(void){
    int peer=pair();uint8_t frame[18]={0,0,0,14,42};
    for(unsigned i=0;i<18;i++){assert(write(peer,frame+i,1)==1);stream_poll();assert(received==(i==17));}
    assert(write(peer,frame,18)==18);assert(write(peer,frame,18)==18);stream_poll();assert(received==3);
    for(unsigned i=0;i<300;i++)stream_send(frame+4,14);
    uint8_t data[8192];ssize_t n=read(peer,data,sizeof(data));assert(n>0 && n%18==0);
    for(ssize_t i=0;i<n;i+=18)assert(!memcmp(data+i,frame,18));
    close(peer);stream_poll();assert(stream.fd==-1 && stream.used==0 && stream.queued==0);
    const uint32_t invalid[]={0,1,13,65537,0xffffffff};
    for(unsigned j=0;j<sizeof(invalid)/sizeof(*invalid);j++){
        peer=pair();uint8_t h[4];for(unsigned i=0;i<4;i++)h[i]=(uint8_t)(invalid[j]>>(24-8*i));
        assert(write(peer,h,4)==4);stream_poll();assert(stream.fd==-1);close(peer);
    }
    peer=pair();uint8_t *large=calloc(1,STREAM_FRAME+4);assert(large);large[1]=1;large[4]=42;
    for(unsigned offset=0;offset<STREAM_FRAME+4;){unsigned size=STREAM_FRAME+4-offset;if(size>1024)size=1024;assert(write(peer,large+offset,size)==size);offset+=size;stream_poll();}assert(received==4);free(large);close(peer);stream_disconnect();
    peer=pair();assert(write(peer,frame,2)==2);stream_poll();assert(stream.used==2);close(peer);stream_poll();assert(stream.used==0);
    // Force partial writes and a full queue; the next frame must be dropped
    // whole while the outstanding length-prefixed frame remains intact.
    peer=pair();int buffer=1024;assert(!setsockopt(stream.fd,SOL_SOCKET,SO_SNDBUF,&buffer,sizeof(buffer)));
    assert(!fcntl(peer,F_SETFL,O_NONBLOCK));large=calloc(1,STREAM_FRAME);assert(large);large[0]=42;
    stream_send(large,STREAM_FRAME);assert(stream.queued>0);uint64_t drops=stream.drops;
    stream_send(frame+4,14);assert(stream.drops==drops+1);
    uint8_t *wire=malloc(STREAM_FRAME+4);assert(wire);size_t total=0;
    for(unsigned budget=0;total<STREAM_FRAME+4 && budget<100000;budget++){
        n=read(peer,wire+total,STREAM_FRAME+4-total);if(n>0)total+=(size_t)n;
        else assert(errno==EAGAIN||errno==EWOULDBLOCK);
        stream_flush();
    }
    assert(total==STREAM_FRAME+4);assert(wire[0]==0&&wire[1]==1&&wire[2]==0&&wire[3]==0);assert(!memcmp(wire+4,large,STREAM_FRAME));
    free(wire);free(large);close(peer);stream_disconnect();
    peer=pair();assert(write(peer,frame,1)==1);stream_poll();stream.progress=stream_ms()-5001;stream_poll();assert(stream.fd==-1);close(peer);
    char dir[]="/tmp/hvf-stream-XXXXXX";assert(mkdtemp(dir));char path[104];snprintf(path,sizeof(path),"%s/net",dir);
    int listener=socket(AF_UNIX,SOCK_STREAM,0);assert(listener>=0);struct sockaddr_un addr={.sun_family=AF_UNIX};strlcpy(addr.sun_path,path,sizeof(addr.sun_path));
    assert(bind(listener,(struct sockaddr*)&addr,sizeof(addr))==0);assert(listen(listener,1)==0);
    stream.path=path;stream.retry=0;assert(chmod(path,0666)==0);struct hvf_options options={.stream_path=path};assert(stream_open(&options,deliver)==-1);assert(stream.fd==-1);
    assert(chmod(path,0600)==0);stream.retry=0;stream_connect();assert(stream.fd>=0);peer=accept(listener,NULL,NULL);assert(peer>=0);
    assert(write(peer,frame,18)==18);stream_poll();assert(received==5);close(peer);stream_poll();assert(stream.fd==-1);
    stream.retry=0;stream_connect();assert(stream.fd>=0);peer=accept(listener,NULL,NULL);assert(peer>=0);
    close(peer);close(listener);stream_disconnect();unlink(path);rmdir(dir);
    puts("PASS stream: split/coalesced frames, bounds, EOF reset, TX framing, private sockets and reconnect");
}
