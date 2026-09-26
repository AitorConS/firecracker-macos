// SPDX-License-Identifier: Apache-2.0
#include <assert.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
static unsigned recv_calls;
static ssize_t counted_recv(int fd,void *buffer,size_t size,int flags);
#define recv counted_recv
#include "net_backend_stream.h"
#undef recv
static ssize_t counted_recv(int fd,void *buffer,size_t size,int flags){
    recv_calls++;return recv(fd,buffer,size,flags);
}
static unsigned received;
static int blocked;
static unsigned block_after;
static uint8_t received_ids[2048];
static const uint8_t *expected_payload;
static size_t expected_size;
static ssize_t deliver(const void *data,size_t size,void *unused){
    (void)unused;assert(size==14 || size==STREAM_FRAME);
    if(blocked || (block_after && received>=block_after)){errno=EAGAIN;return -1;}
    if(expected_payload && size==expected_size)assert(!memcmp(data,expected_payload,size));
    assert(received<sizeof(received_ids));received_ids[received++]=((const uint8_t*)data)[0];return size;
}
static int pair(void){
    int fds[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,fds)==0);
    assert(fcntl(fds[0],F_SETFL,O_NONBLOCK)==0);
    stream.fd=fds[0];stream.receive=deliver;stream.used=0;stream.need=4;stream.rx_start=stream.rx_used=0;stream.connecting=0;stream.paused=0;
    return fds[1];
}
static void write_chunks_poll(int fd,const uint8_t *data,size_t size){
    for(size_t offset=0;offset<size;){size_t chunk=size-offset;if(chunk>4096)chunk=4096;
        assert(write(fd,data+offset,chunk)==(ssize_t)chunk);offset+=chunk;stream_poll();}
}
int main(void){
    int peer=pair();uint8_t frame[18]={0,0,0,14,42};
    for(unsigned i=0;i<18;i++){assert(write(peer,frame+i,1)==1);stream_poll();assert(received==(i==17));}
    assert(write(peer,frame,18)==18);assert(write(peer,frame,18)==18);stream_poll();assert(received==3);
    for(unsigned i=0;i<300;i++)stream_send(frame+4,14);
    uint8_t data[8192];ssize_t n=read(peer,data,sizeof(data));assert(n>0 && n%18==0);
    for(ssize_t i=0;i<n;i+=18)assert(!memcmp(data+i,frame,18));
    close(peer);stream_poll();assert(stream.fd==-1 && stream.used==0 && stream.queued==0);

    // One read can contain many length-prefixed frames. The finite per-poll
    // frame budget leaves remaining data buffered for a poll with no new input.
    peer=pair();uint8_t many[300][18];
    for(unsigned i=0;i<300;i++){memcpy(many[i],frame,18);many[i][4]=(uint8_t)i;}
    unsigned before=received,reads_before=recv_calls;assert(write(peer,many,sizeof(many))==(ssize_t)sizeof(many));stream_poll();
    // The first loop iteration fills the read-ahead buffer; remaining iterations
    // deliver frames, so at most 255 callbacks fit in this poll.
    assert(received==before+255 && stream.rx_used>0);stream_poll();assert(received==before+300 && stream.rx_used==0);
    assert(recv_calls-reads_before<20); /* coalesced frames need far fewer reads than frames */
    printf("READ_AHEAD 300 coalesced frames: %u recv calls\n",recv_calls-reads_before);
    for(unsigned i=0;i<300;i++)assert(received_ids[before+i]==(uint8_t)i);
    close(peer);stream_disconnect();

    // Consume a small frame to leave an offset, then buffer all but the last
    // 16 bytes of a maximum frame. Refill must compact the partial successor;
    // the final callback checks every payload byte after that move.
    peer=pair();uint8_t *large_rx=malloc(STREAM_FRAME);assert(large_rx);
    for(unsigned i=0;i<STREAM_FRAME;i++)large_rx[i]=(uint8_t)(i*37u+11u);
    large_rx[0]=0x5a;uint8_t *prefix=malloc(18+4+STREAM_FRAME-16);assert(prefix);
    memcpy(prefix,frame,18);prefix[18]=0;prefix[19]=1;prefix[20]=0;prefix[21]=0;
    memcpy(prefix+22,large_rx,STREAM_FRAME-16);before=received;
    expected_payload=large_rx;expected_size=STREAM_FRAME;
    write_chunks_poll(peer,prefix,18+4+STREAM_FRAME-16);
    assert(received==before+1 && received_ids[before]==42);
    assert(stream.rx_start==0 && stream.need==STREAM_FRAME+4 && stream.used==STREAM_FRAME+4-16);
    uint8_t tail[16];memcpy(tail,large_rx+STREAM_FRAME-16,sizeof(tail));
    write_chunks_poll(peer,tail,sizeof(tail));
    assert(received==before+2 && received_ids[before+1]==0x5a && stream.rx_used==0);
    expected_payload=NULL;expected_size=0;free(prefix);free(large_rx);close(peer);stream_disconnect();

    // A callback backpressure on frame 2 retains it and all later frames in
    // order, while used==need remains visible to broker blocked_rx polling.
    peer=pair();uint8_t trio[3][18];for(unsigned i=0;i<3;i++){memcpy(trio[i],frame,18);trio[i][4]=(uint8_t)(10+i);}
    before=received;block_after=before+1;assert(write(peer,trio,sizeof(trio))==(ssize_t)sizeof(trio));stream_poll();
    assert(received==before+1 && received_ids[before]==10 && stream.used==stream.need && stream.rx_start==18 && stream.rx_used==36);
    block_after=0;stream_poll();assert(received==before+3 && received_ids[before+1]==11 && received_ids[before+2]==12 && stream.rx_used==0 && stream.rx_start==0);
    close(peer);stream_disconnect();

    // Pause leaves socket bytes untouched; resume consumes them in order.
    peer=pair();stream.paused=1;assert(write(peer,frame,18)==18);before=received;stream_poll();assert(received==before && stream.rx_used==0);
    stream.paused=0;stream_poll();assert(received==before+1);close(peer);stream_disconnect();

    // A valid frame preceding a malformed length is delivered before reset.
    peer=pair();uint8_t valid_bad[22];memcpy(valid_bad,frame,18);memset(valid_bad+18,0,4);valid_bad[21]=1;
    before=received;assert(write(peer,valid_bad,sizeof(valid_bad))==(ssize_t)sizeof(valid_bad));stream_poll();
    assert(received==before+1 && stream.fd==-1 && stream.rx_used==0);close(peer);
    const uint32_t invalid[]={0,1,13,65537,0xffffffff};
    for(unsigned j=0;j<sizeof(invalid)/sizeof(*invalid);j++){
        peer=pair();uint8_t h[4];for(unsigned i=0;i<4;i++)h[i]=(uint8_t)(invalid[j]>>(24-8*i));
        assert(write(peer,h,4)==4);stream_poll();assert(stream.fd==-1);close(peer);
    }
    peer=pair();uint8_t *large=calloc(1,STREAM_FRAME+4);assert(large);large[1]=1;large[4]=42;before=received;
    for(unsigned offset=0;offset<STREAM_FRAME+4;){unsigned size=STREAM_FRAME+4-offset;if(size>1024)size=1024;assert(write(peer,large+offset,size)==size);offset+=size;stream_poll();}assert(received==before+1);free(large);close(peer);stream_disconnect();
    peer=pair();assert(write(peer,frame,2)==2);stream_poll();assert(stream.used==2);close(peer);stream_poll();assert(stream.used==0);
    // EOF after a complete header but before the declared payload is complete.
    peer=pair();assert(write(peer,frame,10)==10);stream_poll();assert(stream.used==10 && stream.need==18);close(peer);stream_poll();assert(stream.used==0 && stream.rx_used==0);
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
    before=received;assert(write(peer,frame,18)==18);stream_poll();assert(received==before+1);close(peer);stream_poll();assert(stream.fd==-1);
    stream.retry=0;stream_connect();assert(stream.fd>=0);peer=accept(listener,NULL,NULL);assert(peer>=0);
    close(peer);close(listener);stream_disconnect();unlink(path);rmdir(dir);
    puts("PASS stream: read-ahead/budget continuation, callback backpressure, pause, malformed/EOF reset, max frame, TX framing, private sockets and reconnect");
}
