// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <sys/socket.h>
#include <netinet/in.h>
int hvf_gate_start(void);
int hvf_gate_active(void);
int hvf_gate_tcp(int fd,const struct sockaddr_in *,int listener);
int hvf_gate_udp(void);
int hvf_gate_is_udp(int fd);
int hvf_gate_bind(int fd,const struct sockaddr_in *);
int hvf_gate_name(int fd,struct sockaddr *,socklen_t *);
ssize_t hvf_gate_send(int fd,const void *,size_t,int,const struct sockaddr *,socklen_t);
ssize_t hvf_gate_recv(int fd,void *,size_t,int,struct sockaddr *,socklen_t *);
void hvf_gate_close(int fd);

int hvf_gate_is_listener(int fd);

int hvf_gate_check(void);
