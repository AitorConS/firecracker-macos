// SPDX-License-Identifier: Apache-2.0
// Mandatory forced include for every vendored libslirp translation unit.
#pragma once
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
int hvf_policy_socket(int,int,int);
int hvf_policy_connect(int,const struct sockaddr *,socklen_t);
int hvf_policy_bind(int,const struct sockaddr *,socklen_t);
int hvf_policy_listen(int,int);
ssize_t hvf_policy_sendto(int,const void *,size_t,int,const struct sockaddr *,socklen_t);
int hvf_policy_dns(struct in_addr *,uint16_t *);
ssize_t hvf_policy_recvfrom(int,void *,size_t,int,struct sockaddr *,socklen_t *);
int hvf_policy_close(int);
#define recvfrom(a,b,c,d,e,f) hvf_policy_recvfrom(a,b,c,d,e,f)
#define close(a) hvf_policy_close(a)
#define socket(a,b,c) hvf_policy_socket(a,b,c)
#define connect(a,b,c) hvf_policy_connect(a,b,c)
#define bind(a,b,c) hvf_policy_bind(a,b,c)
#define listen(a,b) hvf_policy_listen(a,b)
#define sendto(a,b,c,d,e,f) hvf_policy_sendto(a,b,c,d,e,f)

int hvf_policy_getsockname(int,struct sockaddr *,socklen_t *);
#define getsockname(a,b,c) hvf_policy_getsockname(a,b,c)
