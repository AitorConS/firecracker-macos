// SPDX-License-Identifier: Apache-2.0
#include "seatbelt.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc,char **argv){assert(argc==3);int fd=open(argv[2],O_RDWR);assert(fd>=0);close(fd);assert(!hvf_sandbox_install(argv[1]));fd=open(argv[2],O_RDWR);int leak=fd>=0;if(fd>=0)close(fd);printf("replacement_path_access=%d\n",leak);return leak?1:0;}
