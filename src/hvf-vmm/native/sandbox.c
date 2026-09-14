// SPDX-License-Identifier: Apache-2.0
#include "seatbelt.h"
#include <sandbox.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>
int hvf_sandbox_install(const char *profile){
    // A missing profile is an error, never an implicit unrestricted fallback.
    if(!profile){fprintf(stderr,"missing Seatbelt profile\n");return -1;}
    char release[64];size_t size=sizeof(release);
    if(sysctlbyname("kern.osrelease",release,&size,NULL,0)||atoi(release)!=25){fprintf(stderr,"Seatbelt adapter requires macOS 26 / Darwin 25\n");return -1;}
    char *error=NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    int result=sandbox_init(profile,0,&error);
    if(result){fprintf(stderr,"Seatbelt installation failed: %s\n",error?error:"unknown error");if(error)sandbox_free_error(error);}
#pragma clang diagnostic pop
    return result;
}
