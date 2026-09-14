// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "hvf.h"
void hvf_policy_set(const struct hvf_security *);

#include <netinet/in.h>
int hvf_policy_allows(int,const struct sockaddr_in *,int);
