#include <iostream>
#include <digest.h>
//#include <mac.h>
//#include <key_mgmt.h>
#include <cstdio>

#pragma once 
int start_session(vhsm_session& session);
int close_session (vhsm_session& session);
void print_bytes(unsigned char const * data, size_t n_bytes);
