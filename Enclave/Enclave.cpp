#include <stdio.h>
#include <string.h>
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
#include <sgx_tkey_exchange.h>
#include "sgx_trts.h"
#include "sgx_error.h"
#include "sgx_report.h"
#include "sgx_utils.h"

int trusted_func01()
{
    int trusted_x = 987654321;
    ocall_wait_keyinput("Please enter keyboard to show variables in memory ...");
    return trusted_x;
}
