#include "Enclave_t.h"
#include <stdio.h>
#include <string.h>
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
#include <sgx_tkey_exchange.h>
#include <sgx_report.h>

int trusted_func01()
{
    int trusted_x = 987654321;
    ocall_wait_keyinput("Please enter keyboard to show variables in memory ...");
    return trusted_x;
}

sgx_status_t get_enclave_report(sgx_report_t *report)
{
    if (report == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t status = sgx_create_report(NULL, NULL, report);
    return status;
}