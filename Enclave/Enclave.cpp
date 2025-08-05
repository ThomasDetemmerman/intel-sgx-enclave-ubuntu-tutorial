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

uint32_t enclave_create_report(const sgx_target_info_t* p_qe3_target,
                const sgx_report_data_t* p_data,
		sgx_report_t* p_report)
{
    return sgx_create_report(p_qe3_target, p_data, p_report);
}