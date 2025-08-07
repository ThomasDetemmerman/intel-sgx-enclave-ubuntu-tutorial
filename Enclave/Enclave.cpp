#include "Enclave_t.h"
#include <stdio.h>
#include <string.h>

int trusted_func01()
{
    int trusted_x = 987654321;
    ocall_wait_keyinput("Please enter keyboard to show variables in memory ...");
    return trusted_x;
}



#include "sgx_trts.h"
#include "sgx_error.h"
#include "sgx_report.h"
#include "sgx_utils.h"

uint32_t enclave_create_report(const sgx_target_info_t* p_qe3_target,
                const sgx_report_data_t* p_data,
		sgx_report_t* p_report)
{
    return sgx_create_report(p_qe3_target, p_data, p_report);
}


