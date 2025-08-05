#include <stdio.h>
#include <string.h>

# define ENCLAVE_FILENAME "enclave.signed.so"

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

// extras -----
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>

#include "sgx_error.h"   /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "sgx_urts.h"
#include "sgx_quote_3.h"
#include "sgx_dcap_ql_wrapper.h"
// einde extras -----

sgx_enclave_id_t global_eid = 0;

void sha256sum(const uint8_t *data, uint32_t data_size, uint8_t *hash)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, data_size);
    SHA256_Final(hash, &sha256);
}

/* ocall functions (untrusted) */
void ocall_wait_keyinput(const char *str)
{
    printf("%s", str);
    getchar();
}

bool create_app_enclave_report(const char* enclave_path, sgx_target_info_t qe_target_info, sgx_report_t *app_report, const sgx_report_data_t* p_data)
{
    bool ret = true;
    uint32_t retval = 0;
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_enclave_id_t eid = 0;
    int launch_token_updated = 0;
    sgx_launch_token_t launch_token = { 0 };
    // delete because already in calling function
    /*sgx_status = sgx_create_enclave(enclave_path,
                                    SGX_DEBUG_FLAG,
                                    &launch_token,
                                    &launch_token_updated,
                                    &eid,
                                    NULL);
    if (SGX_SUCCESS != sgx_status) {
        printf("Error, call sgx_create_enclave fail [%s], SGXError:%04x.\n", __FUNCTION__, sgx_status);
        ret = false;
        sgx_destroy_enclave(eid);
        return ret;
    }
*/
    sgx_status = enclave_create_report(global_eid,
                                       &retval,
                                       &qe_target_info,
                                       p_data,
				                        app_report);
     printf("sgx_status: %04x. Expected value for success is %04x\n", sgx_status, SGX_SUCCESS);
    printf("Enclave create report returned: %d\n", retval);

    if ((SGX_SUCCESS != sgx_status) || (0 == retval)) {
        printf("\nCall to get_app_enclave_report() failed\n");
        ret = false;
        sgx_destroy_enclave(eid);
        return ret;
    }

    sgx_destroy_enclave(eid);
    return ret;
}

/* application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    int untrusted_x = 123456789;

    // initialize enclave
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Enclave init error\n");
        getchar();
        return -1;
    } else {
        printf("Enclave initialized successfully\n");
    }
 
    //----------------------------------------------
    printf("\nStep1: Call sgx_qe_get_target_info: ");



    
    sgx_target_info_t qe_target_info;
    sgx_report_t app_report;
     quote3_error_t qe3_ret = sgx_qe_get_target_info(&qe_target_info);
    uint8_t enclave_held_data[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    sgx_report_data_t hash;
    sha256sum(enclave_held_data, 6, hash.d);
    if(true != create_app_enclave_report(argv[1], qe_target_info, &app_report, &hash)) {
            printf("Call to create_app_report() failed\n");
            return -1;
        }
        printf("succeed!\n");

    //----- second part ----------------------------------------------



    //---------------------------------------------
    // invoke trusted_func01();
    int returned_result;
    ret = trusted_func01(global_eid, &returned_result);
    if (ret != SGX_SUCCESS) {
        printf("Enclave call error\n");
        return -1;
    }

    // destroy the enclave
    sgx_destroy_enclave(global_eid);

    printf ("X (untrusted): %d\n", untrusted_x);
    printf ("X (trusted): %d\n", returned_result);

    return 0;
}