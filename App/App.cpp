#include <stdio.h>
#include <string.h>

# define ENCLAVE_FILENAME "enclave.signed.so"

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

sgx_enclave_id_t global_eid = 0;

/* ocall functions (untrusted) */
void ocall_wait_keyinput(const char *str)
{
    printf("%s", str);
    getchar();
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
    }
    printf("Enclave initialized successfully. Starting attestation\n");
    //perform attestation
    // 1) Get report from enclave
    sgx_report_t report;
    ret = get_enclave_report(global_eid, &report); 
    if (ret != SGX_SUCCESS) { 
        printf("Error with getting attestation\n");
        getchar();
        return -1;
    }
    // 2) Get quote size
    uint32_t quote_size = 0;
    ret = sgx_get_quote_size(NULL, &quote_size);
    if (ret != SGX_SUCCESS) { 
        printf("Error getting the size of the quote\n");
        getchar();
        return -1;
    }
    // 3) Allocate buffer for quote
    uint8_t *quote = malloc(quote_size);
    if (!quote) { 
        printf("Error allocating buffer for quote\n");
        getchar();
        return -1;
    }
    // 4) Get quote from report
    ret = sgx_get_quote(&report, SGX_LINKABLE_SIGNATURE, NULL, 0, NULL, quote, quote_size);
    if (ret != SGX_SUCCESS)  { 
        printf("Error getting quote from report\n");
        getchar();
        return -1;
    }
    printf("Attestation successful. Quote size: %d\n", quote_size);
    
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

