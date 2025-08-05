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

const char *format_hex_buffer (char *buffer, uint maxSize, uint8_t *data, size_t size)
{
    if (size * 2 >= maxSize)
        return "DEADBEEF";

    for (int i=0; i < size; i++)
    {
        sprintf(&buffer[i*2], "%02X", data[i]);
    }
    buffer[size*2+1] = '\0';
    return buffer;
}


const char *uint16_to_buffer (char *buffer, uint maxSize, uint16_t n, size_t size)
{
    if (size * 2 >= maxSize || size < 2)
        return "DEADBEEF";
    sprintf(&buffer[0], "%02X", uint8_t(n));
    sprintf(&buffer[2], "%02X", uint8_t(n >> 8));

    for (int i=2; i < size; i++)
    {
        sprintf(&buffer[i*2], "%02X", 0);
    }
    buffer[size*2+1] = '\0';
    return buffer;
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

    if ((SGX_SUCCESS != sgx_status) || (0 != retval)) {
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
    printf("\nStep1: Call sgx_qe_get_target_info ");



    
    sgx_target_info_t qe_target_info;
    sgx_report_t app_report;
    uint8_t enclave_held_data[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    sgx_report_data_t hash;
    sha256sum(enclave_held_data, 6, hash.d);
    if(true != create_app_enclave_report(argv[1], qe_target_info, &app_report, &hash)) {
            printf("Call to create_app_report() failed\n");
            return -1;
        }
        printf("succeed!\n");

    //----- second part ----------------------------------------------

    printf("\nStep3: Call sgx_qe_get_quote_size ");

    uint32_t quote_size = 0;
    sgx_qe_get_quote_size(&quote_size);
    printf("\nQuote size = %u\n", quote_size);
    //----- third part ----------------------------------------------

    uint8_t* p_quote_buffer = (uint8_t*)malloc(quote_size);
    if (NULL == p_quote_buffer) {
        printf("\nCouldn't allocate quote_buffer\n");
        if (NULL != p_quote_buffer) {
            free(p_quote_buffer);
        }
        return -1;
    }
    memset(p_quote_buffer, 0, quote_size);

    printf("\nStep4: Call sgx_qe_get_quote: ");
    sgx_qe_get_quote(&app_report, quote_size, p_quote_buffer);

    //----- fourth part ----------------------------------------------


    sgx_quote3_t *p_quote = (_sgx_quote3_t*)p_quote_buffer;
    sgx_ql_ecdsa_sig_data_t *p_sig_data = (sgx_ql_ecdsa_sig_data_t *)p_quote->signature_data;
    sgx_ql_auth_data_t *p_auth_data = (sgx_ql_auth_data_t*)p_sig_data->auth_certification_data;
    sgx_ql_certification_data_t *p_cert_data =
            (sgx_ql_certification_data_t *)((uint8_t *)p_auth_data + sizeof(*p_auth_data) + p_auth_data->size);

    const int hex_buffer_size = 1024*64;
    char hex_buffer[hex_buffer_size];

    /*std::string output_dir("./out/");
    std::string cmd("mkdir -p " + output_dir);
    std::string file(output_dir + "quote.json");
    int result = system(cmd.c_str());
	printf("\nExecuted command '%s' with the result:%u", cmd.c_str(), result);
    printf("\nStep5: Saving quote to JSON file, cert_key_type = 0x%x, output file name = %s\n", p_cert_data->cert_key_type, file.c_str());
    FILE *fp = fopen(file.c_str(), "w");*/
    printf( "%s\n", "{");
    printf( "  \"Type\": %d,\n", (int)2);
    // In open-enclave sdk enclave type 2 means OE_ENCLAVE_TYPE_SGX: 
    // https://github.com/openenclave/openenclave/blob/3e15573418caed43f9094ff8aec36cdde4f278f7/include/openenclave/bits/types.h#L127
    printf( "  \"MrEnclaveHex\": \"%s\",\n", format_hex_buffer(hex_buffer, hex_buffer_size, app_report.body.mr_enclave.m, SGX_HASH_SIZE));
    printf( "  \"MrSignerHex\": \"%s\",\n", format_hex_buffer(hex_buffer, hex_buffer_size, app_report.body.mr_signer.m, SGX_HASH_SIZE));
    printf( "  \"ProductIdHex\": \"%s\",\n", uint16_to_buffer(hex_buffer, hex_buffer_size,(uint16_t)app_report.body.isv_prod_id, 16));
    printf( "  \"SecurityVersion\": %u,\n", (int)app_report.body.isv_svn);
    printf( "  \"Attributes\": %lu,\n", (uint64_t)app_report.body.attributes.flags);
    printf( "  \"QuoteHex\": \"%s\",\n", format_hex_buffer(hex_buffer, hex_buffer_size, p_quote_buffer, quote_size));
    printf( "  \"EnclaveHeldDataHex\": \"%s\"\n", format_hex_buffer(hex_buffer, hex_buffer_size, enclave_held_data, sizeof( enclave_held_data)));
    printf( "%s\n\n", "}");
    //fclose(fp);

    /*if (NULL != p_quote_buffer) {
        free(p_quote_buffer);
    }*/



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