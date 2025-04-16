#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINTF_DEFINED__
#define OCALL_PRINTF_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_printf, (const char* str));
#endif

sgx_status_t ecall_generate_rsa_key_pair(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t ecall_get_rsa_pubkey(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* mod, size_t mod_len, uint8_t* exp, size_t exp_len);
sgx_status_t ecall_rsa_decrypt(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* enc_data, size_t enc_len, uint8_t* output, size_t output_size, size_t* decrypted_len);
sgx_status_t ecall_rsa_sign(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* data, size_t data_len, uint8_t* signature, size_t sig_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
