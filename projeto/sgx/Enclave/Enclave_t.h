#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t ecall_generate_rsa_key_pair(void);
sgx_status_t ecall_get_rsa_pubkey(uint8_t* mod, size_t mod_len, uint8_t* exp, size_t exp_len);
sgx_status_t ecall_rsa_decrypt(const uint8_t* enc_data, size_t enc_len, uint8_t* output, size_t output_size, size_t* decrypted_len);
sgx_status_t ecall_rsa_sign(const uint8_t* data, size_t data_len, uint8_t* signature, size_t sig_len);

sgx_status_t SGX_CDECL ocall_printf(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
