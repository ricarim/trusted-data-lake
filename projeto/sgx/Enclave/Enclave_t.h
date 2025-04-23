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

sgx_status_t ecall_verify_signature(uint8_t* data, size_t data_len, uint8_t* signature, size_t sig_len, int signer_type, int* is_valid);

sgx_status_t SGX_CDECL ocall_printf(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
