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

sgx_status_t ecall_verify_signature(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* data, size_t data_len, uint8_t* signature, size_t sig_len, int signer_type, int* is_valid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
