#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_tcrypto.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t ecc_verify(sgx_enclave_id_t eid, int* retval, uint8_t* data, size_t len, sgx_ec256_signature_t* signature);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
