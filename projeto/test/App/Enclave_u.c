#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecc_verify_t {
	int ms_retval;
	uint8_t* ms_data;
	size_t ms_len;
	sgx_ec256_signature_t* ms_signature;
} ms_ecc_verify_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t ecc_verify(sgx_enclave_id_t eid, int* retval, uint8_t* data, size_t len, sgx_ec256_signature_t* signature)
{
	sgx_status_t status;
	ms_ecc_verify_t ms;
	ms.ms_data = data;
	ms.ms_len = len;
	ms.ms_signature = signature;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

