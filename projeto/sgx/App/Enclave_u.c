#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_verify_signature_t {
	sgx_status_t ms_retval;
	uint8_t* ms_data;
	size_t ms_data_len;
	uint8_t* ms_signature;
	size_t ms_sig_len;
	int ms_signer_type;
	int* ms_is_valid;
} ms_ecall_verify_signature_t;

typedef struct ms_ocall_printf_t {
	const char* ms_str;
} ms_ocall_printf_t;

static sgx_status_t SGX_CDECL Enclave_ocall_printf(void* pms)
{
	ms_ocall_printf_t* ms = SGX_CAST(ms_ocall_printf_t*, pms);
	ocall_printf(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_printf,
	}
};
sgx_status_t ecall_verify_signature(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* data, size_t data_len, uint8_t* signature, size_t sig_len, int signer_type, int* is_valid)
{
	sgx_status_t status;
	ms_ecall_verify_signature_t ms;
	ms.ms_data = data;
	ms.ms_data_len = data_len;
	ms.ms_signature = signature;
	ms.ms_sig_len = sig_len;
	ms.ms_signer_type = signer_type;
	ms.ms_is_valid = is_valid;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

