#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_generate_rsa_key_pair_t {
	sgx_status_t ms_retval;
} ms_ecall_generate_rsa_key_pair_t;

typedef struct ms_ecall_get_rsa_pubkey_t {
	sgx_status_t ms_retval;
	uint8_t* ms_mod;
	size_t ms_mod_len;
	uint8_t* ms_exp;
	size_t ms_exp_len;
} ms_ecall_get_rsa_pubkey_t;

typedef struct ms_ecall_rsa_decrypt_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_enc_data;
	size_t ms_enc_len;
	uint8_t* ms_output;
	size_t ms_output_size;
	size_t* ms_decrypted_len;
} ms_ecall_rsa_decrypt_t;

typedef struct ms_ecall_rsa_sign_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_data;
	size_t ms_data_len;
	uint8_t* ms_signature;
	size_t ms_sig_len;
} ms_ecall_rsa_sign_t;

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
sgx_status_t ecall_generate_rsa_key_pair(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_ecall_generate_rsa_key_pair_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_get_rsa_pubkey(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* mod, size_t mod_len, uint8_t* exp, size_t exp_len)
{
	sgx_status_t status;
	ms_ecall_get_rsa_pubkey_t ms;
	ms.ms_mod = mod;
	ms.ms_mod_len = mod_len;
	ms.ms_exp = exp;
	ms.ms_exp_len = exp_len;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_rsa_decrypt(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* enc_data, size_t enc_len, uint8_t* output, size_t output_size, size_t* decrypted_len)
{
	sgx_status_t status;
	ms_ecall_rsa_decrypt_t ms;
	ms.ms_enc_data = enc_data;
	ms.ms_enc_len = enc_len;
	ms.ms_output = output;
	ms.ms_output_size = output_size;
	ms.ms_decrypted_len = decrypted_len;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_rsa_sign(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* data, size_t data_len, uint8_t* signature, size_t sig_len)
{
	sgx_status_t status;
	ms_ecall_rsa_sign_t ms;
	ms.ms_data = data;
	ms.ms_data_len = data_len;
	ms.ms_signature = signature;
	ms.ms_sig_len = sig_len;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

