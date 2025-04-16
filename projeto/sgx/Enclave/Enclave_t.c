#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_generate_rsa_key_pair(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generate_rsa_key_pair_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_generate_rsa_key_pair_t* ms = SGX_CAST(ms_ecall_generate_rsa_key_pair_t*, pms);
	ms_ecall_generate_rsa_key_pair_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_generate_rsa_key_pair_t), ms, sizeof(ms_ecall_generate_rsa_key_pair_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = ecall_generate_rsa_key_pair();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_rsa_pubkey(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_rsa_pubkey_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_rsa_pubkey_t* ms = SGX_CAST(ms_ecall_get_rsa_pubkey_t*, pms);
	ms_ecall_get_rsa_pubkey_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_get_rsa_pubkey_t), ms, sizeof(ms_ecall_get_rsa_pubkey_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_mod = __in_ms.ms_mod;
	size_t _tmp_mod_len = __in_ms.ms_mod_len;
	size_t _len_mod = _tmp_mod_len;
	uint8_t* _in_mod = NULL;
	uint8_t* _tmp_exp = __in_ms.ms_exp;
	size_t _tmp_exp_len = __in_ms.ms_exp_len;
	size_t _len_exp = _tmp_exp_len;
	uint8_t* _in_exp = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_mod, _len_mod);
	CHECK_UNIQUE_POINTER(_tmp_exp, _len_exp);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_mod != NULL && _len_mod != 0) {
		if ( _len_mod % sizeof(*_tmp_mod) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_mod = (uint8_t*)malloc(_len_mod)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mod, 0, _len_mod);
	}
	if (_tmp_exp != NULL && _len_exp != 0) {
		if ( _len_exp % sizeof(*_tmp_exp) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_exp = (uint8_t*)malloc(_len_exp)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_exp, 0, _len_exp);
	}
	_in_retval = ecall_get_rsa_pubkey(_in_mod, _tmp_mod_len, _in_exp, _tmp_exp_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_mod) {
		if (memcpy_verw_s(_tmp_mod, _len_mod, _in_mod, _len_mod)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_exp) {
		if (memcpy_verw_s(_tmp_exp, _len_exp, _in_exp, _len_exp)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_mod) free(_in_mod);
	if (_in_exp) free(_in_exp);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_rsa_decrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_rsa_decrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_rsa_decrypt_t* ms = SGX_CAST(ms_ecall_rsa_decrypt_t*, pms);
	ms_ecall_rsa_decrypt_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_rsa_decrypt_t), ms, sizeof(ms_ecall_rsa_decrypt_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_enc_data = __in_ms.ms_enc_data;
	size_t _tmp_enc_len = __in_ms.ms_enc_len;
	size_t _len_enc_data = _tmp_enc_len;
	uint8_t* _in_enc_data = NULL;
	uint8_t* _tmp_output = __in_ms.ms_output;
	size_t _tmp_output_size = __in_ms.ms_output_size;
	size_t _len_output = _tmp_output_size;
	uint8_t* _in_output = NULL;
	size_t* _tmp_decrypted_len = __in_ms.ms_decrypted_len;
	size_t _len_decrypted_len = sizeof(size_t);
	size_t* _in_decrypted_len = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_enc_data, _len_enc_data);
	CHECK_UNIQUE_POINTER(_tmp_output, _len_output);
	CHECK_UNIQUE_POINTER(_tmp_decrypted_len, _len_decrypted_len);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_enc_data != NULL && _len_enc_data != 0) {
		if ( _len_enc_data % sizeof(*_tmp_enc_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_enc_data = (uint8_t*)malloc(_len_enc_data);
		if (_in_enc_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enc_data, _len_enc_data, _tmp_enc_data, _len_enc_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_output != NULL && _len_output != 0) {
		if ( _len_output % sizeof(*_tmp_output) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_output = (uint8_t*)malloc(_len_output)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_output, 0, _len_output);
	}
	if (_tmp_decrypted_len != NULL && _len_decrypted_len != 0) {
		if ( _len_decrypted_len % sizeof(*_tmp_decrypted_len) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_decrypted_len = (size_t*)malloc(_len_decrypted_len)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_decrypted_len, 0, _len_decrypted_len);
	}
	_in_retval = ecall_rsa_decrypt((const uint8_t*)_in_enc_data, _tmp_enc_len, _in_output, _tmp_output_size, _in_decrypted_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_output) {
		if (memcpy_verw_s(_tmp_output, _len_output, _in_output, _len_output)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_decrypted_len) {
		if (memcpy_verw_s(_tmp_decrypted_len, _len_decrypted_len, _in_decrypted_len, _len_decrypted_len)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_enc_data) free(_in_enc_data);
	if (_in_output) free(_in_output);
	if (_in_decrypted_len) free(_in_decrypted_len);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_rsa_sign(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_rsa_sign_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_rsa_sign_t* ms = SGX_CAST(ms_ecall_rsa_sign_t*, pms);
	ms_ecall_rsa_sign_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_rsa_sign_t), ms, sizeof(ms_ecall_rsa_sign_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_data = __in_ms.ms_data;
	size_t _tmp_data_len = __in_ms.ms_data_len;
	size_t _len_data = _tmp_data_len;
	uint8_t* _in_data = NULL;
	uint8_t* _tmp_signature = __in_ms.ms_signature;
	size_t _tmp_sig_len = __in_ms.ms_sig_len;
	size_t _len_signature = _tmp_sig_len;
	uint8_t* _in_signature = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_data != NULL && _len_data != 0) {
		if ( _len_data % sizeof(*_tmp_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data = (uint8_t*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_signature != NULL && _len_signature != 0) {
		if ( _len_signature % sizeof(*_tmp_signature) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_signature = (uint8_t*)malloc(_len_signature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_signature, 0, _len_signature);
	}
	_in_retval = ecall_rsa_sign((const uint8_t*)_in_data, _tmp_data_len, _in_signature, _tmp_sig_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_signature) {
		if (memcpy_verw_s(_tmp_signature, _len_signature, _in_signature, _len_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_data) free(_in_data);
	if (_in_signature) free(_in_signature);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_ecall_generate_rsa_key_pair, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_rsa_pubkey, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_rsa_decrypt, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_rsa_sign, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][4];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_printf(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_printf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_printf_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_printf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_printf_t));
	ocalloc_size -= sizeof(ms_ocall_printf_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

