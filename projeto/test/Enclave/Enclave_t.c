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


typedef struct ms_ecc_verify_t {
	int ms_retval;
	uint8_t* ms_data;
	size_t ms_len;
	sgx_ec256_signature_t* ms_signature;
} ms_ecc_verify_t;

static sgx_status_t SGX_CDECL sgx_ecc_verify(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecc_verify_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecc_verify_t* ms = SGX_CAST(ms_ecc_verify_t*, pms);
	ms_ecc_verify_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecc_verify_t), ms, sizeof(ms_ecc_verify_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_data = __in_ms.ms_data;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_data = _tmp_len;
	uint8_t* _in_data = NULL;
	sgx_ec256_signature_t* _tmp_signature = __in_ms.ms_signature;
	size_t _len_signature = sizeof(sgx_ec256_signature_t);
	sgx_ec256_signature_t* _in_signature = NULL;
	int _in_retval;

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
		_in_signature = (sgx_ec256_signature_t*)malloc(_len_signature);
		if (_in_signature == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_signature, _len_signature, _tmp_signature, _len_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecc_verify(_in_data, _tmp_len, _in_signature);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_data) free(_in_data);
	if (_in_signature) free(_in_signature);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_ecc_verify, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


