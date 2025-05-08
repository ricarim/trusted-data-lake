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


typedef struct ms_ecall_generate_and_seal_key_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_data;
	uint32_t ms_sealed_size;
} ms_ecall_generate_and_seal_key_t;

typedef struct ms_ecall_unseal_key_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_data;
	uint32_t ms_sealed_size;
} ms_ecall_unseal_key_t;

typedef struct ms_ecall_process_stats_t {
	sgx_status_t ms_retval;
	const char* ms_signed_data;
	uint32_t ms_signed_data_len;
	const uint8_t* ms_sig1;
	uint32_t ms_sig1_len;
	const uint8_t* ms_sig2;
	uint32_t ms_sig2_len;
	const uint8_t* ms_ciphertext;
	uint32_t ms_ciphertext_len;
	const uint8_t* ms_iv;
	uint32_t ms_iv_len;
	const uint8_t* ms_mac;
	int ms_op_code;
	double* ms_result;
} ms_ecall_process_stats_t;

typedef struct ms_ecall_encrypt_data_t {
	sgx_status_t ms_retval;
	uint8_t* ms_plaintext;
	size_t ms_plaintext_len;
	uint8_t* ms_iv;
	size_t ms_iv_len;
	uint8_t* ms_ciphertext;
	uint8_t* ms_mac;
} ms_ecall_encrypt_data_t;

typedef struct ms_ecall_process_encrypt_t {
	sgx_status_t ms_retval;
	const char* ms_signed_data;
	uint32_t ms_signed_data_len;
	const uint8_t* ms_signature;
	uint32_t ms_signature_len;
} ms_ecall_process_encrypt_t;

typedef struct ms_ecall_generate_iv_t {
	sgx_status_t ms_retval;
	uint8_t* ms_iv;
	size_t ms_iv_len;
} ms_ecall_generate_iv_t;

typedef struct ms_ecall_sum_t {
	sgx_status_t ms_retval;
	double* ms_data;
	size_t ms_len;
	double* ms_result;
} ms_ecall_sum_t;

typedef struct ms_ecall_mean_t {
	sgx_status_t ms_retval;
	double* ms_data;
	size_t ms_len;
	double* ms_result;
} ms_ecall_mean_t;

typedef struct ms_ecall_min_t {
	sgx_status_t ms_retval;
	double* ms_data;
	size_t ms_len;
	double* ms_result;
} ms_ecall_min_t;

typedef struct ms_ecall_max_t {
	sgx_status_t ms_retval;
	double* ms_data;
	size_t ms_len;
	double* ms_result;
} ms_ecall_max_t;

typedef struct ms_ecall_median_t {
	sgx_status_t ms_retval;
	double* ms_data;
	size_t ms_len;
	double* ms_result;
} ms_ecall_median_t;

typedef struct ms_ecall_mode_t {
	sgx_status_t ms_retval;
	double* ms_data;
	size_t ms_len;
	double* ms_result;
} ms_ecall_mode_t;

typedef struct ms_ecall_variance_t {
	sgx_status_t ms_retval;
	double* ms_data;
	size_t ms_len;
	double* ms_result;
} ms_ecall_variance_t;

typedef struct ms_ecall_stddev_t {
	sgx_status_t ms_retval;
	double* ms_data;
	size_t ms_len;
	double* ms_result;
} ms_ecall_stddev_t;

typedef struct ms_ecall_create_report_t {
	sgx_status_t ms_retval;
	uint8_t* ms_target_info_buf;
	uint8_t* ms_report_buf;
} ms_ecall_create_report_t;

typedef struct ms_ocall_printf_t {
	const char* ms_str;
} ms_ocall_printf_t;

typedef struct ms_ocall_get_time_t {
	uint64_t* ms_t;
} ms_ocall_get_time_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	void* ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL sgx_ecall_generate_and_seal_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generate_and_seal_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_generate_and_seal_key_t* ms = SGX_CAST(ms_ecall_generate_and_seal_key_t*, pms);
	ms_ecall_generate_and_seal_key_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_generate_and_seal_key_t), ms, sizeof(ms_ecall_generate_and_seal_key_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_data = __in_ms.ms_sealed_data;
	uint32_t _tmp_sealed_size = __in_ms.ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	uint8_t* _in_sealed_data = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ( _len_sealed_data % sizeof(*_tmp_sealed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_data = (uint8_t*)malloc(_len_sealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data, 0, _len_sealed_data);
	}
	_in_retval = ecall_generate_and_seal_key(_in_sealed_data, _tmp_sealed_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_sealed_data) {
		if (memcpy_verw_s(_tmp_sealed_data, _len_sealed_data, _in_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_data) free(_in_sealed_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_unseal_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_unseal_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_unseal_key_t* ms = SGX_CAST(ms_ecall_unseal_key_t*, pms);
	ms_ecall_unseal_key_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_unseal_key_t), ms, sizeof(ms_ecall_unseal_key_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_data = __in_ms.ms_sealed_data;
	uint32_t _tmp_sealed_size = __in_ms.ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	uint8_t* _in_sealed_data = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ( _len_sealed_data % sizeof(*_tmp_sealed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_data = (uint8_t*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_data, _len_sealed_data, _tmp_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecall_unseal_key(_in_sealed_data, _tmp_sealed_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_sealed_data) free(_in_sealed_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_process_stats(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_process_stats_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_process_stats_t* ms = SGX_CAST(ms_ecall_process_stats_t*, pms);
	ms_ecall_process_stats_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_process_stats_t), ms, sizeof(ms_ecall_process_stats_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_signed_data = __in_ms.ms_signed_data;
	uint32_t _tmp_signed_data_len = __in_ms.ms_signed_data_len;
	size_t _len_signed_data = _tmp_signed_data_len;
	char* _in_signed_data = NULL;
	const uint8_t* _tmp_sig1 = __in_ms.ms_sig1;
	uint32_t _tmp_sig1_len = __in_ms.ms_sig1_len;
	size_t _len_sig1 = _tmp_sig1_len;
	uint8_t* _in_sig1 = NULL;
	const uint8_t* _tmp_sig2 = __in_ms.ms_sig2;
	uint32_t _tmp_sig2_len = __in_ms.ms_sig2_len;
	size_t _len_sig2 = _tmp_sig2_len;
	uint8_t* _in_sig2 = NULL;
	const uint8_t* _tmp_ciphertext = __in_ms.ms_ciphertext;
	uint32_t _tmp_ciphertext_len = __in_ms.ms_ciphertext_len;
	size_t _len_ciphertext = _tmp_ciphertext_len;
	uint8_t* _in_ciphertext = NULL;
	const uint8_t* _tmp_iv = __in_ms.ms_iv;
	uint32_t _tmp_iv_len = __in_ms.ms_iv_len;
	size_t _len_iv = _tmp_iv_len;
	uint8_t* _in_iv = NULL;
	const uint8_t* _tmp_mac = __in_ms.ms_mac;
	size_t _len_mac = 16;
	uint8_t* _in_mac = NULL;
	double* _tmp_result = __in_ms.ms_result;
	size_t _len_result = sizeof(double);
	double* _in_result = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_signed_data, _len_signed_data);
	CHECK_UNIQUE_POINTER(_tmp_sig1, _len_sig1);
	CHECK_UNIQUE_POINTER(_tmp_sig2, _len_sig2);
	CHECK_UNIQUE_POINTER(_tmp_ciphertext, _len_ciphertext);
	CHECK_UNIQUE_POINTER(_tmp_iv, _len_iv);
	CHECK_UNIQUE_POINTER(_tmp_mac, _len_mac);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_signed_data != NULL && _len_signed_data != 0) {
		if ( _len_signed_data % sizeof(*_tmp_signed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_signed_data = (char*)malloc(_len_signed_data);
		if (_in_signed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_signed_data, _len_signed_data, _tmp_signed_data, _len_signed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sig1 != NULL && _len_sig1 != 0) {
		if ( _len_sig1 % sizeof(*_tmp_sig1) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sig1 = (uint8_t*)malloc(_len_sig1);
		if (_in_sig1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sig1, _len_sig1, _tmp_sig1, _len_sig1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sig2 != NULL && _len_sig2 != 0) {
		if ( _len_sig2 % sizeof(*_tmp_sig2) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sig2 = (uint8_t*)malloc(_len_sig2);
		if (_in_sig2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sig2, _len_sig2, _tmp_sig2, _len_sig2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_ciphertext != NULL && _len_ciphertext != 0) {
		if ( _len_ciphertext % sizeof(*_tmp_ciphertext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ciphertext = (uint8_t*)malloc(_len_ciphertext);
		if (_in_ciphertext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ciphertext, _len_ciphertext, _tmp_ciphertext, _len_ciphertext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_iv != NULL && _len_iv != 0) {
		if ( _len_iv % sizeof(*_tmp_iv) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_iv = (uint8_t*)malloc(_len_iv);
		if (_in_iv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_iv, _len_iv, _tmp_iv, _len_iv)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_mac != NULL && _len_mac != 0) {
		if ( _len_mac % sizeof(*_tmp_mac) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_mac = (uint8_t*)malloc(_len_mac);
		if (_in_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_mac, _len_mac, _tmp_mac, _len_mac)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (double*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	_in_retval = ecall_process_stats((const char*)_in_signed_data, _tmp_signed_data_len, (const uint8_t*)_in_sig1, _tmp_sig1_len, (const uint8_t*)_in_sig2, _tmp_sig2_len, (const uint8_t*)_in_ciphertext, _tmp_ciphertext_len, (const uint8_t*)_in_iv, _tmp_iv_len, (const uint8_t*)_in_mac, __in_ms.ms_op_code, _in_result);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_result) {
		if (memcpy_verw_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_signed_data) free(_in_signed_data);
	if (_in_sig1) free(_in_sig1);
	if (_in_sig2) free(_in_sig2);
	if (_in_ciphertext) free(_in_ciphertext);
	if (_in_iv) free(_in_iv);
	if (_in_mac) free(_in_mac);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_encrypt_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_encrypt_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_encrypt_data_t* ms = SGX_CAST(ms_ecall_encrypt_data_t*, pms);
	ms_ecall_encrypt_data_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_encrypt_data_t), ms, sizeof(ms_ecall_encrypt_data_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_plaintext = __in_ms.ms_plaintext;
	size_t _tmp_plaintext_len = __in_ms.ms_plaintext_len;
	size_t _len_plaintext = _tmp_plaintext_len;
	uint8_t* _in_plaintext = NULL;
	uint8_t* _tmp_iv = __in_ms.ms_iv;
	size_t _tmp_iv_len = __in_ms.ms_iv_len;
	size_t _len_iv = _tmp_iv_len;
	uint8_t* _in_iv = NULL;
	uint8_t* _tmp_ciphertext = __in_ms.ms_ciphertext;
	size_t _len_ciphertext = _tmp_plaintext_len;
	uint8_t* _in_ciphertext = NULL;
	uint8_t* _tmp_mac = __in_ms.ms_mac;
	size_t _len_mac = 16;
	uint8_t* _in_mac = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);
	CHECK_UNIQUE_POINTER(_tmp_iv, _len_iv);
	CHECK_UNIQUE_POINTER(_tmp_ciphertext, _len_ciphertext);
	CHECK_UNIQUE_POINTER(_tmp_mac, _len_mac);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		if ( _len_plaintext % sizeof(*_tmp_plaintext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_plaintext = (uint8_t*)malloc(_len_plaintext);
		if (_in_plaintext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_plaintext, _len_plaintext, _tmp_plaintext, _len_plaintext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_iv != NULL && _len_iv != 0) {
		if ( _len_iv % sizeof(*_tmp_iv) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_iv = (uint8_t*)malloc(_len_iv);
		if (_in_iv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_iv, _len_iv, _tmp_iv, _len_iv)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_ciphertext != NULL && _len_ciphertext != 0) {
		if ( _len_ciphertext % sizeof(*_tmp_ciphertext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ciphertext = (uint8_t*)malloc(_len_ciphertext)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ciphertext, 0, _len_ciphertext);
	}
	if (_tmp_mac != NULL && _len_mac != 0) {
		if ( _len_mac % sizeof(*_tmp_mac) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_mac = (uint8_t*)malloc(_len_mac)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mac, 0, _len_mac);
	}
	_in_retval = ecall_encrypt_data(_in_plaintext, _tmp_plaintext_len, _in_iv, _tmp_iv_len, _in_ciphertext, _in_mac);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_ciphertext) {
		if (memcpy_verw_s(_tmp_ciphertext, _len_ciphertext, _in_ciphertext, _len_ciphertext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_mac) {
		if (memcpy_verw_s(_tmp_mac, _len_mac, _in_mac, _len_mac)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_plaintext) free(_in_plaintext);
	if (_in_iv) free(_in_iv);
	if (_in_ciphertext) free(_in_ciphertext);
	if (_in_mac) free(_in_mac);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_process_encrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_process_encrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_process_encrypt_t* ms = SGX_CAST(ms_ecall_process_encrypt_t*, pms);
	ms_ecall_process_encrypt_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_process_encrypt_t), ms, sizeof(ms_ecall_process_encrypt_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_signed_data = __in_ms.ms_signed_data;
	uint32_t _tmp_signed_data_len = __in_ms.ms_signed_data_len;
	size_t _len_signed_data = _tmp_signed_data_len;
	char* _in_signed_data = NULL;
	const uint8_t* _tmp_signature = __in_ms.ms_signature;
	uint32_t _tmp_signature_len = __in_ms.ms_signature_len;
	size_t _len_signature = _tmp_signature_len;
	uint8_t* _in_signature = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_signed_data, _len_signed_data);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_signed_data != NULL && _len_signed_data != 0) {
		if ( _len_signed_data % sizeof(*_tmp_signed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_signed_data = (char*)malloc(_len_signed_data);
		if (_in_signed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_signed_data, _len_signed_data, _tmp_signed_data, _len_signed_data)) {
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
		_in_signature = (uint8_t*)malloc(_len_signature);
		if (_in_signature == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_signature, _len_signature, _tmp_signature, _len_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecall_process_encrypt((const char*)_in_signed_data, _tmp_signed_data_len, (const uint8_t*)_in_signature, _tmp_signature_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_signed_data) free(_in_signed_data);
	if (_in_signature) free(_in_signature);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_generate_iv(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generate_iv_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_generate_iv_t* ms = SGX_CAST(ms_ecall_generate_iv_t*, pms);
	ms_ecall_generate_iv_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_generate_iv_t), ms, sizeof(ms_ecall_generate_iv_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_iv = __in_ms.ms_iv;
	size_t _tmp_iv_len = __in_ms.ms_iv_len;
	size_t _len_iv = _tmp_iv_len;
	uint8_t* _in_iv = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_iv, _len_iv);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_iv != NULL && _len_iv != 0) {
		if ( _len_iv % sizeof(*_tmp_iv) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_iv = (uint8_t*)malloc(_len_iv)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_iv, 0, _len_iv);
	}
	_in_retval = ecall_generate_iv(_in_iv, _tmp_iv_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_iv) {
		if (memcpy_verw_s(_tmp_iv, _len_iv, _in_iv, _len_iv)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_iv) free(_in_iv);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sum(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sum_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sum_t* ms = SGX_CAST(ms_ecall_sum_t*, pms);
	ms_ecall_sum_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_sum_t), ms, sizeof(ms_ecall_sum_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	double* _tmp_data = __in_ms.ms_data;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_data = _tmp_len;
	double* _in_data = NULL;
	double* _tmp_result = __in_ms.ms_result;
	size_t _len_result = sizeof(double);
	double* _in_result = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

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
		_in_data = (double*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (double*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	_in_retval = ecall_sum(_in_data, _tmp_len, _in_result);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_result) {
		if (memcpy_verw_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_data) free(_in_data);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_mean(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_mean_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_mean_t* ms = SGX_CAST(ms_ecall_mean_t*, pms);
	ms_ecall_mean_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_mean_t), ms, sizeof(ms_ecall_mean_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	double* _tmp_data = __in_ms.ms_data;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_data = _tmp_len;
	double* _in_data = NULL;
	double* _tmp_result = __in_ms.ms_result;
	size_t _len_result = sizeof(double);
	double* _in_result = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

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
		_in_data = (double*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (double*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	_in_retval = ecall_mean(_in_data, _tmp_len, _in_result);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_result) {
		if (memcpy_verw_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_data) free(_in_data);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_min(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_min_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_min_t* ms = SGX_CAST(ms_ecall_min_t*, pms);
	ms_ecall_min_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_min_t), ms, sizeof(ms_ecall_min_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	double* _tmp_data = __in_ms.ms_data;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_data = _tmp_len;
	double* _in_data = NULL;
	double* _tmp_result = __in_ms.ms_result;
	size_t _len_result = sizeof(double);
	double* _in_result = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

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
		_in_data = (double*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (double*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	_in_retval = ecall_min(_in_data, _tmp_len, _in_result);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_result) {
		if (memcpy_verw_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_data) free(_in_data);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_max(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_max_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_max_t* ms = SGX_CAST(ms_ecall_max_t*, pms);
	ms_ecall_max_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_max_t), ms, sizeof(ms_ecall_max_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	double* _tmp_data = __in_ms.ms_data;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_data = _tmp_len;
	double* _in_data = NULL;
	double* _tmp_result = __in_ms.ms_result;
	size_t _len_result = sizeof(double);
	double* _in_result = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

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
		_in_data = (double*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (double*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	_in_retval = ecall_max(_in_data, _tmp_len, _in_result);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_result) {
		if (memcpy_verw_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_data) free(_in_data);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_median(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_median_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_median_t* ms = SGX_CAST(ms_ecall_median_t*, pms);
	ms_ecall_median_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_median_t), ms, sizeof(ms_ecall_median_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	double* _tmp_data = __in_ms.ms_data;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_data = _tmp_len;
	double* _in_data = NULL;
	double* _tmp_result = __in_ms.ms_result;
	size_t _len_result = sizeof(double);
	double* _in_result = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

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
		_in_data = (double*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (double*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	_in_retval = ecall_median(_in_data, _tmp_len, _in_result);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_result) {
		if (memcpy_verw_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_data) free(_in_data);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_mode(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_mode_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_mode_t* ms = SGX_CAST(ms_ecall_mode_t*, pms);
	ms_ecall_mode_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_mode_t), ms, sizeof(ms_ecall_mode_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	double* _tmp_data = __in_ms.ms_data;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_data = _tmp_len;
	double* _in_data = NULL;
	double* _tmp_result = __in_ms.ms_result;
	size_t _len_result = sizeof(double);
	double* _in_result = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

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
		_in_data = (double*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (double*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	_in_retval = ecall_mode(_in_data, _tmp_len, _in_result);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_result) {
		if (memcpy_verw_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_data) free(_in_data);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_variance(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_variance_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_variance_t* ms = SGX_CAST(ms_ecall_variance_t*, pms);
	ms_ecall_variance_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_variance_t), ms, sizeof(ms_ecall_variance_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	double* _tmp_data = __in_ms.ms_data;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_data = _tmp_len;
	double* _in_data = NULL;
	double* _tmp_result = __in_ms.ms_result;
	size_t _len_result = sizeof(double);
	double* _in_result = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

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
		_in_data = (double*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (double*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	_in_retval = ecall_variance(_in_data, _tmp_len, _in_result);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_result) {
		if (memcpy_verw_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_data) free(_in_data);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_stddev(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_stddev_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_stddev_t* ms = SGX_CAST(ms_ecall_stddev_t*, pms);
	ms_ecall_stddev_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_stddev_t), ms, sizeof(ms_ecall_stddev_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	double* _tmp_data = __in_ms.ms_data;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_data = _tmp_len;
	double* _in_data = NULL;
	double* _tmp_result = __in_ms.ms_result;
	size_t _len_result = sizeof(double);
	double* _in_result = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

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
		_in_data = (double*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (double*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	_in_retval = ecall_stddev(_in_data, _tmp_len, _in_result);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_result) {
		if (memcpy_verw_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_data) free(_in_data);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_create_report(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_report_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_report_t* ms = SGX_CAST(ms_ecall_create_report_t*, pms);
	ms_ecall_create_report_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_create_report_t), ms, sizeof(ms_ecall_create_report_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_target_info_buf = __in_ms.ms_target_info_buf;
	size_t _len_target_info_buf = 512;
	uint8_t* _in_target_info_buf = NULL;
	uint8_t* _tmp_report_buf = __in_ms.ms_report_buf;
	size_t _len_report_buf = 432;
	uint8_t* _in_report_buf = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_target_info_buf, _len_target_info_buf);
	CHECK_UNIQUE_POINTER(_tmp_report_buf, _len_report_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_target_info_buf != NULL && _len_target_info_buf != 0) {
		if ( _len_target_info_buf % sizeof(*_tmp_target_info_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_target_info_buf = (uint8_t*)malloc(_len_target_info_buf);
		if (_in_target_info_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_target_info_buf, _len_target_info_buf, _tmp_target_info_buf, _len_target_info_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_report_buf != NULL && _len_report_buf != 0) {
		if ( _len_report_buf % sizeof(*_tmp_report_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_report_buf = (uint8_t*)malloc(_len_report_buf)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_report_buf, 0, _len_report_buf);
	}
	_in_retval = ecall_create_report(_in_target_info_buf, _in_report_buf);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_report_buf) {
		if (memcpy_verw_s(_tmp_report_buf, _len_report_buf, _in_report_buf, _len_report_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_target_info_buf) free(_in_target_info_buf);
	if (_in_report_buf) free(_in_report_buf);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[15];
} g_ecall_table = {
	15,
	{
		{(void*)(uintptr_t)sgx_ecall_generate_and_seal_key, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_unseal_key, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_process_stats, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_encrypt_data, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_process_encrypt, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_generate_iv, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sum, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_mean, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_min, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_max, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_median, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_mode, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_variance, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_stddev, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_create_report, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[6][15];
} g_dyn_entry_table = {
	6,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
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

sgx_status_t SGX_CDECL ocall_get_time(uint64_t* t)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_t = sizeof(uint64_t);

	ms_ocall_get_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_time_t);
	void *__tmp = NULL;

	void *__tmp_t = NULL;

	CHECK_ENCLAVE_POINTER(t, _len_t);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (t != NULL) ? _len_t : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_time_t));
	ocalloc_size -= sizeof(ms_ocall_get_time_t);

	if (t != NULL) {
		if (memcpy_verw_s(&ms->ms_t, sizeof(uint64_t*), &__tmp, sizeof(uint64_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_t = __tmp;
		if (_len_t % sizeof(*t) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_t, 0, _len_t);
		__tmp = (void *)((size_t)__tmp + _len_t);
		ocalloc_size -= _len_t;
	} else {
		ms->ms_t = NULL;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (t) {
			if (memcpy_s((void*)t, _len_t, __tmp_t, _len_t)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(void* self)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_self = 1;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(self, _len_self);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (self != NULL) ? _len_self : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	if (self != NULL) {
		if (memcpy_verw_s(&ms->ms_self, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, self, _len_self)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_self);
		ocalloc_size -= _len_self;
	} else {
		ms->ms_self = NULL;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiter = 1;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiter, _len_waiter);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiter != NULL) ? _len_waiter : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	if (waiter != NULL) {
		if (memcpy_verw_s(&ms->ms_waiter, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiter, _len_waiter)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiter);
		ocalloc_size -= _len_waiter;
	} else {
		ms->ms_waiter = NULL;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(void* waiter, void* self)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiter = 1;
	size_t _len_self = 1;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiter, _len_waiter);
	CHECK_ENCLAVE_POINTER(self, _len_self);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiter != NULL) ? _len_waiter : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (self != NULL) ? _len_self : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	if (waiter != NULL) {
		if (memcpy_verw_s(&ms->ms_waiter, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiter, _len_waiter)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiter);
		ocalloc_size -= _len_waiter;
	} else {
		ms->ms_waiter = NULL;
	}

	if (self != NULL) {
		if (memcpy_verw_s(&ms->ms_self, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, self, _len_self)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_self);
		ocalloc_size -= _len_self;
	} else {
		ms->ms_self = NULL;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(void* waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = 1;

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		if (memcpy_verw_s(&ms->ms_waiters, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	if (memcpy_verw_s(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

