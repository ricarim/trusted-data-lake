#include <cstdint>
#include <algorithm>
#include <string>
#include <cctype>
#include <ctime>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <vector>
#include <sstream>
#include "Enclave_t.h"
#include "sgx_tcrypto.h"
#include <cstring>
#include <sstream>
#include <stdint.h>
#include <stdbool.h>
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_report.h"
#include "sgx_utils.h"
#include <map>
#include <numeric>  
#include <cmath>    
#include <openssl/err.h>

#define MY_ERROR_ACCESS_DENIED ((sgx_status_t)0xFFFF0001)
#define SYM_KEY_SIZE 32 
#define IV_SIZE 12       // AES-GCM IV 
#define TAG_SIZE 16      // AES-GCM tag

static sgx_aes_gcm_128bit_key_t g_sym_key;
static bool g_sym_key_ready = false;
std::vector<std::vector<uint8_t>> g_wrapping_keys;
static std::vector<uint8_t> g_wrapped_sk_m;
static int g_expected_keys = 0;


#define SIGNER_HOSPITAL 0
#define SIGNER_LAB 1

static const sgx_ec256_public_t g_pubkey_hospital = {
    .gx = { 0x7a, 0x43, 0xf1, 0xb1, 0x51, 0x96, 0x2e, 0x8d, 0x66, 0x3b, 0xd3, 0x43, 0x66, 0x14, 0x80, 0x50, 0x5a, 0xbe, 0xff, 0x29, 0x86, 0xb6, 0xed, 0x1e, 0x9a, 0x64, 0x9b, 0xe9, 0x09, 0xaf, 0x91, 0x14 },
    .gy = { 0xc4, 0x30, 0xba, 0xb9, 0x5e, 0x3f, 0xa2, 0xea, 0x67, 0x6a, 0x3c, 0x2c, 0x77, 0x56, 0x97, 0xd7, 0xae, 0x51, 0x3f, 0x55, 0xb4, 0x95, 0x48, 0x53, 0xd7, 0xc7, 0xb1, 0x92, 0xab, 0x72, 0xe7, 0xe5 }
};

static const sgx_ec256_public_t g_pubkey_lab = {
    .gx = { 0x5f, 0x51, 0x33, 0x8e, 0x8c, 0x26, 0x3a, 0x2c, 0xa2, 0xef, 0x31, 0x8b, 0x86, 0x8a, 0xad, 0x0e, 0xd3, 0x3c, 0x52, 0x7b, 0xfc, 0xd5, 0x9a, 0x3b, 0x3a, 0xaa, 0xd4, 0x2a, 0x89, 0xb6, 0x66, 0x8f },
    .gy = { 0x1b, 0xad, 0x6f, 0x09, 0x27, 0x47, 0x58, 0xb8, 0x6c, 0x18, 0x87, 0x4f, 0xac, 0x91, 0x0b, 0x8d, 0xb8, 0x7f, 0x69, 0x1c, 0xd2, 0x29, 0x0a, 0x09, 0x0a, 0x37, 0xc1, 0x89, 0xa1, 0x31, 0xcb, 0x55 }
};

sgx_status_t ecall_create_report(uint8_t* target_info_buf, uint8_t* report_buf) {
    if (!target_info_buf || !report_buf) return SGX_ERROR_INVALID_PARAMETER;

    const sgx_target_info_t* target_info = reinterpret_cast<const sgx_target_info_t*>(target_info_buf);
    sgx_report_t* report = reinterpret_cast<sgx_report_t*>(report_buf);

    sgx_report_data_t report_data = { 0 };
    return sgx_create_report(target_info, &report_data, report);
}



int ecc_verify(uint8_t* data, size_t len, sgx_ec256_signature_t* sig,int signer_type) {
    if (!data || !sig || (signer_type != SIGNER_HOSPITAL && signer_type != SIGNER_LAB)) {
        return 0; 
    }
    const sgx_ec256_public_t* pubkey = nullptr;

    
    if (signer_type == SIGNER_HOSPITAL)
        pubkey = &g_pubkey_hospital;
    else if (signer_type == SIGNER_LAB)
        pubkey = &g_pubkey_lab;

    sgx_ecc_state_handle_t ctx;
    sgx_status_t status = sgx_ecc256_open_context(&ctx);
    if (status != SGX_SUCCESS) return 0;

    uint8_t result = SGX_EC_INVALID_SIGNATURE;
    status = sgx_ecdsa_verify(data, (uint32_t)len, pubkey, sig, &result, ctx);
    sgx_ecc256_close_context(ctx);

    return (status == SGX_SUCCESS && result == SGX_EC_VALID);
}


sgx_status_t ecall_generate_iv(uint8_t* iv, size_t iv_len) {
    if (!iv || iv_len != IV_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    return sgx_read_rand(iv, (uint32_t)iv_len);
}




sgx_status_t ecall_generate_master_key(int expected_keys) {
    sgx_status_t ret = sgx_read_rand((uint8_t*)&g_sym_key, SYM_KEY_SIZE);
    if (ret != SGX_SUCCESS) return ret;

    g_sym_key_ready = true;
    g_wrapping_keys.clear();  
    g_expected_keys = expected_keys;

    return SGX_SUCCESS;
}

sgx_status_t ecall_prepare_unwrapping(const uint8_t* wrapped_data, uint32_t wrapped_len) {
    if (!wrapped_data || wrapped_len == 0)
        return SGX_ERROR_INVALID_PARAMETER;

    g_wrapped_sk_m.assign(wrapped_data, wrapped_data + wrapped_len);
    g_wrapping_keys.clear(); 
    g_sym_key_ready = false;

    return SGX_SUCCESS;
}

sgx_status_t ecall_add_wrapping_key(uint8_t* key, uint32_t len) {
    if (!key || len != SYM_KEY_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;
    if (g_wrapping_keys.size() >= 10)
        return SGX_ERROR_OUT_OF_MEMORY;

    g_wrapping_keys.emplace_back(key, key + len);
    return SGX_SUCCESS;
}



sgx_status_t ecall_get_wrapped_master_key(uint8_t* out, uint32_t max_len, uint32_t* used_len) {
    if (g_wrapping_keys.size() < static_cast<size_t>(g_expected_keys))
        return SGX_ERROR_BUSY;
    if (!g_sym_key_ready || !out || !used_len)
        return SGX_ERROR_INVALID_PARAMETER;

    std::vector<uint8_t> sk_m(g_sym_key, g_sym_key + SYM_KEY_SIZE);
    std::vector<uint8_t> wrapped = recursive_wrap(g_wrapping_keys, sk_m);

    if (wrapped.size() > max_len)
        return SGX_ERROR_INVALID_PARAMETER;

    memcpy(out, wrapped.data(), wrapped.size());
    *used_len = static_cast<uint32_t>(wrapped.size());
    return SGX_SUCCESS;
}

sgx_status_t ecall_unwrap_master_key()
{
    if (g_wrapped_sk_m.empty())               return SGX_ERROR_INVALID_STATE;
    if (g_wrapping_keys.empty())              return SGX_ERROR_BUSY;

    std::vector<uint8_t> blob = g_wrapped_sk_m;

    // apply keys in order of arrival (sk1 .. skN)
    for (const auto& key : g_wrapping_keys) {
        std::vector<uint8_t> plain;
        sgx_status_t ret = aesgcm_decrypt(key.data(), blob.data(),
                                          blob.size(), plain);
        if (ret != SGX_SUCCESS)               return ret;
        blob.swap(plain);
    }

    if (blob.size() != SYM_KEY_SIZE)          return SGX_ERROR_UNEXPECTED;

    memcpy(g_sym_key, blob.data(), SYM_KEY_SIZE);
    g_sym_key_ready = true;
    return SGX_SUCCESS;
}


std::vector<uint8_t> recursive_wrap(
    const std::vector<std::vector<uint8_t>>& keys,
    const std::vector<uint8_t>& master_key
) {
    std::vector<uint8_t> wrapped = master_key;

    for (auto it = keys.rbegin(); it != keys.rend(); ++it) {
        const std::vector<uint8_t>& key = *it;

        std::vector<uint8_t> iv(12);
        sgx_read_rand(iv.data(), 12);

        std::vector<uint8_t> ct(wrapped.size());
        sgx_aes_gcm_128bit_tag_t tag;

        sgx_rijndael128GCM_encrypt(
            reinterpret_cast<const sgx_aes_gcm_128bit_key_t*>(key.data()),
            wrapped.data(), static_cast<uint32_t>(wrapped.size()),
            ct.data(),
            iv.data(), static_cast<uint32_t>(iv.size()),
            nullptr, 0,
            &tag
        );

        wrapped.clear();
        wrapped.insert(wrapped.end(), iv.begin(), iv.end());
        wrapped.insert(wrapped.end(), tag.begin(), tag.end());
        wrapped.insert(wrapped.end(), ct.begin(), ct.end());
    }

    return wrapped;
}



sgx_status_t ecall_unseal_key(uint8_t* sealed_data, uint32_t sealed_size) {
    if (!sealed_data || sealed_size == 0) return SGX_ERROR_INVALID_PARAMETER;

    sgx_sealed_data_t* sdata = (sgx_sealed_data_t*)sealed_data;
    uint32_t plaintext_size = sgx_get_encrypt_txt_len(sdata);
    if (plaintext_size != SYM_KEY_SIZE) return SGX_ERROR_UNEXPECTED;

    sgx_status_t ret = sgx_unseal_data(sdata, NULL, 0, (uint8_t*)&g_sym_key, &plaintext_size);
    if (ret == SGX_SUCCESS) g_sym_key_ready = true;
    return ret;
}



sgx_status_t ecall_encrypt_data(uint8_t* plaintext, size_t plaintext_len,
                                uint8_t* iv, size_t iv_len,
                                uint8_t* ciphertext, uint8_t* mac) {
    if (!g_sym_key_ready || !plaintext || !iv || !ciphertext || !mac)
        return SGX_ERROR_INVALID_PARAMETER;

    if (iv_len != IV_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t ret = sgx_rijndael128GCM_encrypt(
        (const sgx_aes_gcm_128bit_key_t*)g_sym_key,  // symmetric key
        plaintext, (uint32_t)plaintext_len,          // input data
        ciphertext,                                  // output buffer
        iv, IV_SIZE,                                 // initialization vector
        NULL, 0,                                     // optional AAD (not used)
        (sgx_aes_gcm_128bit_tag_t*)mac               // output: authentication tag
    );

    return ret;
}

sgx_status_t ecall_decrypt_data(const uint8_t* ciphertext, size_t ciphertext_len,
                                const uint8_t* iv, size_t iv_len,
                                const uint8_t* mac,
                                uint8_t* plaintext) {
    if (!g_sym_key_ready || !ciphertext || !iv || !mac || !plaintext)
        return SGX_ERROR_INVALID_PARAMETER;

    if (iv_len != IV_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t ret = sgx_rijndael128GCM_decrypt(
        (const sgx_aes_gcm_128bit_key_t*)g_sym_key,
        ciphertext, (uint32_t)ciphertext_len,
        plaintext,
        iv, IV_SIZE,
        NULL, 0,
        (const sgx_aes_gcm_128bit_tag_t*)mac
    );

    return ret;
}



using Record = std::map<std::string, std::string>;

std::vector<Record> parse_csv(const std::string& csv_data) {
    std::vector<Record> records;
    std::istringstream ss(csv_data);
    std::string line;

    std::getline(ss, line);
    std::vector<std::string> headers;
    std::istringstream header_stream(line);
    std::string column;
    while (std::getline(header_stream, column, ',')) {
        headers.push_back(column);
    }

    while (std::getline(ss, line)) {
        std::istringstream ls(line);
        std::string field;
        Record r;
        size_t i = 0;
        while (std::getline(ls, field, ',') && i < headers.size()) {
            r[headers[i]] = field;
            ++i;
        }
        records.push_back(r);
    }

    return records;
}

sgx_status_t ecall_sum(double* data, size_t len, double* result) {
    if (!data || !result) return SGX_ERROR_INVALID_PARAMETER;
    std::vector<double> v(data, data + len);
    *result = std::accumulate(v.begin(), v.end(), 0.0);
    return SGX_SUCCESS;
}

sgx_status_t ecall_mean(double* data, size_t len, double* result) {
    if (!data || !result || len == 0) return SGX_ERROR_INVALID_PARAMETER;
    std::vector<double> v(data, data + len);
    double sum = std::accumulate(v.begin(), v.end(), 0.0);
    *result = sum / len;
    return SGX_SUCCESS;
}

sgx_status_t ecall_min(double* data, size_t len, double* result) {
    if (!data || !result || len == 0) return SGX_ERROR_INVALID_PARAMETER;
    std::vector<double> v(data, data + len);
    *result = *std::min_element(v.begin(), v.end());
    return SGX_SUCCESS;
}

sgx_status_t ecall_max(double* data, size_t len, double* result) {
    if (!data || !result || len == 0) return SGX_ERROR_INVALID_PARAMETER;
    std::vector<double> v(data, data + len);
    *result = *std::max_element(v.begin(), v.end());
    return SGX_SUCCESS;
}

sgx_status_t ecall_median(double* data, size_t len, double* result) {
    if (!data || !result || len == 0) return SGX_ERROR_INVALID_PARAMETER;
    std::vector<double> v(data, data + len);
    std::sort(v.begin(), v.end());
    if (len % 2 == 0)
        *result = (v[len/2 - 1] + v[len/2]) / 2.0;
    else
        *result = v[len/2];
    return SGX_SUCCESS;
}

sgx_status_t ecall_mode(double* data, size_t len, double* result) {
    if (!data || !result || len == 0) return SGX_ERROR_INVALID_PARAMETER;
    std::vector<double> v(data, data + len);
    std::map<double, int> freq;
    for (double val : v) freq[val]++;
    auto max_it = std::max_element(freq.begin(), freq.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });
    *result = max_it->first;
    return SGX_SUCCESS;
}

sgx_status_t ecall_mode_string(const char** data, size_t len, char* result_buf, size_t buf_size) {
    if (!data || len == 0 || !result_buf || buf_size == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    std::map<std::string, int> freq;
    for (size_t i = 0; i < len; ++i) {
        freq[data[i]]++;
    }

    std::string mode;
    int max_count = 0;
    for (const auto& kv : freq) {
        if (kv.second > max_count) {
            max_count = kv.second;
            mode = kv.first;
        }
    }

    if (mode.empty() || mode.size() + 1 > buf_size) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    strncpy(result_buf, mode.c_str(), buf_size);
    return SGX_SUCCESS;
}

sgx_status_t ecall_variance(double* data, size_t len, double* result) {
    if (!data || !result || len == 0) return SGX_ERROR_INVALID_PARAMETER;
    std::vector<double> v(data, data + len);
    double m = std::accumulate(v.begin(), v.end(), 0.0) / len;
    double sum_sq = 0.0;
    for (double val : v) sum_sq += (val - m) * (val - m);
    *result = sum_sq / len;
    return SGX_SUCCESS;
}

sgx_status_t ecall_stddev(double* data, size_t len, double* result) {
    sgx_status_t ret = ecall_variance(data, len, result);
    if (ret != SGX_SUCCESS) return ret;
    *result = std::sqrt(*result);
    return SGX_SUCCESS;
}


sgx_status_t ecall_process_encrypt(
    const char* signed_data,
    uint32_t signed_data_len,
    const uint8_t* signature,
    uint32_t signature_len
) {
    if (!signed_data || !signature || signature_len != sizeof(sgx_ec256_signature_t)){
        ocall_printf("[Enclave] Invalid input: null or signature size mismatch\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    std::string msg_str(signed_data, signed_data_len);
    ocall_printf("[Enclave] Received signed data:\n");
    ocall_printf(msg_str.c_str());
    ocall_printf("\n");

    // Split the signed message
    std::vector<std::string> parts;
    std::istringstream iss(msg_str);
    std::string token;
    while (std::getline(iss, token, '|')) {
        parts.push_back(token);
    }

    if (parts.size() != 5) {
        ocall_printf("[Enclave] Invalid encrypt message format. Expected 5 parts.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    std::string signer = parts[1];
    int signer_type = -1;
    if (signer == "hospital") signer_type = SIGNER_HOSPITAL;
    else if (signer == "lab") signer_type = SIGNER_LAB;
    else {
        ocall_printf("[Enclave] Unknown signer.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Parse and validate timestamp
    uint64_t received_ts;
    try {
        received_ts = std::stoull(parts[4]);
    } catch (...) {
        ocall_printf("[Enclave] Failed to parse timestamp.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint64_t now = 0;
    ocall_get_time(&now);

    if (std::abs((int64_t)(now - received_ts)) > 300) {
        ocall_printf("[Enclave] Timestamp is too old or in the future. Possible replay.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }


    const sgx_ec256_signature_t* sig = reinterpret_cast<const sgx_ec256_signature_t*>(signature);

    // Call ecc_verify
    if (!ecc_verify((uint8_t*)signed_data, signed_data_len, (sgx_ec256_signature_t*)sig, signer_type)) {
        ocall_printf("[Enclave] Signature verification failed.\n");
        return SGX_ERROR_INVALID_SIGNATURE;
    }


    ocall_printf("[Enclave] Signature and timestamp are valid. Encrypt approved.\n");
    return SGX_SUCCESS;
}


enum StatOp {
    STAT_SUM = 1,
    STAT_MEAN,
    STAT_MIN,
    STAT_MAX,
    STAT_MEDIAN,
    STAT_MODE,
    STAT_VARIANCE,
    STAT_STDDEV
};

sgx_status_t ecall_process_stats(
    const char* signed_data,
    uint32_t signed_data_len,
    const uint8_t* sig1,
    uint32_t sig1_len,
    const uint8_t* sig2,
    uint32_t sig2_len,
    const uint8_t* ciphertext,
    uint32_t ciphertext_len,
    const uint8_t* iv,
    uint32_t iv_len,
    const uint8_t* mac,
    const char* column_name,
    int op_code,
    char* out_mode_buf, 
    uint32_t out_mode_buf_len,
    double* result
){
    if (!signed_data || !sig1 || !sig2 || !ciphertext || !iv || !mac || !result || !column_name)
    return SGX_ERROR_INVALID_PARAMETER;

    if (!g_sym_key_ready) {
        ocall_printf("[Enclave] Symmetric key not ready.\n");
        return SGX_ERROR_UNEXPECTED;
    }

    std::string msg_str(signed_data, signed_data_len);

    // Verify timestamp
    std::vector<std::string> parts;
    std::istringstream iss(msg_str);
    std::string token;
    while (std::getline(iss, token, '|')) {
        parts.push_back(token);
    }

    if (parts.size() != 6) {
        ocall_printf("[Enclave] Invalid signed message format. Expected 6 parts.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint64_t received_ts;
    try {
        received_ts = std::stol(parts[5]);
    } catch (...) {
        ocall_printf("[Enclave] Failed to parse timestamp.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint64_t now = 0;
    ocall_get_time(&now);
    if (std::abs((int64_t)(now - received_ts)) > 300) { // 5 min tolerance
        ocall_printf("[Enclave] Timestamp out of range. Possible replay attack.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    const sgx_ec256_signature_t* sig_hospital = reinterpret_cast<const sgx_ec256_signature_t*>(sig1);
    const sgx_ec256_signature_t* sig_lab = reinterpret_cast<const sgx_ec256_signature_t*>(sig2);

    bool valid_hosp = ecc_verify((uint8_t*)msg_str.data(), msg_str.size(), const_cast<sgx_ec256_signature_t*>(sig_hospital), SIGNER_HOSPITAL);
    bool valid_lab  = ecc_verify((uint8_t*)msg_str.data(), msg_str.size(), const_cast<sgx_ec256_signature_t*>(sig_lab), SIGNER_LAB);

    if (!(valid_hosp && valid_lab)) {
        ocall_printf("[Enclave] Signature verification failed for one or both parties.\n");
        return MY_ERROR_ACCESS_DENIED;
    }

    ocall_printf("[Enclave] Both signatures verified successfully.\n");

    std::vector<uint8_t> plaintext(ciphertext_len);
    sgx_status_t ret = sgx_rijndael128GCM_decrypt(
        &g_sym_key,
        ciphertext, ciphertext_len,
        plaintext.data(),
        iv, iv_len,
        nullptr, 0,
        (const sgx_aes_gcm_128bit_tag_t*)mac
    );

    if (ret != SGX_SUCCESS) {
        ocall_printf("[Enclave] Decryption failed\n");
        return ret;
    }

    std::string csv((char*)plaintext.data(), plaintext.size());
    std::vector<std::map<std::string, std::string>> records;
    std::istringstream ss(csv);
    std::string line;

    std::getline(ss, line);
    std::vector<std::string> headers;
    std::istringstream header_stream(line);
    std::string column;
    while (std::getline(header_stream, column, ',')) headers.push_back(column);

    while (std::getline(ss, line)) {
        std::istringstream ls(line);
        std::string field;
        std::map<std::string, std::string> r;
        size_t i = 0;
        while (std::getline(ls, field, ',') && i < headers.size()) {
            r[headers[i]] = field;
            ++i;
        }
        records.push_back(r);
    }

    std::vector<double> numbers;
    std::vector<std::string> strings;

    for (const auto& row : records) {
        auto it = row.find(column_name);
        if (it != row.end()) {
            try {
                double val = std::stod(it->second);
                numbers.push_back(val);
            } catch (...) {
                strings.push_back(it->second);
            }
        }
    }

    if (numbers.empty() && strings.empty()) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Choose and execute statistical operation
    switch (op_code) {
        case STAT_MEAN:
            return numbers.empty() ? SGX_ERROR_INVALID_PARAMETER : ecall_mean(numbers.data(), numbers.size(), result);
        case STAT_VARIANCE:
            return numbers.empty() ? SGX_ERROR_INVALID_PARAMETER : ecall_variance(numbers.data(), numbers.size(), result);
        case STAT_STDDEV:
            return numbers.empty() ? SGX_ERROR_INVALID_PARAMETER : ecall_stddev(numbers.data(), numbers.size(), result);
        case STAT_SUM:
            return numbers.empty() ? SGX_ERROR_INVALID_PARAMETER : ecall_sum(numbers.data(), numbers.size(), result);
        case STAT_MIN:
            return numbers.empty() ? SGX_ERROR_INVALID_PARAMETER : ecall_min(numbers.data(), numbers.size(), result);
        case STAT_MAX:
            return numbers.empty() ? SGX_ERROR_INVALID_PARAMETER : ecall_max(numbers.data(), numbers.size(), result);
        case STAT_MEDIAN:
            return numbers.empty() ? SGX_ERROR_INVALID_PARAMETER : ecall_median(numbers.data(), numbers.size(), result);
        case STAT_MODE:
            if (!numbers.empty()) {
                return ecall_mode(numbers.data(), numbers.size(), result);
            } else if (!strings.empty()) {
                std::vector<const char*> cstrs;
                for (const auto& s : strings) cstrs.push_back(s.c_str());

                char mode_buf[64] = {0};
                sgx_status_t ret = ecall_mode_string(cstrs.data(), cstrs.size(), mode_buf, sizeof(mode_buf));
                memcpy(out_mode_buf, mode_buf, std::min(strlen(mode_buf)+1, static_cast<size_t>(out_mode_buf_len)));
                return ret;
            } else {
                return SGX_ERROR_INVALID_PARAMETER;
            }
        default:
            return SGX_ERROR_INVALID_PARAMETER;
    }
}


