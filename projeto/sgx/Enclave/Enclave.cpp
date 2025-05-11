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

const char hospital_public_pem[] =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAzolQ3N45sFIoVZ9Ol4Lw\n"
"mMCtnXyLygscDeKz/cKjdoEN2YexLBTcVlLLZEXv1m3sv16D9mxZrCZtsPeYVLwc\n"
"/i4SYQSLKFpITEqFNHz4i39hqV51/9D1TQNnlSDtLG14jtW+MXeDN4/ZfdPA+tHO\n"
"B/M8H+ODPuT1bDTYtMb0Hzvu18BRHm/H+/U2mcO3c3ldrKZllSJTkeUn301cT+Ql\n"
"atAl+1w23HURhJLe84rxk0pXP+agIZVTwE1iTQZjXtt+jtgBjaq32htA4JJ/tiC7\n"
"CEbIV4jp9PeftMWaXf8OUal5mzilKfIgbfM5Gh9xxJix1Noc6zw3ei2oMuaIVIst\n"
"nGPB/wzwDFG6Ca+6Bo2Gf45w07VzSZAzD8EpLQO++qFW/cEd0/lUIuHHcf9v4aW1\n"
"TIifjgddAmTKC+KaBKuKuhUOsBL4MX9hSxweCmeQF4+dcUo0JWQVsgq0jA0dka0r\n"
"ptFafalHZsBdsnRNzfXiaJxqFQbkCmiK5+Yx11EpnYeXAgMBAAE=\n"
"-----END PUBLIC KEY-----\n";

const char lab_public_pem[] =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAkUbGrtMCHcvHZ6CFioS0\n"
"plpDxLpgiDntyYPCwO2urhJhwXuYE9VEBaYrmZemO8Q/NvMH7OoOIQMyv0dsu/hk\n"
"ywB/ULxk8HoUaOz3N/oFucDHLndTXDQf5Q6okqWuX7mXj57+Lxr4iqUT0Csp8V82\n"
"1MRYdvX67X9DrUk6Fl3ZOd1fO5Ztnhgx7/f6yk/DI5ytj4FuFCFTZcC9aCrWawQ+\n"
"mTwppb+UTt7WlVNwlXbXuhS66mDxu9nvI21a326w5Fih+h7WmdC0UH70/FLx7x3c\n"
"5HZ1vMwPcDEKBKqDVzEpAI0jOWglltRo4eEXUyt3AZHWJdhRajW70bQVRB4mxGHE\n"
"pFJiqvUxItuTAFXl+g4XtoHf9ifn0LpSEZKxEXJcjPwEe793uTsvKpUNnEaiDOMO\n"
"OQLnlJuN3mdZhNW3/XwiUeEfkwEP3fT5jW8aXRj6mQDmwIgpW3v4ZtSbYM/5jys3\n"
"dg3OycBKA3BQ9rdmuloJOKiKdiE6InvWihqGuvnRNFM5AgMBAAE=\n"
"-----END PUBLIC KEY-----\n";


sgx_status_t ecall_create_report(uint8_t* target_info_buf, uint8_t* report_buf) {
    if (!target_info_buf || !report_buf) return SGX_ERROR_INVALID_PARAMETER;

    const sgx_target_info_t* target_info = reinterpret_cast<const sgx_target_info_t*>(target_info_buf);
    sgx_report_t* report = reinterpret_cast<sgx_report_t*>(report_buf);

    sgx_report_data_t report_data = { 0 };
    return sgx_create_report(target_info, &report_data, report);
}


bool verify_signature(const std::string& message, const std::vector<uint8_t>& signature, const char* pem_cstr) {
    char buffer[512];
    snprintf(buffer, sizeof(buffer), "[verify_signature] Message size: %zu, Signature size: %zu\n",
             message.size(), signature.size());
    ocall_printf(buffer);

    // Use raw PEM string directly with -1 size
    BIO* mem = BIO_new_mem_buf((void*)pem_cstr, -1);
    if (!mem) {
        ocall_printf("[verify_signature] Failed to create BIO from PEM string\n");
        return false;
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(mem, nullptr, nullptr, nullptr);
    BIO_free(mem);

    if (!pkey) {
        ocall_printf("[verify_signature] Failed to read public key from BIO\n");
        unsigned long err;
        while ((err = ERR_get_error())) {
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            snprintf(buffer, sizeof(buffer), "[OpenSSL Error] %s\n", err_buf);
            ocall_printf(buffer);
        }
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        ocall_printf("[verify_signature] Failed to create digest context\n");
        EVP_PKEY_free(pkey);
        return false;
    }

    bool valid = (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
                  EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) == 1 &&
                  EVP_DigestVerifyFinal(ctx, signature.data(), signature.size()) == 1);

    if (!valid) {
        ocall_printf("[verify_signature] Signature invalid\n");
        unsigned long err;
        while ((err = ERR_get_error())) {
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            snprintf(buffer, sizeof(buffer), "[OpenSSL Error] %s\n", err_buf);
            ocall_printf(buffer);
        }
    } else {
        ocall_printf("[verify_signature] Signature is valid\n");
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return valid;
}

sgx_status_t ecall_generate_iv(uint8_t* iv, size_t iv_len) {
    if (!iv || iv_len != IV_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    return sgx_read_rand(iv, (uint32_t)iv_len);
}


sgx_status_t ecall_generate_and_seal_key(uint8_t* sealed_data, uint32_t sealed_size) {
    if (!sealed_data || sealed_size < sizeof(sgx_sealed_data_t) + SYM_KEY_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t ret = sgx_read_rand((uint8_t*)&g_sym_key, SYM_KEY_SIZE);
    if (ret != SGX_SUCCESS) return ret;

    g_sym_key_ready = true;
    return sgx_seal_data(0, NULL, SYM_KEY_SIZE, (uint8_t*)&g_sym_key, sealed_size, (sgx_sealed_data_t*)sealed_data);
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
    if (!signed_data || !signature || signature_len != 384){
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

    ocall_printf("[Enclave] Parsed message parts:\n");
    for (size_t i = 0; i < parts.size(); ++i) {
        char buf[256];
        snprintf(buf, sizeof(buf), "  Part %zu: %s\n", i, parts[i].c_str());
        ocall_printf(buf);
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

    // Determine signer and get public key
    std::string signer = parts[1];
    const char* pem_cstr = nullptr;
    if (signer == "hospital") pem_cstr = hospital_public_pem;
    else if (signer == "lab") pem_cstr = lab_public_pem;
    else {
        ocall_printf("[Enclave] Unknown signer ID.\n");
        ocall_printf(signer.c_str());
        ocall_printf("\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    std::vector<uint8_t> sig_vec(signature, signature + signature_len);

    ocall_printf("[Enclave] Verifying signature...\n");
    // Verify signature
    if (!verify_signature(msg_str, sig_vec, pem_cstr)) {
        ocall_printf("[Enclave] Signature verification failed for encrypt.\n");
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

    std::vector<uint8_t> sig1_vec(sig1, sig1 + sig1_len);
    std::vector<uint8_t> sig2_vec(sig2, sig2 + sig2_len);

    bool valid1 = verify_signature(msg_str, sig1_vec, hospital_public_pem);
    bool valid2 = verify_signature(msg_str, sig2_vec, lab_public_pem);

    if (!(valid1 && valid2)) {
        ocall_printf("[Enclave] Signature verification failed.\n");
        return SGX_ERROR_INVALID_SIGNATURE;
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


