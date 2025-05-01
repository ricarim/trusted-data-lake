#include <string>
#include <cctype>
#include <vector>
#include <sstream>
#include "Enclave_t.h"
#include "sgx_tcrypto.h"
#include <cstring>
#include <sstream>
#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <stdbool.h>
#include <map>
#include <numeric>  
#include <cmath>    

#define MY_ERROR_ACCESS_DENIED ((sgx_status_t)0xFFFF0001)
#define RSA3072_KEY_SIZE 384
#define RSA3072_EXP_SIZE 4
#define SYM_KEY_SIZE 32 
#define IV_SIZE 12       // AES-GCM IV 
#define TAG_SIZE 16      // AES-GCM tag


static sgx_aes_gcm_128bit_key_t g_sym_key;
static bool g_sym_key_ready = false;

typedef uint8_t sgx_rsa3072_signature_t[RSA3072_KEY_SIZE];


const uint8_t HOSPITAL_PUB_N[] = {
    0xCE, 0x89, 0x50, 0xDC, 0xDE, 0x39, 0xB0, 0x52,
    0x28, 0x55, 0x9F, 0x4E, 0x97, 0x82, 0xF0, 0x98,
    0xC0, 0xAD, 0x9D, 0x7C, 0x8B, 0xCA, 0x0B, 0x1C,
    0x0D, 0xE2, 0xB3, 0xFD, 0xC2, 0xA3, 0x76, 0x81,
    0x0D, 0xD9, 0x87, 0xB1, 0x2C, 0x14, 0xDC, 0x56,
    0x52, 0xCB, 0x64, 0x45, 0xEF, 0xD6, 0x6D, 0xEC,
    0xBF, 0x5E, 0x83, 0xF6, 0x6C, 0x59, 0xAC, 0x26,
    0x6D, 0xB0, 0xF7, 0x98, 0x54, 0xBC, 0x1C, 0xFE,
    0x2E, 0x12, 0x61, 0x04, 0x8B, 0x28, 0x5A, 0x48,
    0x4C, 0x4A, 0x85, 0x34, 0x7C, 0xF8, 0x8B, 0x7F,
    0x61, 0xA9, 0x5E, 0x75, 0xFF, 0xD0, 0xF5, 0x4D,
    0x03, 0x67, 0x95, 0x20, 0xED, 0x2C, 0x6D, 0x78,
    0x8E, 0xD5, 0xBE, 0x31, 0x77, 0x83, 0x37, 0x8F,
    0xD9, 0x7D, 0xD3, 0xC0, 0xFA, 0xD1, 0xCE, 0x07,
    0xF3, 0x3C, 0x1F, 0xE3, 0x83, 0x3E, 0xE4, 0xF5,
    0x6C, 0x34, 0xD8, 0xB4, 0xC6, 0xF4, 0x1F, 0x3B,
    0xEE, 0xD7, 0xC0, 0x51, 0x1E, 0x6F, 0xC7, 0xFB,
    0xF5, 0x36, 0x99, 0xC3, 0xB7, 0x73, 0x79, 0x5D,
    0xAC, 0xA6, 0x65, 0x95, 0x22, 0x53, 0x91, 0xE5,
    0x27, 0xDF, 0x4D, 0x5C, 0x4F, 0xE4, 0x25, 0x6A,
    0xD0, 0x25, 0xFB, 0x5C, 0x36, 0xDC, 0x75, 0x11,
    0x84, 0x92, 0xDE, 0xF3, 0x8A, 0xF1, 0x93, 0x4A,
    0x57, 0x3F, 0xE6, 0xA0, 0x21, 0x95, 0x53, 0xC0,
    0x4D, 0x62, 0x4D, 0x06, 0x63, 0x5E, 0xDB, 0x7E,
    0x8E, 0xD8, 0x01, 0x8D, 0xAA, 0xB7, 0xDA, 0x1B,
    0x40, 0xE0, 0x92, 0x7F, 0xB6, 0x20, 0xBB, 0x08,
    0x46, 0xC8, 0x57, 0x88, 0xE9, 0xF4, 0xF7, 0x9F,
    0xB4, 0xC5, 0x9A, 0x5D, 0xFF, 0x0E, 0x51, 0xA9,
    0x79, 0x9B, 0x38, 0xA5, 0x29, 0xF2, 0x20, 0x6D,
    0xF3, 0x39, 0x1A, 0x1F, 0x71, 0xC4, 0x98, 0xB1,
    0xD4, 0xDA, 0x1C, 0xEB, 0x3C, 0x37, 0x7A, 0x2D,
    0xA8, 0x32, 0xE6, 0x88, 0x54, 0x8B, 0x2D, 0x9C,
    0x63, 0xC1, 0xFF, 0x0C, 0xF0, 0x0C, 0x51, 0xBA,
    0x09, 0xAF, 0xBA, 0x06, 0x8D, 0x86, 0x7F, 0x8E,
    0x70, 0xD3, 0xB5, 0x73, 0x49, 0x90, 0x33, 0x0F,
    0xC1, 0x29, 0x2D, 0x03, 0xBE, 0xFA, 0xA1, 0x56,
    0xFD, 0xC1, 0x1D, 0xD3, 0xF9, 0x54, 0x22, 0xE1,
    0xC7, 0x71, 0xFF, 0x6F, 0xE1, 0xA5, 0xB5, 0x4C,
    0x88, 0x9F, 0x8E, 0x07, 0x5D, 0x02, 0x64, 0xCA,
    0x0B, 0xE2, 0x9A, 0x04, 0xAB, 0x8A, 0xBA, 0x15,
    0x0E, 0xB0, 0x12, 0xF8, 0x31, 0x7F, 0x61, 0x4B,
    0x1C, 0x1E, 0x0A, 0x67, 0x90, 0x17, 0x8F, 0x9D,
    0x71, 0x4A, 0x34, 0x25, 0x64, 0x15, 0xB2, 0x0A,
    0xB4, 0x8C, 0x0D, 0x1D, 0x91, 0xAD, 0x2B, 0xA6,
    0xD1, 0x5A, 0x7D, 0xA9, 0x47, 0x66, 0xC0, 0x5D,
    0xB2, 0x74, 0x4D, 0xCD, 0xF5, 0xE2, 0x68, 0x9C,
    0x6A, 0x15, 0x06, 0xE4, 0x0A, 0x68, 0x8A, 0xE7,
    0xE6, 0x31, 0xD7, 0x51, 0x29, 0x9D, 0x87, 0x97
};


static const uint8_t HOSPITAL_PUB_E[4] = {
    0x01, 0x00, 0x01, 0x00  // 65537 in little-endian for SGX
};

static const uint8_t LAB_PUB_N[384] = {
    0x91, 0x46, 0xc6, 0xae, 0xd3, 0x02, 0x1d, 0xcb, 0xc7, 0x67, 0xa0, 0x85, 0x8a, 0x84, 0xb4, 0xa6,
    0x5a, 0x43, 0xc4, 0xba, 0x60, 0x88, 0x39, 0xed, 0xc9, 0x83, 0xc2, 0xc0, 0xed, 0xae, 0xae, 0x12,
    0x61, 0xc1, 0x7b, 0x98, 0x13, 0xd5, 0x44, 0x05, 0xa6, 0x2b, 0x99, 0x97, 0xa6, 0x3b, 0xc4, 0x3f,
    0x36, 0xf3, 0x07, 0xec, 0xea, 0x0e, 0x21, 0x03, 0x32, 0xbf, 0x47, 0x6c, 0xbb, 0xf8, 0x64, 0xcb,
    0x00, 0x7f, 0x50, 0xbc, 0x64, 0xf0, 0x7a, 0x14, 0x68, 0xec, 0xf7, 0x37, 0xfa, 0x05, 0xb9, 0xc0,
    0xc7, 0x2e, 0x77, 0x53, 0x5c, 0x34, 0x1f, 0xe5, 0x0e, 0xa8, 0x92, 0xa5, 0xae, 0x5f, 0xb9, 0x97,
    0x8f, 0x9e, 0xfe, 0x2f, 0x1a, 0xf8, 0x8a, 0xa5, 0x13, 0xd0, 0x2b, 0x29, 0xf1, 0x5f, 0x36, 0xd4,
    0xc4, 0x58, 0x76, 0xf5, 0xfa, 0xed, 0x7f, 0x43, 0xad, 0x49, 0x3a, 0x16, 0x5d, 0xd9, 0x39, 0xdd,
    0x5f, 0x3b, 0x96, 0x6d, 0x9e, 0x18, 0x31, 0xef, 0xf7, 0xfa, 0xca, 0x4f, 0xc3, 0x23, 0x9c, 0xad,
    0x8f, 0x81, 0x6e, 0x14, 0x21, 0x53, 0x65, 0xc0, 0xbd, 0x68, 0x2a, 0xd6, 0x6b, 0x04, 0x3e, 0x99,
    0x3c, 0x29, 0xa5, 0xbf, 0x94, 0x4e, 0xde, 0xd6, 0x95, 0x53, 0x70, 0x95, 0x76, 0xd7, 0xba, 0x14,
    0xba, 0xea, 0x60, 0xf1, 0xbb, 0xd9, 0xef, 0x23, 0x6d, 0x5a, 0xdf, 0x6e, 0xb0, 0xe4, 0x58, 0xa1,
    0xfa, 0x1e, 0xd6, 0x99, 0xd0, 0xb4, 0x50, 0x7e, 0xf4, 0xfc, 0x52, 0xf1, 0xef, 0x1d, 0xdc, 0xe4,
    0x76, 0x75, 0xbc, 0xcc, 0x0f, 0x70, 0x31, 0x0a, 0x04, 0xaa, 0x83, 0x57, 0x31, 0x29, 0x00, 0x8d,
    0x23, 0x39, 0x68, 0x25, 0x96, 0xd4, 0x68, 0xe1, 0xe1, 0x17, 0x53, 0x2b, 0x77, 0x01, 0x91, 0xd6,
    0x25, 0xd8, 0x51, 0x6a, 0x35, 0xbb, 0xd1, 0xb4, 0x15, 0x44, 0x1e, 0x26, 0xc4, 0x61, 0xc4, 0xa4,
    0x52, 0x62, 0xaa, 0xf5, 0x31, 0x22, 0xdb, 0x93, 0x00, 0x55, 0xe5, 0xfa, 0x0e, 0x17, 0xb6, 0x81,
    0xdf, 0xf6, 0x27, 0xe7, 0xd0, 0xba, 0x52, 0x11, 0x92, 0xb1, 0x11, 0x72, 0x5c, 0x8c, 0xfc, 0x04,
    0x7b, 0xbf, 0x77, 0xb9, 0x3b, 0x2f, 0x2a, 0x95, 0x0d, 0x9c, 0x46, 0xa2, 0x0c, 0xe3, 0x0e, 0x39,
    0x02, 0xe7, 0x94, 0x9b, 0x8d, 0xde, 0x67, 0x59, 0x84, 0xd5, 0xb7, 0xfd, 0x7c, 0x22, 0x51, 0xe1,
    0x1f, 0x93, 0x01, 0x0f, 0xdd, 0xf4, 0xf9, 0x8d, 0x6f, 0x1a, 0x5d, 0x18, 0xfa, 0x99, 0x00, 0xe6,
    0xc0, 0x88, 0x29, 0x5b, 0x7b, 0xf8, 0x66, 0xd4, 0x9b, 0x60, 0xcf, 0xf9, 0x8f, 0x2b, 0x37, 0x76,
    0x0d, 0xce, 0xc9, 0xc0, 0x4a, 0x03, 0x70, 0x50, 0xf6, 0xb7, 0x66, 0xba, 0x5a, 0x09, 0x38, 0xa8,
    0x8a, 0x76, 0x21, 0x3a, 0x22, 0x7b, 0xd6, 0x8a, 0x1a, 0x86, 0xba, 0xf9, 0xd1, 0x34, 0x53, 0x39
};

static const uint8_t LAB_PUB_E[4] = {
    0x01, 0x00, 0x01, 0x00
};

typedef enum {
    SIGNER_HOSPITAL = 0,
    SIGNER_LAB = 1
} signer_t;


sgx_status_t ecall_generate_iv(uint8_t* iv, size_t iv_len) {
    if (!iv || iv_len != IV_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    return sgx_read_rand(iv, (uint32_t)iv_len);
}

sgx_status_t ecall_verify_signature(
    uint8_t* data,
    size_t data_len,
    uint8_t* signature,
    size_t sig_len,
    int signer_type,
    int* is_valid
) {
    if (!data || !signature || !is_valid)
        return SGX_ERROR_INVALID_PARAMETER;

    if (sig_len != SGX_RSA3072_KEY_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    const uint8_t* pub_n = nullptr;
    const uint8_t* pub_e = nullptr;

    switch (signer_type) {
        case SIGNER_HOSPITAL:
            pub_n = HOSPITAL_PUB_N;
            pub_e = HOSPITAL_PUB_E;
            break;
        case SIGNER_LAB:
            pub_n = LAB_PUB_N;
            pub_e = LAB_PUB_E;
            break;
        default:
            return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_rsa3072_public_key_t* pub_key = nullptr;
    sgx_status_t ret = sgx_create_rsa_pub1_key(
        SGX_RSA3072_KEY_SIZE,
        SGX_RSA3072_PUB_EXP_SIZE,
        pub_n,
        pub_e,
        (void**)&pub_key
    );
    if (ret != SGX_SUCCESS)
        return ret;

    sgx_rsa_result_t valid = SGX_RSA_INVALID_SIGNATURE;
    ret = sgx_rsa3072_verify(
        data,
        (uint32_t)data_len,
        pub_key,
        (const sgx_rsa3072_signature_t*)signature,
        &valid
    );

    sgx_free_rsa_key(pub_key, SGX_RSA_PUBLIC_KEY,
                     SGX_RSA3072_KEY_SIZE, SGX_RSA3072_PUB_EXP_SIZE);

    *is_valid = (valid == SGX_RSA_VALID);
    return ret;
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


sgx_status_t base64_decode_to_bytes(const char* b64_input, uint8_t* output, size_t output_size, size_t* decoded_len) {
    if (!b64_input || !output || !decoded_len)
        return SGX_ERROR_INVALID_PARAMETER;

    const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int val = 0, valb = -8;
    size_t out_len = 0;

    for (size_t i = 0; b64_input[i] != '\0'; ++i) {
        char c = b64_input[i];
        if (c == '=' || isspace(c)) continue;

        const char* p = strchr(base64_chars, c);
        if (!p) return SGX_ERROR_INVALID_PARAMETER;

        val = (val << 6) + (p - base64_chars);
        valb += 6;
        if (valb >= 0) {
            if (out_len >= output_size) return SGX_ERROR_INVALID_PARAMETER;
            output[out_len++] = (uint8_t)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }

    *decoded_len = out_len;
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
    const char* signed_cmd,      
    const char* signature_b64,    
    int signer_type,            
    uint8_t* ciphertext, size_t ciphertext_len,
    uint8_t* iv, size_t iv_len,
    uint8_t* mac,
    int operation_type,
    double* result
) {

    if (!g_sym_key_ready || !ciphertext || !iv || !mac || !result)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t signature_bin[SGX_RSA3072_KEY_SIZE] = {0};
    size_t sig_len = 0;
    sgx_status_t ret = base64_decode_to_bytes(signature_b64, signature_bin, sizeof(signature_bin), &sig_len);
    if (ret != SGX_SUCCESS || sig_len != SGX_RSA3072_KEY_SIZE) {
        ocall_printf("[Enclave] Failed to decode signature.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    int is_valid = 0;
    ret = ecall_verify_signature(
        (uint8_t*)signed_cmd,
        strlen(signed_cmd),
        signature_bin,
        sig_len,
        signer_type,
        &is_valid
    );

    if (ret != SGX_SUCCESS || !is_valid) {
        ocall_printf("[Enclave] Signature verification failed.\n");
        return SGX_ERROR_INVALID_SIGNATURE;
    }

    ocall_printf("[Enclave] Signature verified successfully.\n");


    const char* msg = "Request to execute statistic operation. Approve? (yes/no)";
    int authorized = 0;
    ocall_request_authorization(msg,&authorized);

    
    if (!authorized) {
        ocall_printf("[Enclave] Authorization DENIED.\n");
        return MY_ERROR_ACCESS_DENIED;
    }
    ocall_printf("[Enclave] Authorization GRANTED.\n");


    // Alocar buffer para plaintext
    std::vector<uint8_t> plaintext(ciphertext_len);
    ret = ecall_decrypt_data(ciphertext, ciphertext_len,
                                          iv, iv_len,
                                          mac,
                                          plaintext.data());
    

    if (ret != SGX_SUCCESS){
        char msg[100];
        snprintf(msg, sizeof(msg), "Erro na desencriptação: 0x%x\n", ret);
        ocall_printf(msg);
        return ret;
    }

    // Interpretar plaintext como CSV string
    std::string csv((char*)plaintext.data(), plaintext.size());

    // Parse CSV e extrair coluna "age"
    std::vector<Record> records = parse_csv(csv);
    std::vector<double> ages;
    for (const auto& row : records) {
        auto it = row.find("age");
        if (it != row.end()) {
            try {
                double age = std::stod(it->second);
                ages.push_back(age);
            } catch (...) {
                // Ignora valores inválidos
            }
        }
    }


    if (ages.empty()) return SGX_ERROR_INVALID_PARAMETER;

    // Escolher e executar operação estatística
    switch (operation_type) {
        case STAT_MEAN:
            return ecall_mean(ages.data(), ages.size(), result);
        case STAT_VARIANCE:
            return ecall_variance(ages.data(), ages.size(), result);
        case STAT_STDDEV:
            return ecall_stddev(ages.data(), ages.size(), result);
        case STAT_SUM:
            return ecall_sum(ages.data(), ages.size(), result);
        case STAT_MIN:
            return ecall_min(ages.data(), ages.size(), result);
        case STAT_MAX:
            return ecall_max(ages.data(), ages.size(), result);
        case STAT_MEDIAN:
            return ecall_median(ages.data(), ages.size(), result);
        case STAT_MODE:
            return ecall_mode(ages.data(), ages.size(), result);
        default:
            return SGX_ERROR_INVALID_PARAMETER;
    }
}


