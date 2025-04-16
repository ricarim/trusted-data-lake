#include <string>
#include <vector>
#include <sstream>
#include "Enclave_t.h"
#include "sgx_tcrypto.h"
#include <cstring>
#include <sstream>
#include <string>
#include <map>

static uint8_t g_n[SGX_RSA3072_KEY_SIZE];
static uint8_t g_e[SGX_RSA3072_PUB_EXP_SIZE];
static uint8_t g_d[SGX_RSA3072_PRI_EXP_SIZE];
static uint8_t g_p[SGX_RSA3072_KEY_SIZE / 2];
static uint8_t g_q[SGX_RSA3072_KEY_SIZE / 2];
static uint8_t g_dmp1[SGX_RSA3072_KEY_SIZE / 2];
static uint8_t g_dmq1[SGX_RSA3072_KEY_SIZE / 2];
static uint8_t g_iqmp[SGX_RSA3072_KEY_SIZE / 2];

static bool g_key_ready = false;

sgx_status_t ecall_generate_rsa_key_pair() {
    if (g_key_ready) return SGX_SUCCESS;

    sgx_status_t ret = sgx_create_rsa_key_pair(
        SGX_RSA3072_KEY_SIZE,
        SGX_RSA3072_PUB_EXP_SIZE,
        g_n, g_d, g_e,
        g_p, g_q, g_dmp1, g_dmq1, g_iqmp
    );

    if (ret == SGX_SUCCESS)
        g_key_ready = true;

    return ret;
}

sgx_status_t ecall_get_rsa_pubkey(uint8_t* mod, size_t mod_len,
                                   uint8_t* exp, size_t exp_len) {
    if (!g_key_ready) return SGX_ERROR_UNEXPECTED;

    if (mod_len < SGX_RSA3072_KEY_SIZE || exp_len < SGX_RSA3072_PUB_EXP_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    memcpy(mod, g_n, SGX_RSA3072_KEY_SIZE);
    memcpy(exp, g_e, SGX_RSA3072_PUB_EXP_SIZE);
    return SGX_SUCCESS;
}

sgx_status_t ecall_rsa_decrypt(const uint8_t* enc_data, size_t enc_len,
                               uint8_t* output, size_t output_size,
                               size_t* decrypted_len) {
    if (!g_key_ready || !enc_data || !output || !decrypted_len)
        return SGX_ERROR_INVALID_PARAMETER;

    void* priv_key = nullptr;

    sgx_status_t ret = sgx_create_rsa_priv1_key(
        SGX_RSA3072_KEY_SIZE,
        SGX_RSA3072_PUB_EXP_SIZE,
        SGX_RSA3072_PRI_EXP_SIZE,
        g_n, g_e, g_d,
        &priv_key
    );
    if (ret != SGX_SUCCESS) return ret;

    ret = sgx_rsa_priv_decrypt_sha256(
        priv_key, output, decrypted_len,
        enc_data, enc_len
    );

    sgx_free_rsa_key(priv_key, SGX_RSA_PRIVATE_KEY,
                     SGX_RSA3072_KEY_SIZE, SGX_RSA3072_PUB_EXP_SIZE);
    return ret;
}

sgx_status_t ecall_rsa_sign(const uint8_t* data, size_t data_len,
                            uint8_t* signature, size_t sig_len) {
    if (!g_key_ready || !data || !signature)
        return SGX_ERROR_INVALID_PARAMETER;
    if (sig_len < SGX_RSA3072_KEY_SIZE)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_rsa3072_signature_t* sig = (sgx_rsa3072_signature_t*)signature;

    void* priv_key = nullptr;

    sgx_status_t ret = sgx_create_rsa_priv1_key(
        SGX_RSA3072_KEY_SIZE,
        SGX_RSA3072_PUB_EXP_SIZE,
        SGX_RSA3072_PRI_EXP_SIZE,
        g_n, g_e, g_d,
        &priv_key
    );
    if (ret != SGX_SUCCESS) return ret;

    ret = sgx_rsa3072_sign(data, (uint32_t)data_len, (const sgx_rsa3072_key_t*)priv_key, sig);

    sgx_free_rsa_key(priv_key, SGX_RSA_PRIVATE_KEY,
                     SGX_RSA3072_KEY_SIZE, SGX_RSA3072_PUB_EXP_SIZE);
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



void ecall_process_average_age(const char* decrypted_csv) {
    std::string csv(decrypted_csv);
    std::vector<Record> records = parse_csv(csv);


    char buf[100];
    snprintf(buf, sizeof(buf), "Average patient age: %.2f\n");
    ocall_printf(buf);
}

