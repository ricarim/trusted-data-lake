#include <stdio.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <fcntl.h>
#include <ctime>
#include <cstdint>
#include <sgx_error.h>
#include <sgx_tseal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string>
#include <sgx_urts.h>
#include <sys/stat.h>
#include <time.h>
#include <vector>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <sgx_report.h>
#include <sgx_ql_quote.h>
#include <sgx_ql_lib_common.h>
#include "Enclave_u.h"

#define ENCLAVE_FILE "enclave.signed.so"
#define IV_SIZE 12
#define TAG_SIZE 16
#define SYM_KEY_SIZE 32
#define SEALED_KEY_FILE "sealed_key.bin"
#define MY_ERROR_ACCESS_DENIED 0xFFFF0001

#define PIPE_PATH "/tmp/sgx_pipe"
#define RESPONSE_PIPE "/tmp/sgx_response"

#define SIGNER_HOSPITAL 0
#define SIGNER_LAB 1

#define STAT_SUM 1
#define STAT_MEAN 2
#define STAT_MIN 3
#define STAT_MAX 4
#define STAT_MEDIAN 5
#define STAT_MODE 6
#define STAT_VARIANCE 7
#define STAT_STDDEV 8

#define TARGET_INFO_SIZE 512
#define REPORT_SIZE 432

sgx_enclave_id_t eid = 0;

// OCALL that enclave calls
void ocall_printf(const char* str) {
    printf("%s", str);
}

std::vector<uint8_t> read_pem_file(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return {};
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    rewind(f);
    std::vector<uint8_t> buffer(size);
    fread(buffer.data(), 1, size, f);
    fclose(f);
    return buffer;
}


std::vector<uint8_t> base64_decode(const std::string& encoded) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO* mem = BIO_new_mem_buf(encoded.data(), encoded.size());
    BIO* bio_chain = BIO_push(b64, mem);

    std::vector<uint8_t> decoded(encoded.size()); 
    int len = BIO_read(bio_chain, decoded.data(), decoded.size());
    if (len < 0) len = 0;
    decoded.resize(len);

    BIO_free_all(bio_chain);
    return decoded;
}

// Save sealed key to file
bool save_sealed_key(const char* path, uint8_t* data, uint32_t size) {
    FILE* f = fopen(path, "wb");
    if (!f) return false;
    fwrite(data, 1, size, f);
    fclose(f);
    return true;
}

// Load sealed key from file
bool load_sealed_key(const char* path, uint8_t** out_data, uint32_t* out_size) {
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    *out_size = ftell(f);
    rewind(f);

    *out_data = (uint8_t*)malloc(*out_size);
    fread(*out_data, 1, *out_size, f);
    fclose(f);
    return true;
}


char* read_file(const char* filename, size_t* out_size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("[read_file] Failed to open %s\n", filename);
        return nullptr;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        printf("[read_file] fseek failed\n");
        fclose(file);
        return nullptr;
    }

    long size = ftell(file);
    if (size <= 0) {
        printf("[read_file] File is empty or ftell failed\n");
        fclose(file);
        return nullptr;
    }

    rewind(file);
    char* buffer = (char*)malloc(size);
    if (!buffer) {
        printf("[read_file] malloc failed\n");
        fclose(file);
        return nullptr;
    }

    size_t read = fread(buffer, 1, size, file);
    fclose(file);

    if (read != (size_t)size) {
        printf("[read_file] fread read %zu but expected %ld\n", read, size);
        free(buffer);
        return nullptr;
    }

    if (out_size) *out_size = size;
    return buffer;
}


bool write_file(const char* filename, const uint8_t* data, size_t size) {
    FILE* file = fopen(filename, "wb");
    if (!file) return false;
    fwrite(data, 1, size, file);
    fclose(file);
    return true;
}



bool download_from_gcs(const char* gcs, const char* local) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "gsutil cp %s %s", gcs, local);
    return system(cmd) == 0;
}

bool upload_to_gcs(const char* local, const char* gcs) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "gsutil cp %s %s", local, gcs);
    return system(cmd) == 0;
}


// Function to check if the remote file on GCS is newer than the local one
bool is_remote_newer(const char* gcs_uri, const char* local_path) {
    // Save metadata to a temporary file
    const char* temp_meta = "gcs_meta.txt";
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "gsutil ls -l %s > %s", gcs_uri, temp_meta);
    if (system(cmd) != 0) return false;

    FILE* f = fopen(temp_meta, "r");
    if (!f) return false;

    char line[512];
    time_t remote_time = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, gcs_uri)) {
            // Parse the date: expected format is " 12345  2025-04-30T22:31:12Z"
            char date[20];
            if (sscanf(line, "%*s %19s", date) == 1) {
                struct tm tm;
                memset(&tm, 0, sizeof(tm));
                strptime(date, "%Y-%m-%dT%H:%M:%SZ", &tm);
                remote_time = timegm(&tm);
            }
        }
    }
    fclose(f);
    remove(temp_meta);
    // Check the local file modification time
    struct stat st;
    if (stat(local_path, &st) != 0) {
        return true;  // If the file doesn't exist locally, consider remote as newer
    }

    time_t local_time = st.st_mtime;
    return remote_time > local_time;
}

void ocall_get_time(uint64_t* t) {
    if (t) *t = static_cast<uint64_t>(time(nullptr));
}


int main() {
    sgx_status_t ret,retval;
    sgx_status_t sgx_ret;

    remove(PIPE_PATH);
    remove(RESPONSE_PIPE);

    // Create enclave
    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Error creating enclave: 0x%x\n", ret);
        return -1;
    }


    uint32_t sealed_size = sizeof(sgx_sealed_data_t) + SYM_KEY_SIZE;
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);

    if (access(SEALED_KEY_FILE, F_OK) != 0) {
        printf("[App] Generating and sealing symmetric key...\n");
        ret = ecall_generate_and_seal_key(eid, &retval, sealed_data, sealed_size);
        if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
            printf("[App] Failed to seal key.\n");
            return 1;
        }
        if (!save_sealed_key(SEALED_KEY_FILE, sealed_data, sealed_size)) {
            printf("[App] Failed to save sealed key.\n");
            return 1;
        }
    } else {
        printf("[App] Loading sealed key from file...\n");
        if (!load_sealed_key(SEALED_KEY_FILE, &sealed_data, &sealed_size)) {
            printf("[App] Failed to load sealed key.\n");
            return 1;
        }
        ret = ecall_unseal_key(eid, &retval, sealed_data, sealed_size);
        if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
            printf("[App] Failed to unseal key.\n");
            return 1;
        }
    }
    free(sealed_data);

    if (access(PIPE_PATH, F_OK) != 0)
        mkfifo(PIPE_PATH, 0666);
    if (access(RESPONSE_PIPE, F_OK) != 0)
        mkfifo(RESPONSE_PIPE, 0666);

    int pipe_fd = open(PIPE_PATH, O_RDONLY);
    if (pipe_fd < 0) {
        perror("open pipe");
        return 1;
    }

    FILE* pipe = fdopen(pipe_fd, "r");
    printf("[App] SGX App is running. Waiting for commands...\n");


    char input[4096];
    while (fgets(input, sizeof(input), pipe)) {
        input[strcspn(input, "\n")] = 0;
        if (strcmp(input, "exit") == 0) break;

        std::vector<std::string> tokens;
        char* tok = strtok(input, "|");
        while (tok) {
            tokens.push_back(tok);
            tok = strtok(nullptr, "|");
        }
        

        if (tokens.size() == 6 && tokens[0] == "encrypt") {
            std::string signer = tokens[1];
            std::string filename = tokens[2];
            std::string gcs_path = tokens[3];
            std::string timestamp = tokens[4];
            std::string signature_b64 = tokens[5];

            std::string signed_data = "encrypt|" + signer + "|" + filename + "|" + gcs_path + "|" + timestamp;

            std::vector<uint8_t> sig_bin = base64_decode(signature_b64);
            if (sig_bin.size() != 384) {
                printf("[App] Invalid signature size.\n");
                continue;
            }

            sgx_status_t verify_ret;
            ret = ecall_process_encrypt(
                eid, &verify_ret,
                signed_data.c_str(), signed_data.size(),
                sig_bin.data(), sig_bin.size()
            );

            if (ret != SGX_SUCCESS || verify_ret != SGX_SUCCESS) {
                printf("[App] Signature or timestamp invalid. Aborting encryption.\n");
                continue;
            }


            size_t plaintext_len;
            char* plaintext = read_file(filename.c_str(), &plaintext_len);
            if (!plaintext) {
                printf("[App] Failed to read input file\n");
                continue;
            }

            uint8_t iv[IV_SIZE], mac[TAG_SIZE];
            std::vector<uint8_t> ciphertext(plaintext_len);

            ret = ecall_generate_iv(eid, &retval, iv, IV_SIZE);
            if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
                printf("[App] Failed to generate IV\n");
                free(plaintext);
                continue;
            }

            ret = ecall_encrypt_data(eid, &retval, (uint8_t*)plaintext, plaintext_len, iv, IV_SIZE, ciphertext.data(), mac);
            free(plaintext);

            if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
                printf("[App] Encryption failed\n");
                continue;
            }

            std::vector<uint8_t> combined(IV_SIZE + TAG_SIZE + ciphertext.size());
            memcpy(combined.data(), iv, IV_SIZE);
            memcpy(combined.data() + IV_SIZE, mac, TAG_SIZE);
            memcpy(combined.data() + IV_SIZE + TAG_SIZE, ciphertext.data(), ciphertext.size());

            write_file("encrypted.bin", combined.data(), combined.size());

            if (upload_to_gcs("encrypted.bin", gcs_path.c_str()))
                printf("[App] Upload successful\n");
            else
                printf("[App] Upload failed\n");
        } else if (tokens.size() == 7 && tokens[0] == "stat") {
            std::string signer = tokens[1];
            std::string operation = tokens[2];
            std::string gcs_path = tokens[3];
            std::string timestamp = tokens[4];
            std::string signature1_b64 = tokens[5];
            std::string signature2_b64 = tokens[6];

            int signer_type = (signer == "hospital") ? SIGNER_HOSPITAL : SIGNER_LAB;

            if (!download_from_gcs(gcs_path.c_str(), "encrypted.bin")) {
                printf("[App] Failed to download encrypted file\n");
                continue;
            }

            size_t total_len;
            uint8_t* full_data = (uint8_t*)read_file("encrypted.bin", &total_len);
            if (!full_data || total_len < IV_SIZE + TAG_SIZE) {
                printf("[App] Encrypted file invalid\n");
                continue;
            }

            uint8_t iv[IV_SIZE], mac[TAG_SIZE];
            memcpy(iv, full_data, IV_SIZE);
            memcpy(mac, full_data + IV_SIZE, TAG_SIZE);
            uint8_t* ciphertext = full_data + IV_SIZE + TAG_SIZE;
            size_t ciphertext_len = total_len - IV_SIZE - TAG_SIZE;

            int op_code = 0;
            if (operation == "sum") op_code = STAT_SUM;
            else if (operation == "mean") op_code = STAT_MEAN;
            else if (operation == "min") op_code = STAT_MIN;
            else if (operation == "max") op_code = STAT_MAX;
            else if (operation == "median") op_code = STAT_MEDIAN;
            else if (operation == "mode") op_code = STAT_MODE;
            else if (operation == "variance") op_code = STAT_VARIANCE;
            else if (operation == "stddev") op_code = STAT_STDDEV;

            char signed_data[512];
            snprintf(signed_data, sizeof(signed_data), "stat|%s|%s|%s|%s", signer.c_str(), operation.c_str(), gcs_path.c_str(), timestamp.c_str());

            std::vector<uint8_t> sig1_bin = base64_decode(signature1_b64);
            std::vector<uint8_t> sig2_bin = base64_decode(signature2_b64);

            if (sig1_bin.size() != 384 || sig2_bin.size() != 384) {
                printf("[App] One or both signatures are invalid size (expected 384 bytes)\n");
                continue;
            }


            static const std::vector<std::string> categorical_columns = {
                "gender",
                "diagnosis",
                "exam_type"
            };

            bool is_categorical = (op_code == STAT_MODE) &&
                (std::find(categorical_columns.begin(),
                           categorical_columns.end(),
                           column) != categorical_columns.end());

            const char* column = "age";
            char mode_buf[64];
            double result = 0.0;
            ret = ecall_process_stats(
                eid, &retval,
                signed_data,
                strlen(signed_data),
                sig1_bin.data(), sig1_bin.size(),
                sig2_bin.data(), sig2_bin.size(),
                ciphertext, ciphertext_len,
                iv, IV_SIZE,
                mac,
                column,
                op_code,
                mode_buf, sizeof(mode_buf),
                &result
            );

            FILE* resp = fopen(RESPONSE_PIPE, "w");
            if (resp) {
                if (ret == SGX_SUCCESS && retval == SGX_SUCCESS){
                        fprintf(resp, "[App] Authorization granted\n");
                    if (is_categorical) {
                        fprintf(resp, "[App] Most frequent value is %s\n", mode_buf);
                    } else {
                        fprintf(resp, "[App] Result: %.2f\n", result);
                    }
                }else if (retval == MY_ERROR_ACCESS_DENIED)
                    fprintf(resp, "[App] Authorization denied\n");
                else
                    fprintf(resp, "[App] Computation failed\n");
                fclose(resp);
            }

            free(full_data);
        }
    }

    sgx_destroy_enclave(eid);
    return 0;
}
