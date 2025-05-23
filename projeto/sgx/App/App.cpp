#include <stdio.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <fcntl.h>
#include <algorithm>
#include <ctime>
#include <cstdint>
#include <unistd.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <time.h>
#include <string.h>

#include <sgx_urts.h>
#include <sgx_error.h>
#include <sgx_report.h>
#include <sgx_dcap_quoteverify.h>
#include <sgx_ql_quote.h>
#include <sgx_ql_lib_common.h>
#include <sgx_dcap_ql_wrapper.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "Enclave_u.h"


#define ENCLAVE_FILE "enclave.signed.so"
#define IV_SIZE 12
#define TAG_SIZE 16
#define SYM_KEY_SIZE 32
#define MAX_WRAPPING_KEYS 2
#define MAX_WRAPPED_SIZE (SYM_KEY_SIZE + MAX_WRAPPING_KEYS * (IV_SIZE + TAG_SIZE))
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
    sgx_status_t ret;
    sgx_status_t sgx_ret;
    bool master_key_ready = false;
    const char* gcs_wrapped_path = "gs://enclave_bucket/wrapped_key.bin";
    const char* local_wrapped_file = "wrapped_key.bin";
    bool restoring_existing_key = false;

    remove(PIPE_PATH);
    remove(RESPONSE_PIPE);

    // Create enclave
    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Error creating enclave: 0x%x\n", ret);
        return -1;
    }

    sgx_target_info_t qe_target_info = {};
    sgx_report_t report = {};
    uint32_t quote_size = 0;
    uint8_t* quote = nullptr;
    sgx_status_t retval = SGX_SUCCESS;
    quote3_error_t qe_ret = SGX_QL_SUCCESS;

    // get target_info
    qe_ret = sgx_qe_get_target_info(&qe_target_info);
    if (qe_ret != SGX_QL_SUCCESS) {
        printf("sgx_qe_get_target_info failed: 0x%x\n", qe_ret);
        return -1;
    }

    // Create report inside enclave
    ret = ecall_create_report(eid, &retval,
        (uint8_t*)&qe_target_info,
        (uint8_t*)&report);
    if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
        printf("ecall_create_report failed: 0x%x\n", ret);
        return -1;
    }

    // Get quote size
    qe_ret = sgx_qe_get_quote_size(&quote_size);
    if (qe_ret != SGX_QL_SUCCESS) {
        printf("sgx_qe_get_quote_size failed: 0x%x\n", qe_ret);
        return -1;
    }

    quote = (uint8_t*)malloc(quote_size);

    // Get quote
    qe_ret = sgx_qe_get_quote(&report, quote_size, quote);
    if (qe_ret != SGX_QL_SUCCESS) {
        printf("sgx_qe_get_quote failed: 0x%x\n", qe_ret);
        free(quote);
        return -1;
    }

    printf("[App] Remote attestation quote successfully generated.\n");

    uint32_t collateral_expiration_status = 1;
    quote3_error_t qv_ret = SGX_QL_SUCCESS;
    tee_qv_result_t qv_result = TEE_QV_RESULT_UNSPECIFIED;
    time_t current_time = time(NULL);

    qv_ret = sgx_qv_verify_quote(
        quote,                   
        quote_size,              
        NULL, 
        current_time,   
        &collateral_expiration_status,
        &qv_result,
        NULL, 0, NULL       
    );

    if (qv_ret == SGX_QL_SUCCESS) {
        switch (qv_result) {
            case SGX_QL_QV_RESULT_OK:
                printf("[App] Quote verification succeeded.\n");
                break;
            case SGX_QL_QV_RESULT_CONFIG_NEEDED:
            case SGX_QL_QV_RESULT_OUT_OF_DATE:
            case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
            case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
                printf("[App] Quote is acceptable with warnings: 0x%x\n", qv_result);
                break;
            default:
                printf("[App] Quote is invalid: 0x%x\n", qv_result);
                break;
        }
    } else {
        printf("[App] Quote verification failed. Error code: 0x%x\n", qv_ret);
    }


    bool gcs_has_wrapped = false;
    if (is_remote_newer(gcs_wrapped_path, local_wrapped_file)) {
        printf("[App] Wrapped key in GCS is newer. Downloading...\n");
        gcs_has_wrapped = download_from_gcs(gcs_wrapped_path, local_wrapped_file);
    } else {
        printf("[App] Local wrapped_key.bin is up-to-date. Skipping download.\n");
        gcs_has_wrapped = (access(local_wrapped_file, F_OK) == 0);
    }

    if (gcs_has_wrapped) {
        printf("[App] Found wrapped master key in cloud. Preparing to unwrap...\n");

        size_t wrapped_len = 0;
        uint8_t* wrapped_data = (uint8_t*)read_file(local_wrapped_file, &wrapped_len);
        if (!wrapped_data) {
            printf("[App] Failed to read wrapped_key.bin after download\n");
            return 1;
        }

        ret = ecall_prepare_unwrapping(eid, &retval, wrapped_data, (uint32_t)wrapped_len);
        free(wrapped_data);
        if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
            printf("[App] Failed to prepare unwrapping inside enclave\n");
            return 1;
        }

        restoring_existing_key = true;

    } else {
        printf("[App] No wrapped key found in cloud. Generating new master key...\n");

        int expected_keys = 2;
        ret = ecall_generate_master_key(eid, &retval, expected_keys);
        if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
            printf("[App] Failed to generate master key\n");
            return 1;
        }

        restoring_existing_key = false;
    }


    if (access(PIPE_PATH, F_OK) != 0)
        mkfifo(PIPE_PATH, 0666);
    if (access(RESPONSE_PIPE, F_OK) != 0)
        mkfifo(RESPONSE_PIPE, 0666);

    int pipe_fd = open(PIPE_PATH, O_RDWR);
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
        
        if (tokens.size() == 2 && tokens[0] == "addkey") {
            std::vector<uint8_t> key_bin = base64_decode(tokens[1]);
            if (key_bin.size() != SYM_KEY_SIZE) {
                printf("[App] Invalid key length\n");
                continue;
            }

            ret = ecall_add_wrapping_key(eid, &retval, key_bin.data(), key_bin.size());
            if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
                printf("[App] Failed to add sk to enclave\n");
                continue;
            }
            printf("[App] Key added.\n");


            if (restoring_existing_key) {
                ret = ecall_unwrap_master_key(eid, &retval);
                if (ret == SGX_SUCCESS && retval == SGX_SUCCESS) {
                    printf("[App] Master key unwrapped successfully.\n");
                    master_key_ready = true;
                } else if (ret == SGX_ERROR_BUSY) {
                    printf("[App] Waiting for more keys to unwrap...\n");
                } else {
		    printf("[App] Error unwrapping master key: SGX ret=0x%x, enclave ret=0x%x\n", ret, retval);
                }
            }else{
                std::vector<uint8_t> wrapped(1024);
                uint32_t used_len = 0;
                ret = ecall_get_wrapped_master_key(eid, &retval, wrapped.data(), wrapped.size(), &used_len);
                if (ret == SGX_SUCCESS && retval == SGX_SUCCESS) {
                    wrapped.resize(used_len);
                    write_file("wrapped_key.bin", wrapped.data(), wrapped.size());
                    printf("[App] Master key successfully wrapped and saved.\n");

                    const char* gcs_dest = "gs://enclave_bucket/wrapped_key.bin";
                    if (upload_to_gcs("wrapped_key.bin", gcs_dest))
                        printf("[App] Uploaded to GCS: %s\n", gcs_dest);
                    else
                        printf("[App]Upload failed\n");

                    master_key_ready = true;
                } else if (ret == SGX_ERROR_BUSY) {
                    printf("[App] Still waiting for more keys...\n");
                } else {
		    printf("[App] Error wrapping master key: SGX ret=0x%x, enclave ret=0x%x\n", ret, retval);

                }
            }

            continue;
        }

        if (!master_key_ready) {
            printf("[App] Master key is not ready. Skipping command.\n");
            continue;
        }


        if (tokens.size() == 6 && tokens[0] == "encrypt") {
            std::string signer = tokens[1];
	    std::string base64_data = tokens[2];
            std::string gcs_path = tokens[3];
            std::string timestamp = tokens[4];
            std::string signature_b64 = tokens[5];

            int signer_type = -1;
            if (signer == "hospital") signer_type = SIGNER_HOSPITAL;
            else if (signer == "lab") signer_type = SIGNER_LAB;
            else {
                printf("[App] Invalid signer: %s\n", signer.c_str());
                continue;
            }

            std::string signed_data = "encrypt|" + signer + "|" + base64_data + "|" + gcs_path + "|" + timestamp;

            std::vector<uint8_t> sig_bin = base64_decode(signature_b64);
            if (sig_bin.size() != sizeof(sgx_ec256_signature_t)) {
                printf("[App] Invalid signature size\n");
                continue;
            }

            sgx_ec256_signature_t sig;

            memcpy(&sig, sig_bin.data(), sizeof(sgx_ec256_signature_t));

            sgx_status_t enc_ret;
            ret = ecall_process_encrypt(
                eid, &enc_ret,
                reinterpret_cast<const char*>(signed_data.data()), signed_data.size(),
                reinterpret_cast<const uint8_t*>(&sig), sizeof(sig)
            );


            if (ret != SGX_SUCCESS || enc_ret != SGX_SUCCESS) {
                printf("[App] Signature verification or timestamp check failed. Aborting encryption.\n");
                continue;
            }


	    std::vector<uint8_t> plaintext_bin = base64_decode(base64_data);
	    size_t plaintext_len = plaintext_bin.size();
            if (plaintext_bin.empty()) {
                printf("[App] Failed to read input file\n");
                continue;
            }

            uint8_t iv[IV_SIZE], mac[TAG_SIZE];
            std::vector<uint8_t> ciphertext(plaintext_len);

            ret = ecall_generate_iv(eid, &retval, iv, IV_SIZE);
            if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
                printf("[App] Failed to generate IV\n");
                continue;
            }

            ret = ecall_encrypt_data(eid, &retval, (uint8_t*)plaintext_bin.data(), plaintext_len, iv, IV_SIZE, ciphertext.data(), mac);

            if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
                printf("[App] Encryption failed\n");
                continue;
            }

            std::vector<uint8_t> combined(IV_SIZE + TAG_SIZE + ciphertext.size());
            memcpy(combined.data(), iv, IV_SIZE);
            memcpy(combined.data() + IV_SIZE, mac, TAG_SIZE);
            memcpy(combined.data() + IV_SIZE + TAG_SIZE, ciphertext.data(), ciphertext.size());

	    std::string local_encrypted_file = signer + ".bin";
	    write_file(local_encrypted_file.c_str(), combined.data(), combined.size());

            if (upload_to_gcs(local_encrypted_file.c_str(), gcs_path.c_str()))
                printf("[App] Upload successful\n");
            else
                printf("[App] Upload failed\n");
        } else if (tokens.size() == 8 && tokens[0] == "stat") {
            std::string signer = tokens[1];
            std::string column = tokens[2];
            std::string operation = tokens[3];
            std::string gcs_path = tokens[4];
            std::string timestamp = tokens[5];
            std::string signature1_b64 = tokens[6];
            std::string signature2_b64 = tokens[7];

            int signer_type = -1;
            if (signer == "hospital") signer_type = SIGNER_HOSPITAL;
            else if (signer == "lab") signer_type = SIGNER_LAB;
            else {
                printf("[App] Invalid signer: %s\n", signer.c_str());
                continue;
            }

	    std::string local_file = signer + ".bin";
            if (is_remote_newer(gcs_path.c_str(), local_file.c_str())) {
                printf("[App] Remote file is newer, downloading...\n");
                if (!download_from_gcs(gcs_path.c_str(), local_file.c_str())) {
                    printf("[App] Failed to download encrypted file\n");
                    continue;
                }
            }else {
                printf("[App] Local encrypted.bin is up-to-date. Skipping download.\n");
	    
	    }

		    size_t total_len;
		    uint8_t* full_data = (uint8_t*)read_file(local_file.c_str(), &total_len);
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
            snprintf(signed_data, sizeof(signed_data), "stat|%s|%s|%s|%s|%s", signer.c_str(), column.c_str(), operation.c_str(), gcs_path.c_str(), timestamp.c_str());

            std::vector<uint8_t> sig1_bin = base64_decode(signature1_b64);
            std::vector<uint8_t> sig2_bin = base64_decode(signature2_b64);

            if (sig1_bin.size() != sizeof(sgx_ec256_signature_t) || sig2_bin.size() != sizeof(sgx_ec256_signature_t)) {
                printf("[App] One or both signatures have invalid size (expected 64 bytes)\n");
                continue;
            }

            sgx_ec256_signature_t sig1, sig2;
            memcpy(&sig2, sig2_bin.data(), sizeof(sgx_ec256_signature_t));
            memcpy(&sig1, sig1_bin.data(), sizeof(sgx_ec256_signature_t));

            static const std::vector<std::string> categorical_columns = {
                "gender",
                "diagnosis",
                "exam_type"
            };

            bool is_categorical = (op_code == STAT_MODE) &&
                (std::find(categorical_columns.begin(),
                           categorical_columns.end(),
                           column) != categorical_columns.end());

            char mode_buf[512];
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
                column.c_str(),
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
