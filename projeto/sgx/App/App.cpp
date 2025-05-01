#include <stdio.h>
#include <fcntl.h>
#include <sgx_error.h>
#include <sgx_tseal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_urts.h>
#include <sys/stat.h>
#include <time.h>
#include <vector>
#include "Enclave_u.h"

#define ENCLAVE_FILE "enclave.signed.so"
#define IV_SIZE 12
#define TAG_SIZE 16
#define SYM_KEY_SIZE 32
#define SEALED_KEY_FILE "sealed_key.bin"
#define MY_ERROR_ACCESS_DENIED 0xFFFF0001

#define PIPE_PATH "/tmp/sgx_pipe"
#define RESPONSE_PIPE "/tmp/sgx_response"
#define AUTH_REQUEST_FILE "/tmp/sgx_auth_request"
#define AUTH_RESPONSE_FILE "/tmp/sgx_authorization"

sgx_enclave_id_t eid = 0;

// OCALL that enclave calls
void ocall_printf(const char* str) {
    printf("%s", str);
}

void ocall_request_authorization(const char* message, int* authorized) {
    printf("[App] Authorization request: %s\n", message);

    // Escreve o pedido no ficheiro
    FILE* req_file = fopen("/tmp/sgx_auth_request", "w");
    if (req_file) {
        fprintf(req_file, "%s\n", message);
        fclose(req_file);
    } else {
        printf("[App] Failed to write auth request file.\n");
        *authorized = 0;
        return;
    }

    // Aguarda a resposta ser escrita pelo client
    printf("[App] Waiting for authorization response...\n");
    while (access("/tmp/sgx_authorization", F_OK) != 0) {
        sleep(1);  // Espera até o client escrever
    }

    // Lê a resposta
    FILE* approval_file = fopen("/tmp/sgx_authorization", "r");
    if (approval_file) {
        char response[16];
        fgets(response, sizeof(response), approval_file);
        fclose(approval_file);
        remove("/tmp/sgx_authorization");  // limpa depois de usar
        remove("/tmp/sgx_auth_request");

        response[strcspn(response, "\n")] = 0;
        *authorized = (strcmp(response, "yes") == 0);
        printf("[App] Authorization result: %s\n", response);
    } else {
        printf("[App] Failed to read authorization response.\n");
        *authorized = 0;
    }
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
    if (!file) return nullptr;

    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    rewind(file);

    char* buffer = (char*)malloc(size);
    if (!buffer) {
        fclose(file);
        return nullptr;
    }

    fread(buffer, 1, size, file);
    fclose(file);
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


int main() {
    sgx_status_t ret,retval;

    remove(PIPE_PATH);
    remove(RESPONSE_PIPE);
    remove(AUTH_REQUEST_FILE);
    remove(AUTH_RESPONSE_FILE);

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

    int pipe_fd = open(PIPE_PATH, O_RDWR);
    if (pipe_fd < 0) {
        perror("open pipe");
        return 1;
    }

    FILE* pipe_stream = fdopen(pipe_fd, "r");
    printf("[App] SGX App is running. Waiting for commands...\n");

    char buffer[256];

    while (fgets(buffer, sizeof(buffer), pipe_stream)) {
        buffer[strcspn(buffer, "\n")] = 0;
        if (strcmp(buffer, "exit") == 0) break;

        char cmd[16], arg1[128], arg2[256];
        int parsed = sscanf(buffer, "%s %s %s", cmd, arg1, arg2);

        if (parsed >= 2 && strcmp(cmd, "encrypt") == 0) {
            printf("[App] Encrypting file: %s\n", arg1);

            size_t plaintext_len;
            char* plaintext = read_file(arg1, &plaintext_len);
            if (!plaintext) {
                printf("Failed to read file.\n");
                continue;
            }

            uint8_t iv[IV_SIZE];
            ret = ecall_generate_iv(eid, &retval, iv, IV_SIZE);
            if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
                printf("IV generation failed.\n");
                continue;
            }

            std::vector<uint8_t> ciphertext(plaintext_len);
            uint8_t mac[TAG_SIZE];
            ret = ecall_encrypt_data(eid, &retval, (uint8_t*)plaintext, plaintext_len, iv, IV_SIZE, ciphertext.data(), mac);
            free(plaintext);

            if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
                printf("Encryption failed.\n");
                continue;
            }

            std::vector<uint8_t> combined(IV_SIZE + TAG_SIZE + ciphertext.size());
            memcpy(combined.data(), iv, IV_SIZE);
            memcpy(combined.data() + IV_SIZE, mac, TAG_SIZE);
            memcpy(combined.data() + IV_SIZE + TAG_SIZE, ciphertext.data(), ciphertext.size());

            write_file("encrypted.bin", combined.data(), combined.size());
            printf("[App] File encrypted and saved as 'encrypted.bin'.\n");

            if (parsed == 3) {
                if (upload_to_gcs("encrypted.bin", arg2))
                    printf("[App] Upload to GCS successful.\n");
                else
                    printf("[App] Upload to GCS failed.\n");
            }

        } else if (parsed >= 3 && strcmp(cmd, "stat") == 0) {
            printf("[App] Computing statistic '%s' using file from: %s\n", arg1, arg2);

            if (!download_from_gcs(arg2, "encrypted.bin")) {
                printf("[App] Failed to download encrypted file from GCS.\n");
                continue;
            }

            size_t total_len;
            uint8_t* full_data = (uint8_t*)read_file("encrypted.bin", &total_len);
            if (!full_data || total_len < (IV_SIZE + TAG_SIZE)) {
                printf("Encrypted file is invalid.\n");
                continue;
            }

            uint8_t iv[IV_SIZE], mac[TAG_SIZE];
            memcpy(iv, full_data, IV_SIZE);
            memcpy(mac, full_data + IV_SIZE, TAG_SIZE);

            uint8_t* ciphertext = full_data + IV_SIZE + TAG_SIZE;
            size_t ciphertext_len = total_len - IV_SIZE - TAG_SIZE;

            int op_code = 0;
            if (strcmp(arg1, "sum") == 0) op_code = 1;
            else if (strcmp(arg1, "mean") == 0) op_code = 2;
            else if (strcmp(arg1, "min") == 0) op_code = 3;
            else if (strcmp(arg1, "max") == 0) op_code = 4;
            else if (strcmp(arg1, "median") == 0) op_code = 5;
            else if (strcmp(arg1, "mode") == 0) op_code = 6;
            else if (strcmp(arg1, "variance") == 0) op_code = 7;
            else if (strcmp(arg1, "stddev") == 0) op_code = 8;

            double result;
            ret = ecall_process_stats(eid, &retval, ciphertext, ciphertext_len, iv, IV_SIZE, mac, op_code, &result);
            free(full_data);

            FILE* resp = fopen(RESPONSE_PIPE, "w");
            if (resp) {
                if (ret == SGX_SUCCESS && retval == SGX_SUCCESS)
                    fprintf(resp, "[App] Authorization granted.\n[App] Result: %.2f\n", result);
                else if (retval == MY_ERROR_ACCESS_DENIED)
                    fprintf(resp, "[App] Authorization denied.\n");
                else
                    fprintf(resp, "[App] Failed to compute stat.\n");
                fclose(resp);
            }

        } else {
            printf("[App] Invalid command format.\n");
        }
    }

    sgx_destroy_enclave(eid);
    printf("[App] SGX App exited.\n");
    return 0;
}

