#include <stdio.h>
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

#define SEALED_KEY_FILE "sealed_key.bin"
#define SYM_KEY_SIZE 32

sgx_enclave_id_t eid = 0;

// OCALL that enclave calls
void ocall_printf(const char* str) {
    printf("%s", str);
}

void menu() {
    printf("\nSecure SGX Data Lake\n");
    printf("====================\n");
    printf("1. Encrypt and upload CSV\n");
    printf("2. Download and compute statistic\n");
    printf("0. Exit\n");
    printf("Choose an option: ");
}

void stats_menu() {
    printf("\nStatistical Operations\n");
    printf("=======================\n");
    printf("1. Sum\n");
    printf("2. Mean\n");
    printf("3. Min\n");
    printf("4. Max\n");
    printf("5. Median\n");
    printf("6. Mode\n");
    printf("7. Variance\n");
    printf("8. Standard Deviation\n");
    printf("0. Back\n");
    printf("Choose an operation: ");
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


const char* encrypted_hospital_csv = "<encrypted_hospital_data_placeholder>";
const char* encrypted_lab_csv = "<encrypted_lab_data_placeholder>";

int main() {
    sgx_status_t ret,retval;

    // Create enclave
    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Error creating enclave: 0x%x\n", ret);
        return -1;
    }

    uint8_t iv[IV_SIZE];
    ret = ecall_generate_iv(eid, &retval, iv, IV_SIZE);
    if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
        printf("Failed to generate IV inside enclave.\n");
    }

    uint32_t sealed_size = sizeof(sgx_sealed_data_t) + SYM_KEY_SIZE;
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);

    if (access(SEALED_KEY_FILE, F_OK) != 0) {
        printf("Generating new symmetric key and sealing it...\n");
        ret = ecall_generate_and_seal_key(eid, &retval, sealed_data, sealed_size);
        if (ret != SGX_SUCCESS) {
            printf("Failed to seal key: 0x%x\n", ret);
            return -1;
        }
        if (!save_sealed_key(SEALED_KEY_FILE, sealed_data, sealed_size)) {
            printf("Failed to save sealed key.\n");
            return -1;
        }
    } else {
        printf("Loading sealed key from file...\n");
        if (!load_sealed_key(SEALED_KEY_FILE, &sealed_data, &sealed_size)) {
            printf("Failed to load sealed key.\n");
            return -1;
        }
        ret = ecall_unseal_key(eid, &retval, sealed_data, sealed_size);
        if (ret != SGX_SUCCESS) {
            printf("Failed to unseal key: 0x%x\n", ret);
            return -1;
        }
    }
    free(sealed_data);


    char local_file[256] = "input.csv";
    char encrypted_file[256] = "encrypted.bin";
    char gcs_uri[256];
    uint8_t mac[TAG_SIZE] = {0};

    int option = -1;
    while (1) {
        menu();
        scanf("%d", &option);
        getchar(); // consume newline

        switch (option) {
            case 1: {
                printf("Enter path to CSV file: ");
                fgets(local_file, sizeof(local_file), stdin);
                local_file[strcspn(local_file, "\n")] = 0;

                size_t plaintext_len;
                char* plaintext = read_file(local_file, &plaintext_len);
                if (!plaintext) {
                    printf("Failed to read file.\n");
                    continue;
                }

                std::vector<uint8_t> ciphertext(plaintext_len);

                ret = ecall_encrypt_data(
                    eid, &retval,
                    (uint8_t*)plaintext, plaintext_len,
                    iv, IV_SIZE,
                    ciphertext.data(), mac
                );
                free(plaintext);

                if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
                    printf("Encryption failed.\n");
                    continue;
                }

                // Save IV + MAC + ciphertext to file
                std::vector<uint8_t> combined(IV_SIZE + TAG_SIZE + ciphertext.size());
                memcpy(combined.data(), iv, IV_SIZE);
                memcpy(combined.data() + IV_SIZE, mac, TAG_SIZE);
                memcpy(combined.data() + IV_SIZE + TAG_SIZE, ciphertext.data(), ciphertext.size());


                if (!write_file(encrypted_file, combined.data(), combined.size())) {
                    printf("Failed to write encrypted file.\n");
                    continue;
                }


                // Ask GCS URI
                printf("Enter GCS URI to upload: ");
                fgets(gcs_uri, sizeof(gcs_uri), stdin);
                gcs_uri[strcspn(gcs_uri, "\n")] = 0;

                if (!upload_to_gcs(encrypted_file, gcs_uri))
                    printf("Upload failed.\n");
                else
                    printf("Upload complete.\n");
            break;
            }
            case 2: {
                // Check if the encrypted file should be downloaded or used locally
                printf("Enter GCS URI to check/download encrypted file: ");
                fgets(gcs_uri, sizeof(gcs_uri), stdin);
                gcs_uri[strcspn(gcs_uri, "\n")] = 0;

                // Check if the remote file is newer or local doesn't exist
                if (access(encrypted_file, F_OK) != 0 || is_remote_newer(gcs_uri, encrypted_file)) {
                    printf("Downloading the most recent file from GCS...\n");
                    if (!download_from_gcs(gcs_uri, encrypted_file)) {
                        printf("Download failed.\n");
                        continue;
                    }
                } else {
                    printf("Local file is up-to-date. Using local copy.\n");
                }

                size_t total_len;
                uint8_t* full_data = (uint8_t*)read_file(encrypted_file, &total_len);
                if (!full_data || total_len < (IV_SIZE + TAG_SIZE)) {
                    printf("Encrypted file is invalid or corrupted.\n");
                    if (full_data) free(full_data);
                    continue;
                }

                memcpy(iv, full_data, IV_SIZE);  // get IV
                memcpy(mac, full_data + IV_SIZE, TAG_SIZE);  // get MAC

                uint8_t* ciphertext = full_data + IV_SIZE + TAG_SIZE;
                size_t ciphertext_len = total_len - IV_SIZE - TAG_SIZE;


                stats_menu();
                int op;
                scanf("%d", &op);
                getchar();

                double result;
                sgx_status_t retval;

                ret = ecall_process_stats(
                    eid, &retval,
                    ciphertext, ciphertext_len,
                    iv, IV_SIZE,
                    mac,
                    op, &result
                );

                free(full_data);

                if (ret == SGX_SUCCESS && retval == SGX_SUCCESS)
                    printf("Result: %.2f\n", result);
                else
                    printf("Failed to compute stat. SGX error: 0x%x\n", ret);
                break;
            }
            case 0: {
                printf("Exiting...\n");
                sgx_destroy_enclave(eid);
                return 0;
            }
            default: {
                printf("Invalid option. Try again.\n");
                break;
            }
        }
    }

    sgx_destroy_enclave(eid);
    return 0;
}
