#include <stdio.h>
#include <sgx_urts.h>
#include "Enclave_u.h"

#define ENCLAVE_FILE "enclave.signed.so"

sgx_enclave_id_t eid = 0;

// OCALL that enclave calls
void ocall_printf(const char* str) {
    printf("%s", str);
}

void menu() {
    printf("\nSecure SGX Data Lake\n");
    printf("====================\n");
    printf("1. Compute average patient age\n");
    printf("0. Exit\n");
    printf("Choose an option: ");
}

char* read_file(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) return NULL;

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);

    char* buffer = (char*) malloc(size + 1);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    fread(buffer, 1, size, file);
    buffer[size] = '\0';
    fclose(file);
    return buffer;
}

char* download_csv(const char* gcs_uri, const char* local_file) {
    char command[512];
    snprintf(command, sizeof(command), "gsutil cp %s %s", gcs_uri, local_file);
    int result = system(command);

    if (result != 0) {
        printf("Failed to download from GCS: %s\n", gcs_uri);
        return NULL;
    }

    char* encrypted_data = read_file(local_file);
    if (!encrypted_data) {
        printf("Failed to read downloaded file: %s\n", local_file);
        return NULL;
    }

    return encrypted_data;
}

const char* encrypted_hospital_csv = "<encrypted_hospital_data_placeholder>";
const char* encrypted_lab_csv = "<encrypted_lab_data_placeholder>";

int main() {
    sgx_status_t ret;

    // Create enclave
    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Error creating enclave: 0x%x\n", ret);
        return -1;
    }

    int option = -1;
    while (1) {
        menu();
        scanf("%d", &option);
        getchar(); // consume newline

        switch (option) {
            case 1: {
                char* encrypted_data = download_csv("gs://hospital-dataa/hospital.csv.gpg", "data/hospital.csv.gpg");
                if(encrypted_data != NULL)
                break;
            }
            case 0: {
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
