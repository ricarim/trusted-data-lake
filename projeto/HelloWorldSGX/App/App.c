#include <stdio.h>
#include <sgx_urts.h>
#include "Enclave_u.h"

#define ENCLAVE_FILE "enclave.signed.so"

sgx_enclave_id_t eid = 0;

// OCALL que o enclave chama
void ocall_printf(const char* str) {
    printf("%s", str);
}

int main() {
    sgx_status_t ret;

    // Cria enclave
    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Erro ao criar enclave: 0x%x\n", ret);
        return -1;
    }

    // Chama ECALL
    ecall_entrypoint(eid);

    // Destroi enclave
    sgx_destroy_enclave(eid);
    return 0;
}

