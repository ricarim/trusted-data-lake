#include <stdio.h>
#include <sgx_urts.h>
#include "Enclave_u.h"

#define ENCLAVE_FILE "enclave.signed.so"

sgx_enclave_id_t eid = 0;

// OCALL that enclave calls
void ocall_printf(const char* str) {
    printf("%s", str);
}

int main() {
    sgx_status_t ret;

    // Create enclave
    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Error creating enclave: 0x%x\n", ret);
        return -1;
    }

    // Calls ECALL
    ecall_entrypoint(eid);

    sgx_destroy_enclave(eid);
    return 0;
}

