#include <stdio.h>
#include <string.h>
#include <sgx_urts.h>
#include <sgx_tcrypto.h>
#include "Enclave_u.h"

#define ENCLAVE_FILE "enclave.signed.so"


// Função utilitária para ler binários
bool read_binary(const char* path, void* buf, size_t len) {
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    size_t r = fread(buf, 1, len, f);
    fclose(f);
    return r == len;
}

int main() {
    sgx_enclave_id_t eid;
    sgx_launch_token_t token = {0};
    int updated = 0;

    if (sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL) != SGX_SUCCESS) {
        printf("Erro ao criar enclave.\n");
        return 1;
    }

    const char* msg = "mensagem para verificar";
    size_t msg_len = strlen(msg);

    // Carregar assinatura do arquivo (gerada fora do enclave)
    sgx_ec256_signature_t signature;
    if (!read_binary("assinatura.bin", &signature, sizeof(signature))) {
        printf("Erro ao carregar assinatura.bin\n");
        return 1;
    }

    // Verificar assinatura no enclave
    int result = 0;
    sgx_status_t ret = ecc_verify(eid, &result, (uint8_t*)msg, msg_len, &signature);
    if (ret != SGX_SUCCESS) {
        printf("Erro na chamada do enclave: 0x%x\n", ret);
        return 1;
    }

    if (result)
        printf("✔️  Assinatura VÁLIDA\n");
    else
        printf("❌  Assinatura INVÁLIDA\n");

    sgx_destroy_enclave(eid);
    return 0;
}

