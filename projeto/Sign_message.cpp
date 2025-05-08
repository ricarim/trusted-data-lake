#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

std::string base64_encode(const std::vector<unsigned char>& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // no line breaks
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);

    BIO_write(b64, data.data(), data.size());
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(mem, &bptr);
    std::string encoded(bptr->data, bptr->length);
    BIO_free_all(b64);
    return encoded;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: ./sign_message <private_key.pem> <message_string> <output_file.b64>\n";
        return 1;
    }

    const char* key_path = argv[1];
    std::string message = argv[2];
    const char* output_path = argv[3];

    FILE* key_file = fopen(key_path, "r");
    if (!key_file) {
        std::cerr << "Failed to open key file: " << key_path << "\n";
        return 1;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(key_file, nullptr, nullptr, nullptr);
    fclose(key_file);
    if (!pkey) {
        std::cerr << "Failed to load private key.\n";
        return 1;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return 1;

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        std::cerr << "DigestSignInit failed\n";
        return 1;
    }

    if (EVP_DigestSignUpdate(ctx, message.data(), message.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        std::cerr << "DigestSignUpdate failed\n";
        return 1;
    }

    size_t sig_len = 0;
    EVP_DigestSignFinal(ctx, nullptr, &sig_len);
    std::vector<unsigned char> sig(sig_len);
    if (EVP_DigestSignFinal(ctx, sig.data(), &sig_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        std::cerr << "DigestSignFinal failed\n";
        return 1;
    }

    sig.resize(sig_len);
    std::string b64sig = base64_encode(sig);

    // Save to output file
    std::ofstream outfile(output_path);
    if (!outfile) {
        std::cerr << "Failed to open output file: " << output_path << "\n";
        return 1;
    }
    outfile << b64sig;
    outfile.close();

    std::cout << "[+] Signature saved to: " << output_path << "\n";

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 0;
}

