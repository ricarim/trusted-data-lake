#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <iostream>
#include <vector>
#include <string>

// Decode base64
std::vector<uint8_t> base64_decode(const std::string& b64) {
    BIO* bio = BIO_new_mem_buf(b64.data(), b64.size());
    BIO* b64bio = BIO_new(BIO_f_base64());
    BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64bio, bio);

    std::vector<uint8_t> out(b64.size()); // max possible
    int len = BIO_read(bio, out.data(), out.size());
    out.resize(len > 0 ? len : 0);

    BIO_free_all(bio);
    return out;
}

// Load PEM public key from file
EVP_PKEY* load_public_key(const std::string& path) {
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) return nullptr;
    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    return pkey;
}

// Verify signature
bool verify_signature(const std::string& message, const std::vector<uint8_t>& signature, EVP_PKEY* pkey) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0 ||
        EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    int res = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(ctx);
    return res == 1;
}

int main() {
    std::string public_key_path = "sgx/hospital_keys/hospital_public.pem";
    std::string message = "stat|hospital|sum|gs://enclave_bucket/encrypted.bin";
    std::string signature_base64 = "OeB+BaFbEKwQYIVeWKXc3toYtCWGKcRkjuYDsB6ZEXUbAXyF7KUALvBjvftrkDcFLvHvn5SUWITw/4Ko36V9GCS7qZ1MDp3yxa5BNo0vdYv58G+o8min8SpuXeDWD6MRwJWNDVvuY9lD4C3Dcx7ireZ35WXMXN1D5qjfJ6sNJ6xY25M0YUE9+HJAjXVaGsNuqkgvzJzLz04r2aIe7bqhseu66QSC80GzWJOwd7Mof+AuWqjYzAEaXDgeAKdJTKiMSTjKyP1wTfXCkY8qHiTR9gIiyao+Qp+JVVGF/WC2POqJy14iudDy16cvsI2W2//MkdVnrxk4jSbFZcra7x84Nvc5JZQcPeD9osw2ROdv+FFUky9pdGWZdJ0+up8jV0YSdwJs/kKnlVcKfo3MiQEa+oLY8wj6Y6scq7kZk6GOysmjTn3bLji8R40BtDfvRfb0galX88Mb32JuhNgR0bbZjsFaWJ81oju65/GbplnbqeH1uLPBHssv2i5e5Cu2L7DY";

    EVP_PKEY* pubkey = load_public_key(public_key_path);
    if (!pubkey) {
        std::cerr << "Failed to load public key\n";
        return 1;
    }

    std::vector<uint8_t> sig_bin = base64_decode(signature_base64);
    if (verify_signature(message, sig_bin, pubkey))
        std::cout << "✅ Signature is VALID\n";
    else
        std::cout << "❌ Signature is INVALID\n";

    EVP_PKEY_free(pubkey);
    return 0;
}

