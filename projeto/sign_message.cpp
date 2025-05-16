#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

EVP_PKEY* load_private_key(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return nullptr;

    std::vector<unsigned char> priv_bytes(32);
    file.read((char*)priv_bytes.data(), 32);
    if (file.gcount() != 32) return nullptr;

    BIGNUM* priv_bn = BN_bin2bn(priv_bytes.data(), 32, nullptr);
    if (!priv_bn) return nullptr;

    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);  // NIST P-256
    if (!EC_KEY_set_private_key(ec_key, priv_bn)) {
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        return nullptr;
    }

    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    EC_POINT* pub_key = EC_POINT_new(group);
    if (!EC_POINT_mul(group, pub_key, priv_bn, nullptr, nullptr, nullptr)) {
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        EC_POINT_free(pub_key);
        return nullptr;
    }

    EC_KEY_set_public_key(ec_key, pub_key);
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec_key);

    BN_free(priv_bn);
    EC_POINT_free(pub_key);
    return pkey;
}


std::string sign_message(const std::string& message, EVP_PKEY* pkey) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    if (EVP_DigestSignUpdate(ctx, message.c_str(), message.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    size_t siglen = 0;
    EVP_DigestSignFinal(ctx, nullptr, &siglen);
    std::vector<unsigned char> der(siglen);
    if (EVP_DigestSignFinal(ctx, der.data(), &siglen) <= 0) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    der.resize(siglen);
    EVP_MD_CTX_free(ctx);

    const unsigned char* p = der.data();
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, der.size());
    if (!sig) return "";

    const BIGNUM *r, *s;
    ECDSA_SIG_get0(sig, &r, &s);

    std::vector<uint8_t> rs(64);
    BN_bn2lebinpad(r, rs.data(), 32);      // Little endian r
    BN_bn2lebinpad(s, rs.data() + 32, 32); // Little endian s
    ECDSA_SIG_free(sig);

    // Base64 encode
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* mem = BIO_new(BIO_s_mem());
    BIO* bio_chain = BIO_push(b64, mem);

    BIO_write(bio_chain, rs.data(), rs.size());
    BIO_flush(bio_chain);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(mem, &bptr);
    std::string b64sig(bptr->data, bptr->length);

    BIO_free_all(bio_chain);
    return b64sig;
}


int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: ./sign_message <private_key.bin> <message_string> <output_file.b64>\n";
        return 1;
    }

    const char* key_path = argv[1];
    std::string message = argv[2];
    const char* output_path = argv[3];

    EVP_PKEY* pkey = load_private_key(key_path);
    if (!pkey) {
        std::cerr << "Failed to load private key from binary.\n";
        ERR_print_errors_fp(stderr);
        return 1;
    }

    std::string sig = sign_message(message, pkey);

    std::ofstream outfile(output_path);
    if (!outfile) {
        std::cerr << "Failed to open output file: " << output_path << "\n";
        return 1;
    }
    outfile << sig;
    outfile.close();

    std::cout << "[+] Signature saved to: " << output_path << "\n";


    return 0;
}

