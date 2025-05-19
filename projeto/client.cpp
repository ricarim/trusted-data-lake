#include <openssl/evp.h>
#include <algorithm>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <unistd.h>
#include <sstream>
#include <sys/stat.h>

#define PIPE_PATH "/tmp/sgx_pipe"
#define RESPONSE_PIPE "/tmp/sgx_response"
#define AUTH_REQUEST_FILE_A "/tmp/sgx_auth_request_A"
#define AUTH_REQUEST_FILE_B "/tmp/sgx_auth_request_B"

std::string gcs_path = "gs://enclave_bucket/";

std::string other_id(const std::string& id) {
    return id == "lab" ? "hospital" : "lab";
}

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


void show_menu() {
    std::cout << "\n==== SGX Client Menu ====\n";
    std::cout << "1. Encrypt and upload CSV\n";
    std::cout << "2. Compute statistic\n";
    std::cout << "3. Send my key to enclave\n";
    std::cout << "0. Exit\n";
    std::cout << "Choose an option: ";
}

void stats_menu() {
    std::cout << "\nStatistical Operations\n";
    std::cout << "1. Sum\n2. Mean\n3. Min\n4. Max\n5. Median\n6. Mode\n7. Variance\n8. Std Dev\n0. Back\n";
    std::cout << "Choose an operation: ";
}

std::string get_stat_name(int op) {
    switch (op) {
        case 1: return "sum"; case 2: return "mean"; case 3: return "min"; case 4: return "max";
        case 5: return "median"; case 6: return "mode"; case 7: return "variance"; case 8: return "stddev";
        default: return "unknown";
    }
}


void read_response() {
    while (access(RESPONSE_PIPE, F_OK) != 0) {
        usleep(10000);
    }

    std::ifstream resp(RESPONSE_PIPE);
    if (!resp.is_open()) return;

    std::cout << "\n[Client] Response from SGX App:\n";
    std::string line;
    while (std::getline(resp, line)) {
        std::cout << "  " << line << "\n";
    }
    resp.close();
    std::remove(RESPONSE_PIPE);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ./client <hospital|lab>\n";
        return 1;
    }

    std::string client_id = argv[1];
    if (client_id != "hospital" && client_id != "lab") {
        std::cerr << "Client ID must be 'hospital' or 'lab'\n";
        return 1;
    }


    std::string key_path = "ecc_" + client_id + "_privkey.bin";
    EVP_PKEY* pkey = load_private_key(key_path);
    if (!pkey) {
        std::cerr << "Failed to load private key: " << key_path << "\n";
        ERR_print_errors_fp(stderr);
        return 1;
    }

    while (true) {
        show_menu();
        int choice;
        std::cin >> choice;
        std::cin.ignore();

        if (choice == 0) break;


        if (choice == 1) {
            std::string filename;
            std::cout << "Enter CSV file name: ";
            std::getline(std::cin, filename);

	    std::ifstream infile(filename, std::ios::binary);
	    std::ostringstream contents;
	    contents << infile.rdbuf();
	    if (!infile.is_open()) {
	    	std::cerr << "Error: Failed to open file '" << filename << "'\n";
	    	continue;
	    }
 	    std::string raw_data = contents.str();
	    if (!infile.is_open()) {
	    	std::cerr << "Error: Failed to open file '" << filename << "'\n";
	    	continue;
	    }

	    BIO* b64 = BIO_new(BIO_f_base64());
	    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
       	    BIO* mem = BIO_new(BIO_s_mem());
	    BIO* chain = BIO_push(b64, mem);
	    BIO_write(chain, raw_data.data(), raw_data.size());
	    BIO_flush(chain);
	    BUF_MEM* bptr;
	    BIO_get_mem_ptr(mem, &bptr);
	    std::string base64_file(bptr->data, bptr->length);
	    BIO_free_all(chain);


            time_t now = time(nullptr);
            std::string message = "encrypt|" + client_id + "|" + base64_file + "|" + gcs_path + "|" + std::to_string(now);
            std::cout << "message: " << message << "\n";
            std::string sig = sign_message(message, pkey);

            auto sanitize = [](std::string& s) {
                s.erase(std::remove(s.begin(), s.end(), '\n'), s.end());
                s.erase(std::remove(s.begin(), s.end(), '\r'), s.end());
                s.erase(std::remove(s.begin(), s.end(), ' '), s.end());
            };
            sanitize(sig);

            std::ostringstream cmd;
            cmd << "ssh localhost \"echo '" << message << "|" << sig << "' > " << PIPE_PATH << "\"";
            system(cmd.str().c_str());
        } else if (choice == 2) {
            stats_menu();
            int op;
            std::cin >> op;
            std::cin.ignore();

            std::string stat = get_stat_name(op);
            if (stat == "unknown") continue;

            std::string gcs_file;
            std::cout << "Enter GCS file: ";
            std::getline(std::cin, gcs_file);

            std::string column;
            std::cout << "Enter the column name (e.g., 'age', 'gender'): ";
            std::getline(std::cin, column);  

            time_t now = time(nullptr);
            std::string message = "stat|" + client_id + "|"+ column +"|"+ stat + "|" + gcs_path + ""+gcs_file + "|" + std::to_string(now);
            std::cout << "message: " << message << "\n";
            std::string sig = sign_message(message, pkey);

            std::string sig_path;
            std::cout << "Enter path to other party's signature file: ";
            std::getline(std::cin, sig_path);

            std::ifstream f(sig_path);
            std::stringstream buf;
            buf << f.rdbuf();
            std::string other_sig = buf.str();

            auto sanitize = [](std::string& s) {
                s.erase(std::remove(s.begin(), s.end(), '\n'), s.end());
                s.erase(std::remove(s.begin(), s.end(), '\r'), s.end());
                s.erase(std::remove(s.begin(), s.end(), ' '), s.end());
            };
            sanitize(sig);
            sanitize(other_sig);

            std::string full_msg = message + "|" + sig + "|" + other_sig;

            std::ostringstream cmd;
            cmd << "ssh localhost \"echo '" << message << "|" << sig << "|" << other_sig << "' > " << PIPE_PATH << "\"";

            system(cmd.str().c_str());

            read_response();
        }else if(choice == 3){
	    std::ifstream key_file(key_path, std::ios::binary);
	    if (!key_file) {
		std::cerr << "Failed to open key file: " << key_path << "\n";
		continue;
	    }

	    std::vector<unsigned char> key_bytes(32);
	    key_file.read((char*)key_bytes.data(), 32);
	    if (key_file.gcount() != 32) {
		std::cerr << "Invalid key length in file\n";
		continue;
	    }

	    BIO* b64 = BIO_new(BIO_f_base64());
	    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	    BIO* mem = BIO_new(BIO_s_mem());
	    BIO* chain = BIO_push(b64, mem);
	    BIO_write(chain, key_bytes.data(), key_bytes.size());
	    BIO_flush(chain);
	    BUF_MEM* bptr;
	    BIO_get_mem_ptr(mem, &bptr);
	    std::string key_b64(bptr->data, bptr->length);
	    BIO_free_all(chain);

	    auto sanitize = [](std::string& s) {
		s.erase(std::remove(s.begin(), s.end(), '\n'), s.end());
		s.erase(std::remove(s.begin(), s.end(), '\r'), s.end());
		s.erase(std::remove(s.begin(), s.end(), ' '), s.end());
	    };
	    sanitize(key_b64);

	    std::ostringstream cmd;
	    cmd << "ssh localhost \"echo 'addkey|" << key_b64 << "' > " << PIPE_PATH << "\"";
	    system(cmd.str().c_str());

	    std::cout << "[Client] Sent symmetric key to enclave.\n";
	}
    }

    EVP_PKEY_free(pkey);
    return 0;
}

