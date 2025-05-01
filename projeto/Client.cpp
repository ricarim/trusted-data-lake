#include <openssl/evp.h>
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
#define AUTH_RESPONSE_FILE_A "/tmp/sgx_authorization_A"
#define AUTH_RESPONSE_FILE_B "/tmp/sgx_authorization_B"

std::string gcs_path = "gs://enclave_bucket/";

std::string other_id(const std::string& id) {
    return id == "lab" ? "hospital" : "lab";
}

EVP_PKEY* load_private_key(const std::string& keyfile) {
    FILE* fp = fopen(keyfile.c_str(), "r");
    if (!fp) return nullptr;
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
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

    size_t sig_len = 0;
    EVP_DigestSignFinal(ctx, nullptr, &sig_len);
    std::vector<unsigned char> sig(sig_len);

    if (EVP_DigestSignFinal(ctx, sig.data(), &sig_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_MD_CTX_free(ctx);

    // Base64 encode
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_write(b64, sig.data(), sig_len);
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(mem, &bptr);
    std::string b64sig(bptr->data, bptr->length);  // remove \0

    BIO_free_all(b64);
    return b64sig;
}

void show_menu() {
    std::cout << "\n==== SGX Client Menu ====\n";
    std::cout << "1. Encrypt and upload CSV\n";
    std::cout << "2. Compute statistic\n";
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

void wait_for_authorization(const std::string& id) {
    std::string file = "/tmp/sgx_auth_request_" + id;
    while (access(file.c_str(), F_OK) != 0) {
        usleep(100000);
    }

    std::ifstream in(file);
    std::string message;
    std::getline(in, message);
    in.close();
    std::remove(file.c_str());

    std::string answer;
    std::cout << "\n[Auth Request for you] " << message << "\nApprove? (yes/no): ";
    std::getline(std::cin, answer);

    std::string auth_resp = "/tmp/sgx_authorization_" + id;
    std::ofstream out(auth_resp);
    out << answer << std::endl;
    out.close();
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
        std::cerr << "Usage: ./client <hospital|lab>\\n";
        return 1;
    }

    std::string client_id = argv[1];
    if (client_id != "hospital" && client_id != "lab") {
        std::cerr << "Client ID must be 'hospital' or 'lab'\n";
        return 1;
    }


    std::string key_path = client_id + "_private.pem";
    EVP_PKEY* pkey = load_private_key(key_path);
    if (!pkey) {
        std::cerr << "Failed to load private key: " << key_path << "\n";
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

            std::string message = "encrypt|" + client_id + "|" + filename + "|" + gcs_path;
            std::string sig = sign_message(message, pkey);
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

            std::string message = "stat|" + client_id + "|" + stat + "|" + gcs_path + ""+gcs_file;
            std::string sig = sign_message(message, pkey);

            std::ostringstream cmd;
            cmd << "ssh localhost \"echo '" << message << "|" << sig << "' > " << PIPE_PATH << "\"";

            system(cmd.str().c_str());

            wait_for_authorization(other_id(client_id));
            read_response();
        }
    }

    EVP_PKEY_free(pkey);
    return 0;
}

