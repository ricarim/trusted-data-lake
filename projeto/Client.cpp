#include <iostream>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <fstream>
#include <fcntl.h>
#include <sys/stat.h>

#define AUTH_REQUEST_FILE "/tmp/sgx_auth_request"
#define AUTH_RESPONSE_FILE "/tmp/sgx_authorization"
#define RESPONSE_PIPE "/tmp/sgx_response"

void show_menu() {
    std::cout << "\n==== SGX Client Menu ====" << std::endl;
    std::cout << "1. Encrypt and upload CSV" << std::endl;
    std::cout << "2. Compute statistic" << std::endl;
    std::cout << "0. Exit" << std::endl;
    std::cout << "Choose an option: ";
}

void stats_menu() {
    std::cout << "\nStatistical Operations\n";
    std::cout << "=======================\n";
    std::cout << "1. Sum\n2. Mean\n3. Min\n4. Max\n5. Median\n6. Mode\n7. Variance\n8. Standard Deviation\n0. Back\n";
    std::cout << "Choose an operation: ";
}

std::string get_stat_name(int op) {
    switch (op) {
        case 1: return "sum";
        case 2: return "mean";
        case 3: return "min";
        case 4: return "max";
        case 5: return "median";
        case 6: return "mode";
        case 7: return "variance";
        case 8: return "stddev";
        default: return "unknown";
    }
}

void wait_for_authorization_request() {
    while (access(AUTH_REQUEST_FILE, F_OK) != 0) {
        usleep(100000); // espera 100ms
    }

    std::ifstream in(AUTH_REQUEST_FILE);
    std::string message;
    std::getline(in, message);
    in.close();
    std::remove(AUTH_REQUEST_FILE);

    std::string answer;
    std::cout << "\n[Authorization Request] " << message << std::endl;
    std::cout << "Approve? (yes/no): ";
    std::getline(std::cin, answer);

    std::ofstream out(AUTH_RESPONSE_FILE);
    out << answer << std::endl;
    out.close();
}

void read_sgx_response() {
    while (access(RESPONSE_PIPE, F_OK) != 0) {
        usleep(100000);
    }

    std::ifstream resp(RESPONSE_PIPE);
    if (!resp.is_open()) {
        std::cerr << "[Client] Failed to open sgx_response.\n";
        return;
    }

    std::cout << "\n[Client] Response from SGX app:\n";
    std::string line;
    while (std::getline(resp, line)) {
        std::cout << "  " << line << "\n";
    }
    resp.close();
    std::remove(RESPONSE_PIPE);

}

int main() {
    while (true) {
        show_menu();
        int choice;
        std::cin >> choice;
        std::cin.ignore();

        if (choice == 0) {
            std::cout << "Exiting client.\n";
            break;
        }

        std::string filename;
        std::cout << "Enter CSV file name: ";
        std::getline(std::cin, filename);

        if (choice == 1) {
            std::string cmd = "ssh localhost \"echo 'encrypt " + filename + "' > /tmp/sgx_pipe\"";
            std::cout << "\n[Client] Sending encrypt/upload command via SSH...\n";
            system(cmd.c_str());

        } else if (choice == 2) {
            stats_menu();
            int stat_op;
            std::cin >> stat_op;
            std::cin.ignore();

            if (stat_op == 0) continue;

            std::string stat_name = get_stat_name(stat_op);
            if (stat_name == "unknown") {
                std::cout << "Invalid statistic operation.\n";
                continue;
            }

            // Envia comando antes de responder à autorização
            std::string cmd = "ssh localhost \"echo 'stat " + stat_name + " " + filename + "' > /tmp/sgx_pipe\"";
            std::cout << "\n[Client] Sending stat command via SSH...\n";
            system(cmd.c_str());

            wait_for_authorization_request();
            read_sgx_response();
        } else {
            std::cout << "Invalid option. Try again.\n";
        }
    }
    return 0;
}

