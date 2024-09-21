
#include <arpa/inet.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <nlohmann/json.hpp>
#include <pthread.h>
#include <queue>
#include <signal.h>
#include <sstream>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <thread>

#define BUF_SIZE 10240
using json = nlohmann::json;

struct ClientSettings {
    std::string ip;
    int port;
    int k_words;
    int packet_size;
};

void* client_func(void* arg) {
    ClientSettings* settings = static_cast<ClientSettings*>(arg);
    int sock_fd, offset = 0;
    struct sockaddr_in server_addr;
    char recv_buf[BUF_SIZE];
    char req_buf[100];
    int read_bytes;

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        std::cerr << "Socket creation error\n";
        pthread_exit(nullptr);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(settings->port);
    server_addr.sin_addr.s_addr = inet_addr(settings->ip.c_str());

    if (connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        std::cerr << "Connection failed\n";
        close(sock_fd);
        pthread_exit(nullptr);
    }

    while (true) {
        snprintf(req_buf, sizeof(req_buf), "%d", offset);
        if (write(sock_fd, req_buf, strlen(req_buf)) < 0) {
            std::cerr << "Write failed\n";
            close(sock_fd);
            pthread_exit(nullptr);
        }

        std::cout << "Requesting words from offset " << offset << "...\n";

        int words_recv = 0;
        bool eof_flag = false;
        std::string resp_str = "";

        while (words_recv < settings->k_words && (read_bytes = read(sock_fd, recv_buf, sizeof(recv_buf) - 1)) > 0) {
            recv_buf[read_bytes] = '\0';
            resp_str += recv_buf;

            int cnt = 0;
            for (int i = 0; recv_buf[i] != '\0'; ++i) {
                if (recv_buf[i] == ',') {
                    cnt++;
                }
            }
            words_recv += cnt + 1;

            if (strstr(recv_buf, "EOF") != nullptr) {
                std::cout << "EOF encountered.\n";
                eof_flag = true;
                break;
            }

            if (words_recv >= settings->k_words) {
                break;
            }
        }

        if (read_bytes < 0) {
            std::cerr << "Read error\n";
            close(sock_fd);
            pthread_exit(nullptr);
        }

        std::cout << "Received: " << resp_str << "\n";

        if (eof_flag) {
            break;
        }

        offset += settings->k_words;
        std::cout << "Sending new offset " << offset << "\n";
    }

    close(sock_fd);
    pthread_exit(nullptr);
}

int main() {
    std::ifstream cfg_file("config.json");
    if (!cfg_file.is_open()) {
        std::cerr << "Cannot open config.json\n";
        return -1;
    }

    json cfg_json;
    cfg_file >> cfg_json;

    std::string server_ip = cfg_json["server_ip"];
    int server_port = cfg_json["server_port"];
    int max_words = cfg_json["k"];
    int client_count = cfg_json["num_clients"];

    ClientSettings settings = {server_ip, server_port, max_words, cfg_json["p"]};

    std::vector<pthread_t> threads(client_count);

    for (int i = 0; i < client_count; ++i) {
        pthread_create(&threads[i], nullptr, client_func, &settings);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    for (int i = 0; i < client_count; ++i) {
        pthread_join(threads[i], nullptr);
    }

    return 0;
}
