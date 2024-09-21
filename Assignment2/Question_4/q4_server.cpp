
#include <arpa/inet.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <pthread.h>
#include <queue>
#include <signal.h>
#include <sstream>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#define BUF_SIZE 10240
pthread_mutex_t mutex_lock = PTHREAD_MUTEX_INITIALIZER;
std::queue<int> socket_queue;
int client_id_seq = 1;

using json = nlohmann::json;

void sigpipe_handler(int sig) {
    std::cout << "SIGPIPE caught: Client disconnected unexpectedly.\n";
}

void* client_handler(void* arg) {
    auto* data_pair = static_cast<std::pair<std::vector<std::string>*, int>*>(arg);
    std::vector<std::string>* words_ptr = data_pair->first;
    int k_val = data_pair->second;
    std::vector<std::string>& words_list = *words_ptr;

    while (true) {
        pthread_mutex_lock(&mutex_lock);
        if (!socket_queue.empty()) {
            int client_sock = socket_queue.front();
            socket_queue.pop();
            pthread_mutex_unlock(&mutex_lock);

            char recv_buffer[BUF_SIZE];
            int client_id = client_id_seq++;

            std::string out_file = "output_" + std::to_string(client_id) + ".txt";
            std::ofstream outfile(out_file);
            if (!outfile.is_open()) {
                std::cerr << "Unable to open file for client " << client_id << "\n";
                close(client_sock);
                continue;
            }

            std::cout << "Processing client ID: " << client_id << "\n";

            int current_offset = 0;
            std::unordered_map<std::string, int> freq_map;

            while (true) {
                ssize_t read_bytes = read(client_sock, recv_buffer, BUF_SIZE - 1);
                if (read_bytes <= 0) {
                    std::cout << "Client " << client_id << " disconnected.\n";
                    break;
                }
                recv_buffer[read_bytes] = '\0';

                current_offset = std::stoi(recv_buffer);
                std::cout << "Client " << client_id << " sent offset " << current_offset << "\n";

                std::ostringstream resp_stream;
                int send_count = std::min(k_val, static_cast<int>(words_list.size()) - current_offset);

                if (current_offset < static_cast<int>(words_list.size())) {
                    for (int i = 0; i < send_count; ++i) {
                        const std::string& word = words_list[current_offset + i];
                        if (word != "EOF") {
                            resp_stream << word;
                            if (i < send_count - 1) {
                                resp_stream << ',';
                            }
                            freq_map[word]++;
                        }
                    }

                    std::string response = resp_stream.str() + '\n';
                    ssize_t sent_bytes = write(client_sock, response.c_str(), response.size());
                    if (sent_bytes == -1) {
                        std::cerr << "Error sending to client " << client_id << "\n";
                        break;
                    }

                    std::cout << "Sent " << sent_bytes << " bytes to client " << client_id << "\n";

                    if (current_offset + send_count >= static_cast<int>(words_list.size())) {
                        std::cout << "All words sent to client " << client_id << "\n";
                        break;
                    }
                } else {
                    std::cout << "Offset exceeds word list for client " << client_id << ".\n";
                    break;
                }
            }

            for (const auto& [word, count] : freq_map) {
                outfile << word << "," << count << "\n";
            }

            close(client_sock);
            outfile.close();
        } else {
            pthread_mutex_unlock(&mutex_lock);
        }
    }
    return nullptr;
}

void* connection_acceptor(void* arg) {
    int serv_sock = *((int*)arg);
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    while (true) {
        int new_sock = accept(serv_sock, (struct sockaddr*)&client_addr, &addr_len);
        if (new_sock < 0) {
            std::cerr << "Error on accept()\n";
            continue;
        }

        std::cout << "New client connected, enqueued.\n";

        pthread_mutex_lock(&mutex_lock);
        socket_queue.push(new_sock);
        pthread_mutex_unlock(&mutex_lock);
    }
    return nullptr;
}

int main() {
    signal(SIGPIPE, sigpipe_handler);

    std::ifstream cfg_file("config.json");
    if (!cfg_file.is_open()) {
        std::cerr << "Cannot open config.json\n";
        return -1;
    }

    json cfg_json;
    cfg_file >> cfg_json;

    std::string server_ip = cfg_json["server_ip"];
    int server_port = cfg_json["server_port"];
    int max_clients = cfg_json["num_clients"];
    std::string infile = cfg_json["input_file"];
    int k_param = cfg_json["k"];

    std::vector<std::string> word_list;
    std::ifstream in_stream(infile);
    if (!in_stream.is_open()) {
        std::cerr << "Cannot open input file: " << infile << "\n";
        return -1;
    }

    std::string word;
    while (std::getline(in_stream, word, ',')) {
        if (word != "EOF") {
            word_list.push_back(word);
        }
    }
    in_stream.close();

    int serv_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (serv_sock < 0) {
        std::cerr << "Socket creation failed.\n";
        return -1;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(server_ip.c_str());
    serv_addr.sin_port = htons(server_port);

    if (bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) != 0) {
        std::cerr << "Bind failed.\n";
        close(serv_sock);
        return -1;
    }

    if (listen(serv_sock, max_clients) != 0) {
        std::cerr << "Listen failed.\n";
        close(serv_sock);
        return -1;
    }

    std::cout << "Server running on " << server_ip << ":" << server_port << "\n";

    std::pair<std::vector<std::string>*, int> thread_args = {&word_list, k_param};

    pthread_t accept_tid;
    pthread_create(&accept_tid, nullptr, connection_acceptor, &serv_sock);

    pthread_t handler_tid;
    pthread_create(&handler_tid, nullptr, client_handler, &thread_args);

    pthread_join(accept_tid, nullptr);
    pthread_join(handler_tid, nullptr);

    close(serv_sock);
    return 0;
}
