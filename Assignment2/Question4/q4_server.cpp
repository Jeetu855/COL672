#include <arpa/inet.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <pthread.h>
#include <queue>
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#define BUFFER_SIZE 10240
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
std::queue<int> client_queue;
int client_id_counter = 1;

using json = nlohmann::json;

void handle_sigpipe(int sig) {
    std::cout << "Caught SIGPIPE (Client disconnected abruptly)\n";
}

void *serve_client(void *arg) {
    std::vector<std::string> *words_ptr = (std::vector<std::string> *)arg;
    std::vector<std::string> &words = *words_ptr;

    while (true) {
        pthread_mutex_lock(&queue_mutex);
        if (!client_queue.empty()) {
            int client_socket = client_queue.front();
            client_queue.pop();
            pthread_mutex_unlock(&queue_mutex);

            char buffer[BUFFER_SIZE];
            int client_id = client_id_counter++;

            std::string output_filename = "output_" + std::to_string(client_id) + ".txt";
            std::ofstream output_file(output_filename);
            if (!output_file.is_open()) {
                std::cerr << "Failed to open output file for client " << client_id << "\n";
                close(client_socket);
                continue;
            }

            std::cout << "Serving client with ID: " << client_id << "\n";

            int offset = 0;
            std::unordered_map<std::string, int> word_frequency;

            while (true) {
                ssize_t bytes_from_client = read(client_socket, buffer, BUFFER_SIZE - 1);
                if (bytes_from_client <= 0) {
                    std::cout << "Client " << client_id << " disconnected\n";
                    break;
                }
                buffer[bytes_from_client] = '\0';

                offset = strtol(buffer, NULL, 10);
                std::cout << "Received offset " << offset << " from client " << client_id << "\n";

                std::ostringstream response;
                int k = 10;
                int words_to_send = std::min(k, static_cast<int>(words.size()) - offset);

                if (offset < static_cast<int>(words.size())) {
                    for (int i = 0; i < words_to_send; ++i) {
                        const std::string &current_word = words[offset + i];
                        if (current_word != "EOF") {  // Skip EOF entirely
                            response << current_word;
                            if (i < words_to_send - 1) {
                                response << ',';
                            }
                            word_frequency[current_word]++;
                        }
                    }

                    std::string response_str = response.str() + '\n';

                    ssize_t bytes_sent = write(client_socket, response_str.c_str(), response_str.size());
                    if (bytes_sent == -1) {
                        std::cerr << "Error writing to client " << client_id << "\n";
                        break;
                    }

                    std::cout << "Bytes sent to client " << client_id << ": " << bytes_sent << "\n";

                    if (offset + words_to_send >= static_cast<int>(words.size())) {
                        std::cout << "End of word list reached for client " << client_id << "\n";
                        break;
                    }
                } else {
                    std::cout << "Offset beyond word list size, ending connection.\n";
                    break;
                }
            }

            for (const auto &entry : word_frequency) {
                output_file << entry.first << "," << entry.second << "\n";
            }

            close(client_socket);
            output_file.close();
        } else {
            pthread_mutex_unlock(&queue_mutex);
        }
    }
    return nullptr;
}

void *accept_clients(void *arg) {
    int server_socket = *((int *)arg);
    struct sockaddr_in client;
    socklen_t addrlen = sizeof(client);

    while (true) {
        int client_socket = accept(server_socket, (struct sockaddr *)&client, &addrlen);
        if (client_socket < 0) {
            std::cerr << "accept() error\n";
            continue;
        }

        std::cout << "New client connected, added to queue\n";

        pthread_mutex_lock(&queue_mutex);
        client_queue.push(client_socket);
        pthread_mutex_unlock(&queue_mutex);
    }
    return nullptr;
}

int main() {
    signal(SIGPIPE, handle_sigpipe);

    std::ifstream config_file("config.json");
    if (!config_file.is_open()) {
        std::cerr << "Failed to open config.json\n";
        return -1;
    }

    json config;
    config_file >> config;

    std::string IP = config["server_ip"];
    int PORT = config["server_port"];
    int num_clients = config["num_clients"];
    std::string input_file = config["input_file"];
    int k = config["k"];

    std::vector<std::string> words;
    std::ifstream input_stream(input_file);
    if (!input_stream.is_open()) {
        std::cerr << "Failed to open input file: " << input_file << "\n";
        return -1;
    }

    std::string word;
    while (std::getline(input_stream, word, ',')) {
        if (word != "EOF") {  // Skip "EOF" when reading the file
            words.push_back(word);
        }
    }
    input_stream.close();

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        std::cerr << "socket() error\n";
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(IP.c_str());
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        std::cerr << "bind() error\n";
        close(server_socket);
        return -1;
    }

    if (listen(server_socket, num_clients) != 0) {
        std::cerr << "listen() error\n";
        close(server_socket);
        return -1;
    }

    std::cout << "Server listening on " << IP << ":" << PORT << "\n";

    pthread_t accept_thread;
    pthread_create(&accept_thread, nullptr, accept_clients, &server_socket);

    pthread_t serve_thread;
    pthread_create(&serve_thread, nullptr, serve_client, &words);

    pthread_join(accept_thread, nullptr);
    pthread_join(serve_thread, nullptr);

    close(server_socket);
    return 0;
}
