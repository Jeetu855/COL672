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
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <thread>

#define BUFFER_SIZE 10240
using json = nlohmann::json;

// Client parameters struct
struct ClientParams {
    std::string server_ip;
    int server_port;
    int k;  // Number of words to request
    int p;  // Number of words in a packet
};

// Function for each client thread
void *client_thread(void *arg) {
    ClientParams *params = (ClientParams *)arg;
    int s, offset = 0;
    struct sockaddr_in sock;
    char buffer[BUFFER_SIZE];
    char request[100];
    int bytes_read;

    // Create the socket
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        std::cerr << "socket() error\n";
        pthread_exit(nullptr);
    }

    // Configure the server address
    sock.sin_addr.s_addr = inet_addr(params->server_ip.c_str());
    sock.sin_port = htons(params->server_port);
    sock.sin_family = AF_INET;

    // Connect to the server
    if (connect(s, (struct sockaddr *)&sock, sizeof(sock)) != 0) {
        std::cerr << "connect() error\n";
        close(s);
        pthread_exit(nullptr);
    }

    // Communicate with the server, sending offset and receiving words
    while (true) {
        snprintf(request, sizeof(request), "%d", offset);
        if (write(s, request, strlen(request)) < 0) {
            std::cerr << "write() error\n";
            close(s);
            pthread_exit(nullptr);
        }

        std::cout << "Client requesting words from offset " << offset << "...\n";

        int words_received = 0;
        bool eof_received = false;
        std::string response_str = "";

        while (words_received < params->k && (bytes_read = read(s, buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes_read] = '\0';
            response_str += buffer;

            // Count the number of words received in the buffer
            int word_count = 0;
            for (int i = 0; buffer[i] != '\0'; i++) {
                if (buffer[i] == ',') {
                    word_count++;
                }
            }
            words_received += word_count + 1;

            if (strstr(buffer, "EOF") != NULL) {
                std::cout << "EOF received.\n";
                eof_received = true;
                break;
            }

            if (words_received >= params->k) {
                break;
            }
        }

        if (bytes_read < 0) {
            std::cerr << "read() error\n";
            close(s);
            pthread_exit(nullptr);
        }

        std::cout << "Client received: " << response_str << "\n";

        // If EOF was received, break out of the loop
        if (eof_received) {
            break;
        }

        // Increment the offset by k for the next request
        offset += params->k;
        std::cout << "Client sending new request with offset " << offset << "\n";
    }

    close(s);  // Close socket after EOF received
    pthread_exit(nullptr);
}

int main() {
    // Read configuration from the config file
    std::ifstream config_file("config.json");
    if (!config_file.is_open()) {
        std::cerr << "Failed to open config.json\n";
        return -1;
    }

    json config;
    config_file >> config;

    std::string IP = config["server_ip"];
    int PORT = config["server_port"];
    int MAX_WORDS = config["k"];
    int NUM_CLIENTS = config["num_clients"];

    ClientParams params = {IP, PORT, MAX_WORDS, config["p"]};

    std::vector<pthread_t> client_threads(NUM_CLIENTS);

    // Create multiple client threads, each with a 10ms delay
    for (int i = 0; i < NUM_CLIENTS; ++i) {
        pthread_create(&client_threads[i], nullptr, client_thread, &params);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));  // Delay between clients
    }

    // Wait for all client threads to finish
    for (int i = 0; i < NUM_CLIENTS; ++i) {
        pthread_join(client_threads[i], nullptr);
    }

    return 0;
}
