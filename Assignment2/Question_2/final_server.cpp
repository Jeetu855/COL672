#include <arpa/inet.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <nlohmann/json.hpp>
#include <pthread.h>
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <algorithm>

#define BUFFER_LEN 10240
#define FILE_BUFFER_LEN 10240

int PACKET_SIZE = 10;
std::vector<std::string> data_words; 
int client_id_counter = 1;           
pthread_mutex_t client_id_mutex;     


void signal_handler(int signum) {
    std::cout << "SIGPIPE caught (Client disconnected abruptly)\n";
}


void send_data_to_client(int client_socket, int offset) {
    std::ostringstream response_stream;
    char send_buffer[BUFFER_LEN];
    size_t total_words = data_words.size();

    if (offset < static_cast<int>(total_words)) {
        for (size_t i = offset; i < total_words; i += PACKET_SIZE) {
            response_stream.str("");
            response_stream.clear();

            for (size_t j = 0; j < PACKET_SIZE && (i + j) < total_words; ++j) {
                response_stream << data_words[i + j];
                if ((i + j) < (total_words - 1) && j < (PACKET_SIZE - 1)) {
                    response_stream << ',';
                }
            }

            std::string response_str = response_stream.str() + '\n';
            ssize_t bytes_sent = write(client_socket, response_str.c_str(), response_str.size());
            printf("Bytes sent: %zd\n", bytes_sent);

            if (bytes_sent == -1) {
                std::cout << "Error in write()\n";
                break;
            } else if (bytes_sent != static_cast<ssize_t>(response_str.size())) {
                std::cout << "Partial write occurred\n";
            }
        }
 
        std::string eof_message = "EOF\n";
        write(client_socket, eof_message.c_str(), eof_message.size());
        std::cout << "Sent: " << eof_message;
    } else {
       
        std::string eof_message = "EOF\n";
        write(client_socket, eof_message.c_str(), eof_message.size());
        std::cout << "Sent: " << eof_message;
    }
}


void *client_handler(void *arg) {
    int client_socket = *(int *)arg;
    delete (int *)arg; 

  
    pthread_mutex_lock(&client_id_mutex);
    int client_id = client_id_counter++;
    pthread_mutex_unlock(&client_id_mutex);

    
    std::string id_message = std::to_string(client_id) + "\n";
    if (write(client_socket, id_message.c_str(), id_message.size()) < 0) {
        std::cout << "Failed to send client ID\n";
        close(client_socket);
        return NULL;
    }

    char recv_buffer[BUFFER_LEN]; 

    while (true) {
        ssize_t received_bytes = read(client_socket, recv_buffer, BUFFER_LEN - 1);
        if (received_bytes <= 0) {
            if (received_bytes == 0) {
                std::cout << "Client " << client_id << " disconnected\n";
            } else {
                std::cout << "Error in read()\n";
            }
            break;
        }
        recv_buffer[received_bytes] = '\0';

        int offset = atoi(recv_buffer); 
        std::cout << "Received offset from client " << client_id << ": " << offset << "\n";

        send_data_to_client(client_socket, offset);
        break;
    }
    close(client_socket);
    return NULL;
}

int main() {
    int server_socket, client_socket;
    signal(SIGPIPE, signal_handler);
    socklen_t addr_len;


    std::ifstream config_stream("config.json");
    if (!config_stream.is_open()) {
        std::cerr << "Cannot open config.json\n";
        return -1;
    }

    nlohmann::json config_json;
    config_stream >> config_json;

   
    std::string server_ip;
    int server_port, packet_size_config, max_words;
    std::string input_filename;

  
    if (config_json.contains("server_ip") && config_json["server_ip"].is_string()) {
        server_ip = config_json["server_ip"];
    } else {
        std::cerr << "Missing or invalid 'server_ip' in config.json\n";
        return -1;
    }

    if (config_json.contains("server_port") && config_json["server_port"].is_number_integer()) {
        server_port = config_json["server_port"];
    } else {
        std::cerr << "Missing or invalid 'server_port' in config.json\n";
        return -1;
    }

    if (config_json.contains("p") && config_json["p"].is_number_integer()) {
        packet_size_config = config_json["p"];
    } else {
        std::cerr << "Missing or invalid 'p' in config.json\n";
        return -1;
    }

    if (config_json.contains("k") && config_json["k"].is_number_integer()) {
        max_words = config_json["k"];
    } else {
        std::cerr << "Missing or invalid 'k' in config.json\n";
        return -1;
    }

    if (config_json.contains("input_file") && config_json["input_file"].is_string()) {
        input_filename = config_json["input_file"];
    } else {
        std::cerr << "Missing or invalid 'input_file' in config.json\n";
        return -1;
    }

   
    PACKET_SIZE = packet_size_config;

    
    if (pthread_mutex_init(&client_id_mutex, NULL) != 0) {
        std::cerr << "Mutex initialization failed\n";
        return -1;
    }

    
    std::ifstream input_file(input_filename);
    if (!input_file.is_open()) {
        std::cout << "Cannot open input file: " << input_filename << "\n";
        return -1;
    }

    std::string word;
    while (std::getline(input_file, word, ',')) {
        data_words.push_back(word);
    }
    input_file.close();

    
    struct sockaddr_in server_addr_struct, client_addr_struct;
    memset(&server_addr_struct, 0, sizeof(server_addr_struct));
    memset(&client_addr_struct, 0, sizeof(client_addr_struct));

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Error in socket()");
        return -1;
    }

    server_addr_struct.sin_family = AF_INET;
    server_addr_struct.sin_addr.s_addr = inet_addr(server_ip.c_str());
    server_addr_struct.sin_port = htons(server_port);

    if (bind(server_socket, (struct sockaddr *)&server_addr_struct, sizeof(server_addr_struct)) != 0) {
        perror("Error in bind()");
        close(server_socket);
        return -1;
    }

    if (listen(server_socket, 34) != 0) {
        perror("Error in listen()");
        close(server_socket);
        return -1;
    }

    std::cout << "Server listening on " << server_ip << ":" << server_port << "\n";

 
    while (true) {
        addr_len = sizeof(client_addr_struct);
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr_struct, &addr_len);
        if (client_socket < 0) {
            perror("Error in accept()");
            continue; 
        }
        std::cout << "Client connected\n";
        int *client_sock_ptr = new int;
        *client_sock_ptr = client_socket;
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, &client_handler, (void *)client_sock_ptr) != 0) {
            perror("Error creating thread");
            close(client_socket);
            delete client_sock_ptr;
            continue;
        }
        pthread_detach(thread_id); 
    }

    pthread_mutex_destroy(&client_id_mutex);
    close(server_socket);
    return 0;
}
