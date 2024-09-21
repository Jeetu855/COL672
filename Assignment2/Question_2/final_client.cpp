#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <netinet/in.h>
#include <nlohmann/json.hpp>
#include <pthread.h>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <thread>
#include <chrono>

#define BUFFER_LEN 10240
using json = nlohmann::json;

struct ClientParams
{
    std::string IP;
    int PORT;
    int MAX_WORDS;
    int PACKET_SIZE;

    ClientParams(const std::string &ip, int port, int max_words, int packet_size)
        : IP(ip), PORT(port), MAX_WORDS(max_words), PACKET_SIZE(packet_size) {}
};

bool read_config(ClientParams &params, std::vector<int> &client_counts)
{
    std::ifstream config_stream("config.json");
    if (!config_stream.is_open())
    {
        std::cerr << "Cannot open config.json\n";
        return false;
    }

    json config_json;
    config_stream >> config_json;

    if (config_json.contains("server_ip") && config_json["server_ip"].is_string())
    {
        params.IP = config_json["server_ip"].get<std::string>();
    }
    else
    {
        std::cerr << "Missing or invalid 'server_ip' in config.json\n";
        return false;
    }

    if (config_json.contains("server_port") && config_json["server_port"].is_number_integer())
    {
        params.PORT = config_json["server_port"].get<int>();
    }
    else
    {
        std::cerr << "Missing or invalid 'server_port' in config.json\n";
        return false;
    }

    if (config_json.contains("k") && config_json["k"].is_number_integer())
    {
        params.MAX_WORDS = config_json["k"].get<int>();
    }
    else
    {
        std::cerr << "Missing or invalid 'k' in config.json\n";
        return false;
    }

    if (config_json.contains("p") && config_json["p"].is_number_integer())
    {
        params.PACKET_SIZE = config_json["p"].get<int>();
    }
    else
    {
        std::cerr << "Missing or invalid 'p' in config.json\n";
        return false;
    }

    if (config_json.contains("num_clients") && config_json["num_clients"].is_array())
    {
        try
        {
            client_counts = config_json["num_clients"].get<std::vector<int>>();
        }
        catch (json::type_error &e)
        {
            std::cerr << "Type error in 'num_clients': " << e.what() << "\n";
            return false;
        }
    }
    else
    {
        std::cerr << "Missing or invalid 'num_clients' in config.json\n";
        return false;
    }

    return true;
}

void *client_thread(void *arg)
{
    ClientParams *params = (ClientParams *)arg;

    int client_socket;
    struct sockaddr_in server_addr;
    char recv_buffer[BUFFER_LEN];
    char send_buffer[100];
    int offset = 0;
    int bytes_received;

    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0)
    {
        std::cerr << "Error in socket()\n";

        pthread_exit(NULL);
    }

    server_addr.sin_addr.s_addr = inet_addr(params->IP.c_str());
    server_addr.sin_port = htons(params->PORT);
    server_addr.sin_family = AF_INET;

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) != 0)
    {
        std::cerr << "Error in connect()\n";
        close(client_socket);
        pthread_exit(NULL);
    }

    ssize_t id_bytes = read(client_socket, recv_buffer, BUFFER_LEN - 1);
    if (id_bytes <= 0)
    {
        std::cout << "Failed to receive client ID\n";
        close(client_socket);
        pthread_exit(NULL);
    }
    recv_buffer[id_bytes] = '\0';
    std::string id_str(recv_buffer);
    id_str.erase(std::remove(id_str.begin(), id_str.end(), '\n'), id_str.end());

    int client_id = atoi(id_str.c_str());
    std::cout << "Assigned client ID: " << client_id << "\n";

    std::map<std::string, int> word_counts;

    std::string accumulated_data;

    while (true)
    {

        snprintf(send_buffer, sizeof(send_buffer), "%d\n", offset);
        if (write(client_socket, send_buffer, strlen(send_buffer)) < 0)
        {
            std::cerr << "Error in write()\n";
            close(client_socket);
            pthread_exit(NULL);
        }
        std::cout << "Client " << client_id << " sent offset: " << offset << "\n";

        int words_received = 0;
        bool eof_received = false;

        while ((bytes_received = read(client_socket, recv_buffer, sizeof(recv_buffer) - 1)) > 0)
        {
            recv_buffer[bytes_received] = '\0';
            std::string received(recv_buffer);
            std::cout << "Client " << client_id << " received data: " << received << "\n";
            accumulated_data += received;

            size_t eof_pos = accumulated_data.find("EOF");
            if (eof_pos != std::string::npos)
            {
                eof_received = true;
                accumulated_data.erase(eof_pos);
                std::cout << "Client " << client_id << " detected EOF.\n";
            }

            size_t last_newline = accumulated_data.rfind('\n');
            if (last_newline == std::string::npos)
            {

                continue;
            }

            std::string complete_words = accumulated_data.substr(0, last_newline);

            accumulated_data.erase(0, last_newline + 1);

            std::cout << "Client " << client_id << " processing words:\n"
                      << complete_words << "\n";

            std::istringstream stream(complete_words);
            std::string word;
            while (std::getline(stream, word))
            {

                word.erase(std::remove(word.begin(), word.end(), '\n'), word.end());
                word.erase(std::remove(word.begin(), word.end(), '\r'), word.end());
                size_t start = word.find_first_not_of(" \t\r\n");
                size_t end = word.find_last_not_of(" \t\r\n");
                if (start != std::string::npos && end != std::string::npos && end >= start)
                {
                    word = word.substr(start, end - start + 1);
                }
                else
                {
                    word = "";
                }

                if (!word.empty())
                {
                    word_counts[word]++;
                    words_received++;
                    std::cout << "Client " << client_id << " counted word: '" << word << "' (Total: " << word_counts[word] << ")\n";
                }
            }

            if (eof_received || words_received >= params->MAX_WORDS)
            {
                break;
            }
        }

        if (bytes_received < 0)
        {
            std::cerr << "Error in read()\n";
            close(client_socket);
            pthread_exit(NULL);
        }

        if (eof_received)
        {
            std::cout << "Client " << client_id << " received EOF. Exiting loop.\n";
            break;
        }

        offset += params->MAX_WORDS;
        std::cout << "Client " << client_id << " updating offset to: " << offset << "\n";
    }

    close(client_socket);

    std::string output_filename = "output_" + std::to_string(client_id) + ".txt";
    std::ofstream output_file(output_filename);
    if (!output_file.is_open())
    {
        std::cerr << "Cannot open output file for client " << client_id << "\n";
        pthread_exit(NULL);
    }

    for (const auto &entry : word_counts)
    {
        output_file << entry.first << ", " << entry.second << "\n";
    }

    output_file.close();
    std::cout << "Client " << client_id << " has written data to " << output_filename << "\n";

    pthread_exit(NULL);
    return NULL;
}

int main()
{
    ClientParams params("", 0, 0, 0);
    std::vector<int> client_counts;

    if (!read_config(params, client_counts))
    {
        return -1;
    }

    for (size_t i = 0; i < client_counts.size(); i++)
    {
        int num_clients = client_counts[i];
        std::vector<pthread_t> threads(num_clients);

        std::cout << "Starting " << num_clients << " concurrent clients...\n";

        for (int j = 0; j < num_clients; j++)
        {

            ClientParams *params_copy = new ClientParams(params.IP, params.PORT, params.MAX_WORDS, params.PACKET_SIZE);

            if (pthread_create(&threads[j], NULL, &client_thread, params_copy) != 0)
            {
                perror("Error creating thread");
                delete params_copy;
                return 2;
            }
        }

        for (int j = 0; j < num_clients; j++)
        {
            if (pthread_join(threads[j], NULL) != 0)
            {
                perror("Error joining thread");
                std::cout << "Client count: " << num_clients << ", Thread: " << j << "\n";
                return 3;
            }
        }

        std::cout << "Completed " << num_clients << " concurrent clients.\n";
    }

    return 0;
}
