#include <algorithm>
#include <arpa/inet.h>
// #include <bits/stdc++.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <chrono>
#include <algorithm>
#include <cstdlib>
#include <sstream>
#include <string>
#include <fstream>
// #include <jsoncpp/json/json.h>
#include <iostream>
#include <netinet/in.h>
#include <nlohmann/json.hpp>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
pthread_mutex_t mutex;
#define BUFFER_SIZE 10240
using json = nlohmann::json; // like alias in bash

void *connect_server(void *arg)
{
  int s;
  struct sockaddr_in sock;
  char buffer[BUFFER_SIZE];
  char request[100];
  int offset = 0;
#include <algorithm>
#include <arpa/inet.h>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <nlohmann/json.hpp>
#include <pthread.h>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#define BUFFER_SIZE 10240
using json = nlohmann::json;

struct ClientParams {
    std::string IP;
    int PORT;
    int MAX_WORDS;
    int PACKET_SIZE;
};

void *connect_server(void *arg) {
    ClientParams *params = (ClientParams *)arg;

    int s;
    struct sockaddr_in sock;
    char buffer[BUFFER_SIZE]; // Make buffer local to the thread
    char request[100];
    int offset = 0;
    int bytes_read;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printf("socket() error\n");
        pthread_exit(NULL);
    }

    sock.sin_addr.s_addr = inet_addr(params->IP.c_str());
    sock.sin_port = htons(params->PORT);
    sock.sin_family = AF_INET;

    if (connect(s, (struct sockaddr *)&sock, sizeof(struct sockaddr_in)) != 0) {
        printf("connect() error\n");
        close(s);
        pthread_exit(NULL);
    }

    // Receive client ID from server
    ssize_t id_bytes = read(s, buffer, BUFFER_SIZE - 1);
    if (id_bytes <= 0) {
        std::cout << "Failed to receive client ID\n";
        close(s);
        pthread_exit(NULL);
    }
    buffer[id_bytes] = '\0';
    std::string id_str(buffer);
    // Remove any newline characters
    id_str.erase(std::remove(id_str.begin(), id_str.end(), '\n'), id_str.end());

    int client_id = std::stoi(id_str);
    std::cout << "Assigned client ID: " << client_id << "\n";

    // Open output file
    std::ofstream output_file("output_" + std::to_string(client_id) + ".txt");
    if (!output_file.is_open()) {
        std::cout << "Failed to open output file for client " << client_id << "\n";
        close(s);
        pthread_exit(NULL);
    }

    while (1) {
        snprintf(request, sizeof(request), "%d", offset);
        if (write(s, request, strlen(request)) < 0) {
            printf("write() error\n");
            close(s);
            pthread_exit(NULL);
        }

        int words_received = 0;
        bool eof_received = false;
        std::string response_str = "";

        while ((bytes_read = read(s, buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes_read] = '\0';
            response_str += buffer;

            // Write the received data to the output file
            output_file << buffer;

            if (strstr(buffer, "EOF") != NULL) {
                eof_received = true;
                break;
            }

            int count = 0;
            for (int i = 0; buffer[i] != '\0'; i++) {
                if (buffer[i] == ',') {
                    count++;
                }
            }
            words_received += count + 1;

            if (words_received >= params->MAX_WORDS) {
                break;
            }
        }

        if (bytes_read < 0) {
            printf("read() error\n");
            close(s);
            pthread_exit(NULL);
        }

        if (eof_received) {
            break;
        }

        offset += params->MAX_WORDS;
    }

    output_file.close();
    close(s);
    pthread_exit(NULL);
    return NULL;
}

int main() {
    // Read the config file
    std::ifstream config_file("config.json");
    if (!config_file.is_open()) {
        std::cerr << "Failed to open config.json\n";
        return -1;
    }

    json config;
    try {
        config_file >> config;
    } catch (json::parse_error &e) {
        std::cerr << "JSON parse error: " << e.what() << "\n";
        return -1;
    }

    // Read "num_clients" from config
    std::vector<int> client_count;
    if (config.contains("num_clients") && config["num_clients"].is_array()) {
        client_count = config["num_clients"].get<std::vector<int>>();
    } else {
        std::cerr << "num_clients parameter is missing or not an array in config.json\n";
        return -1;
    }

    // Read other parameters
    std::string IP = config["server_ip"];
    int PORT = config["server_port"];
    int MAX_WORDS = config["k"];
    int PACKET_SIZE = config["p"];

    // Prepare parameters to pass to threads
    ClientParams params = { IP, PORT, MAX_WORDS, PACKET_SIZE };

    // Iterate over each client count value
    for (size_t i = 0; i < client_count.size(); i++) {
        int num_threads = client_count[i];
        std::vector<pthread_t> threads(num_threads);

        std::cout << "Starting " << num_threads << " concurrent clients...\n";

        // Create threads
        for (int j = 0; j < num_threads; j++) {
            if (pthread_create(&threads[j], NULL, &connect_server, &params) != 0) {
                perror("Failed to create thread\n");
                return 2;
            }
        }

        // Join threads
        for (int j = 0; j < num_threads; j++) {
            if (pthread_join(threads[j], NULL) != 0) {
                perror("Failed to join thread\n");
                std::cout << "Client count: " << num_threads << ", Thread: " << j << "\n";
                return 3;
            }
        }

        std::cout << "Completed " << num_threads << " concurrent clients.\n";
    }

    return 0;
}

  int bytes_read;

  // Read the config file
  std::ifstream config_file("config.json");
  if (!config_file.is_open())
  {
    std::cout << "Failed to open config.json\n";
    pthread_exit(NULL);
  }

  json config;
  config_file >> config;

  std::string IP = config["server_ip"];
  int PORT = config["server_port"];
  int MAX_WORDS = config["k"];
  int PACKET_SIZE = config["p"];

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0)
  {
    printf("socket() error\n");
    pthread_exit(NULL);
  }

  sock.sin_addr.s_addr = inet_addr(IP.c_str());
  sock.sin_port = htons(PORT);
  sock.sin_family = AF_INET;

  if (connect(s, (struct sockaddr *)&sock, sizeof(struct sockaddr_in)) != 0)
  {
    printf("connect() error\n");
    close(s);
    pthread_exit(NULL);
  }

  while (1)
  {
    snprintf(request, sizeof(request), "%d", offset);

    if (write(s, request, strlen(request)) < 0)
    {
      printf("write() error\n");
      close(s);
      pthread_exit(NULL);
    }

    int words_received = 0;
    bool eof_received = false;
    std::string response_str = "";

    while (words_received < MAX_WORDS &&
           (bytes_read = read(s, buffer, sizeof(buffer) - 1)) > 0)
    {
      buffer[bytes_read] = '\0';
      response_str += buffer;

      int count = 0;
      for (int i = 0; buffer[i] != '\0'; i++)
      {
        if (buffer[i] == ',')
        {
          count++;
        }
      }
      words_received += count + 1;

      if (strstr(buffer, "EOF") != NULL)
      {
        eof_received = true;
        break;
      }

      if (words_received >= MAX_WORDS)
      {
        break;
      }
    }

    if (bytes_read < 0)
    {
      printf("read() error\n");
      close(s);
      pthread_exit(NULL);
    }

    if (eof_received)
    {
      break;
    }

    offset += MAX_WORDS;
  }

  close(s);
  pthread_exit(NULL);
}

int main()
{
  std ::vector<int> client_count;
  std ::cout << "No. of client :";
  client_count.push_back(1);
  std ::cout << client_count[0] << " ";
  for (int i = 1; i <= 8; i++)
  {
    client_count.push_back(i * 4); // initialize no. of client connect at a time
    // std::cout<<client_count[i]<<" ";
  }

  for (int i = 0; i < client_count.size(); i++)
  {
    std ::vector<pthread_t> th(client_count[i]);
    for (int j = 0; j < client_count[i]; j++) // create thread
    {
      if (pthread_create(&th[j], NULL, &connect_server, NULL) != 0)
      {
        perror("failed to create thread\n");
        return 2;
      }
    };
    for (int j = 0; j < client_count[i]; j++) // join thread
    {
      if (pthread_join(th[j], NULL) != 0)
      {
        perror("failed to join thread\n");
        std::cout << client_count[i] << " :" << j;
        return 3;
      }
      else
      {
        std::cout << i << ":" << j << " Complete :\n";
      };
    };
  }
  return 1;
}
