/* sockets.c */

#include <algorithm>
#include <arpa/inet.h>
// #include <bits/stdc++.h>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
// #include <jsoncpp/json/json.h>
#include <iostream>
#include <netinet/in.h>
#include <nlohmann/json.hpp>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFER_SIZE 10240
using json = nlohmann::json; // like alias in bash

std::map<std::string, int> freq;

void print_freq() {
  std::ofstream output_file("output_part1.txt");

  if (!output_file.is_open()) {
    std::cerr << "Failed to open output file.\n";
    return;
  }

  std::vector<std::pair<std::string, int>> sorted_freq(freq.begin(),
                                                       freq.end());

  std::sort(sorted_freq.begin(), sorted_freq.end(),
            [](const std::pair<std::string, int> &a,
               const std::pair<std::string, int> &b) {
              std::string a_lower = a.first;
              std::string b_lower = b.first;
              std::transform(a_lower.begin(), a_lower.end(), a_lower.begin(),
                             ::tolower);
              std::transform(b_lower.begin(), b_lower.end(), b_lower.begin(),
                             ::tolower);
              return a_lower < b_lower;
            });

  for (const auto &pair : sorted_freq) {
    output_file << pair.first << " " << pair.second << "\n";
  }

  output_file.close();
};

void removeNewLinesWithcomma(std::string &str) {
  replace(str.begin(), str.end(), '\n', ',');
};

void frequency(std::string response_str) {
  std::string str = response_str;
  removeNewLinesWithcomma(str);
  std::istringstream iss(str);
  std::string word;
  while (std::getline(iss, word, ',')) {
    if (!word.empty() && word != "EOF") {
      freq[word]++;
    }
  }
};

int main() {
  std::map<std::string, int> freq;
  int s;
  struct sockaddr_in sock;
  char buffer[BUFFER_SIZE];
  char request[100];
  int offset = 0;
  int bytes_read;

  std::ifstream config_file("config.json");
  if (!config_file.is_open()) {
    std::cout << "Failed to open config.json\n";
    return -1;
  }

  json config;
  config_file >> config;

  std::string IP = config["server_ip"];
  int PORT = config["server_port"];
  int MAX_WORDS = config["k"];
  int PACKET_SIZE = config["p"];

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    printf("socket() error");
    return -1;
  }

  sock.sin_addr.s_addr = inet_addr(IP.c_str());
  sock.sin_port = htons(PORT);
  sock.sin_family = AF_INET;

  if (connect(s, (struct sockaddr *)&sock, sizeof(struct sockaddr_in)) != 0) {
    printf("connect() error");
    close(s);
    return -1;
  }

  while (1) {
    snprintf(request, sizeof(request), "%d", offset);
    if (write(s, request, strlen(request)) < 0) {
      printf("write() error");
      close(s);
      return -1;
    }

    printf("Response from offset %d:\n", offset);
    int words_received = 0;
    bool eof_received = false;
    std::string response_str = "";

    while (words_received < MAX_WORDS &&
           (bytes_read = read(s, buffer, sizeof(buffer) - 1)) > 0) {
      buffer[bytes_read] = '\0';
      response_str += buffer;
      auto end_receive = std::chrono::high_resolution_clock::now();

      int count = 0;
      for (int i = 0; buffer[i] != '\0'; i++) {
        if (buffer[i] == ',') {
          count++;
        }
      }
      words_received += count + 1;

      if (strstr(buffer, "EOF") != NULL) {
        printf("\nEOF received.\n");
        eof_received = true;
        break;
      }

      if (words_received >= MAX_WORDS) {
        break;
      }
    }
    printf("%s\n", response_str.c_str());
    frequency(response_str.c_str());
    if (bytes_read < 0) {
      printf("read() error");
      close(s);
      return -1;
    }

    if (eof_received) {
      break;
    }

    offset += MAX_WORDS;

    printf("\nSending new request for offset %d\n", offset);
  }

  print_freq();
  close(s);
  return 0;
}
