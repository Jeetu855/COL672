/* srv.c */
#include <arpa/inet.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <jsoncpp/json/json.h>
#include <netinet/in.h>
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#define BUFFER_SIZE 4096
#define FILE_BUFFER 4096

void handle_sigpipe(int sig) {
  std::cout << "Caught SIGPIPE (Client disconnected abruptly)" << std::endl;
} // if socket or pipe closed from the other end and we try to write to it,
  // sigpipe signal is sent
// if this signal is received by the process, the default action is termination,
// by here we create a function to just print if we receive sigpipe and we just
// print the message rather than termination

int main() {
  int s, c, fd;
  signal(SIGPIPE, handle_sigpipe);
  socklen_t addrlen;
  std::vector<std::string> words; // csv file ke words ke liye
  char buffer[BUFFER_SIZE];

  std::ifstream config_file("config.json", std::ifstream::binary);
  Json::Value config; // need a stream object to read into this
  config_file >> config;

  std::string IP = config["server_ip"].asString();
  int PORT = config["server_port"].asInt();
  int PACKET_SIZE = config["p"].asInt();
  int MAX_WORDS = config["k"].asInt();

  fd = open("words.csv", O_RDONLY);
  if (fd == -1) {
    std::cout << "open() error\n";
    return -1;
  }

  char file_buff[FILE_BUFFER];
  ssize_t n;

  std::string file_content;
  while ((n = read(fd, file_buff, FILE_BUFFER)) > 0) {
    file_content.append(file_buff, n);
  }
  if (n == -1) {
    std::cout << "read() error\n";
    close(fd);
    return -1;
  }
  close(fd);

  std::istringstream stream_of_file(file_content);
  std::string token;

  while (std::getline(stream_of_file, token, ',')) {
    words.push_back(token);
  }

  struct sockaddr_in srv, client;
  memset(&srv, 0, sizeof(srv));
  memset(&client, 0, sizeof(client));

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    perror("socket");
    return -1;
  }

  srv.sin_family = AF_INET;
  srv.sin_addr.s_addr = inet_addr(IP.c_str());
  srv.sin_port = htons(PORT);

  if (bind(s, (struct sockaddr *)&srv, sizeof(srv)) != 0) {
    std::cout << "bind() error\n";
    close(s);
    return -1;
  }

  if (listen(s, 5) != 0) {
    std::cout << "listen() error\n";
    close(s);
    return -1;
  }

  std::cout << "Listening on " << IP << ":" << PORT << "\n";

  while (1) {
    addrlen = sizeof(client);
    c = accept(s, (struct sockaddr *)&client, &addrlen);
    if (c < 0) {
      std::cout << "accept() error\n";
      close(s);
      return -1;
    }
    std::cout << "Client connected" << "\n";

    while (1) {
      ssize_t bytes_from_client = read(c, buffer, BUFFER_SIZE - 1);
      if (bytes_from_client <= 0) {
        if (bytes_from_client == 0) {
          std::cout << "Client disconnected" << "\n";
        } else {
          std::cout << "read() error\n";
        }
        break;
      }
      buffer[bytes_from_client] = '\0';

      int offset = strtol(buffer, NULL, 10);
      std::cout << "Received offset: " << offset << "\n";

      std::ostringstream response;
      if (offset < (int)words.size()) {
        for (size_t i = offset; i < words.size(); i += PACKET_SIZE) {
          response.str("");
          response.clear();

          for (size_t j = 0; j < PACKET_SIZE && (i + j) < words.size(); ++j) {
            response << words[i + j];
            if (i + j < words.size() - 1 && j < PACKET_SIZE - 1) {
              response << ',';
            }
          }

          std::string response_str = response.str();

          response_str += '\n';

          ssize_t bytes_sent =
              write(c, response_str.c_str(), response_str.size());
          printf("bytes_sent : %zd ", bytes_sent);
          if (bytes_sent == -1) {
            std::cout << "write() error\n";
            break;
          } else if (bytes_sent != static_cast<ssize_t>(response_str.size())) {
            std::cout << "Partial write occurred" << "\n";
          }

          std::cout << "Sent packet: " << response_str << "\n";
          usleep(100000);
          std::cout << "\n--------------K words sent-------------------\n";
        }
      } else {
        response << "Offset exceeds number of words";
        std::string response_str = response.str();
        write(c, response_str.c_str(), response_str.size());
        std::cout << "Sent: " << response_str << "\n";
      }
    }
    close(c);
  }

  close(s);
  return 0;
}
// The goal of InputStream and OutputStream is to abstract different ways to
// input and output: whether the stream is a file, a web page, or the screen
// shouldn't matter. All that matters is that you receive information from the
// stream (or send information into that stream.)
//
//
// fix if client just presses enter, it sends the entire file
