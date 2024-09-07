
/* srv.c */
#include <arpa/inet.h>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#define PORT 8001
#define BUFFER_SIZE 4096
#define FILE_BUFFER 4096

int main() {
  int s, c, fd;
  socklen_t addrlen;
  std::vector<std::string> words;

  char buffer[BUFFER_SIZE];

  fd = open("example.txt", O_RDONLY);
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

  std::istringstream iss(
      file_content); // creating stream object 'iss' from a file
  std::string token;

  for (; std::getline(iss, token, ',');) {
    if (token ==
        "EOF") { // This reads data from the input stream (iss) into the string
                 // token, using a comma (,) as the delimiter.
      break;
    }
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
  srv.sin_addr.s_addr = INADDR_ANY;
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

  std::cout << "Listening on 0.0.0.0:" << PORT << std::endl;

  while (1) {
    addrlen = sizeof(client);
    c = accept(s, (struct sockaddr *)&client, &addrlen);
    if (c < 0) {
      std::cout << "accept() error\n";
      close(s);
      return -1;
    }
    std::cout << "Client connected" << std::endl;

    while (1) {
      ssize_t bytes_from_client = read(c, buffer, BUFFER_SIZE - 1);
      if (bytes_from_client <= 0) {
        if (bytes_from_client == 0) {
          std::cout << "Client disconnected" << std::endl;
        } else {
          std::cout << "read() error\n";
        }
        break;
      }
      buffer[bytes_from_client] = '\0';

      // when client just presses enter

      if (buffer[0] == '\n' || buffer[0] == '\0') {
        std::cout << "Client sent an empty line, closing connection"
                  << std::endl;
        break;
      }

      int offset = strtol(buffer, NULL, 10); // converting to int with base 10
      std::cout << "Received offset: " << offset << std::endl;

      std::ostringstream response;
      if (offset < words.size()) {
        for (size_t i = offset; i < words.size(); i++) {
          response << words[i];
          if (i < words.size() - 1) {
            response << ',';
          }
        }
      } else {
        response << "Offset exceeds number of words";
      }

      std::string response_str = response.str();
      // Send file content to client
      ssize_t bytes_sent = write(c, response_str.c_str(), response_str.size());
      if (bytes_sent == -1) {
        std::cout << "write() error\n";
      } else if (bytes_sent != static_cast<ssize_t>(response_str.size())) {
        std::cerr << "Partial write occurred" << std::endl;
      }

      std::cout << "Sent: " << response_str << std::endl;
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
