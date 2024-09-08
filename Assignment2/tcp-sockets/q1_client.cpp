/* sockets.c */

#include <arpa/inet.h>
#include <fstream>
#include <jsoncpp/json/json.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFER_SIZE 4096

int main() {
  int s;
  struct sockaddr_in sock;
  char buffer[BUFFER_SIZE];
  char request[100];
  int offset = 0;
  int bytes_read;

  // Read config.json
  std::ifstream config_file("config.json", std::ifstream::binary);
  Json::Value config;
  config_file >> config;

  std::string IP = config["server_ip"].asString(); // Read IP
  int PORT = config["server_port"].asInt();        // Read Port
  int MAX_WORDS = config["k"].asInt();             // Read Max Words
  int PACKET_SIZE = config["p"].asInt();           // Read Packet Size

  // Create socket
  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    perror("socket");
    return -1;
  }

  // Set up sockaddr_in structure
  sock.sin_addr.s_addr = inet_addr(IP.c_str()); // Use IP from config
  sock.sin_port = htons(PORT);                  // Use PORT from config
  sock.sin_family = AF_INET;

  // Connect to the server
  if (connect(s, (struct sockaddr *)&sock, sizeof(struct sockaddr_in)) != 0) {
    perror("connect");
    close(s);
    return -1;
  }

  while (1) {
    // Send the offset request
    snprintf(request, sizeof(request), "%d", offset);
    if (write(s, request, strlen(request)) < 0) {
      perror("write");
      close(s);
      return -1;
    }

    printf("Response from offset %d:\n", offset);
    int words_received = 0;
    bool eof_received = false;
    std::string response_str = ""; // Collect response

    // Read the server response
    while (words_received < MAX_WORDS &&
           (bytes_read = read(s, buffer, sizeof(buffer) - 1)) > 0) {
      buffer[bytes_read] = '\0';
      response_str += buffer; // Collect the response in a string

      // Count the number of words in the received buffer
      int count = 0;
      for (int i = 0; buffer[i] != '\0'; i++) {
        if (buffer[i] == ',') {
          count++;
        }
      }
      words_received += count + 1; // Each ',' separates two words

      // Check for EOF in the buffer
      if (strstr(buffer, "EOF") != NULL) {
        printf("\nEOF received.\n");
        eof_received = true;
        break;
      }

      // Break if the words received so far have hit the max limit
      if (words_received >= MAX_WORDS) {
        break;
      }
    }

    // Print the response
    printf("%s\n", response_str.c_str());

    if (bytes_read < 0) {
      perror("read");
      close(s);
      return -1;
    }

    if (eof_received) {
      break; // Exit the loop if EOF is received
    }

    // Update offset for the next request: offset + k
    offset += MAX_WORDS;

    printf("\nSending new request for offset %d\n", offset);
  }

  // Close the connection
  close(s);
  return 0;
}
