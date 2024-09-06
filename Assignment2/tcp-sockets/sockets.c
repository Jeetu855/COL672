/* sockets.c */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define IP "142.250.206.142" // host google.com
#define PORT 80

/*
struct sockaddr_in {
    short int sin_family; // Address family (e.g., AF_INET for IPv4)
    unsigned short int sin_port; // Port number
    struct in_addr sin_addr; // IP address
    char sin_zero[8]; // Padding to make the structure the same size as sockaddr
};*/

int main() {
  int s; // file descriptor for socket
  struct sockaddr_in sock;
  s = socket(AF_INET, SOCK_STREAM, 0); // AF_INET = tells us its an internet
                                       // connection, then we have a stream
  char buffer[512];
  char *data;
  data = "HEAD / HTTP/1.0\n\n";
  // for tcp connection
  // man 2 socket
  if (s < 0) {
    printf("socket() error\n");
    return -1; // -1 is standard error code
  }

  sock.sin_addr.s_addr = inet_addr(IP); // IP of target
  /*sock.sin_addr.s_addr:

  This is a field within struct in_addr that directly holds the IP address in a
  binary form. */
  sock.sin_port = htons(PORT);
  // The  htons() function converts the unsigned
  // short integer hostshort from host byte order
  // to network byte order
  sock.sin_family = AF_INET;

  // next step is to connect to the host usnig connect() system call
  // type casting to sockaddr, s is our socket
  // man connect

  if (connect(s, (struct sockaddr *)&sock, sizeof(struct sockaddr_in)) != 0) {
    printf("connect() error.\n");
    close(s);
    return -1;
  };

  write(s, data, strlen(data)); // write/ send data to socket
  read(s, buffer, 511);         // read/recv data from socket
  close(s);
  printf("\n%s\n", buffer);
  return 0;
}
