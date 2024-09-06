/* srv.c */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PORT 8181

int main() {

  int s, c;
  socklen_t addrlen; // describes lenght of socket address. int type of atlease
  addrlen = 0;       // 32 bits, will be used for
                     // accept function
  char buffer[512];
  char *data;

  struct sockaddr_in srv, client;
  memset(
      &srv, 0,
      sizeof(srv)); // The memset() function fills the first n(last parameter)
                    // bytes of the memory area pointed to by first parameter
                    // with the constant byte c given by second parameter
  memset(&client, 0, sizeof(client));

  s = socket(AF_INET, SOCK_STREAM, 0);

  if (s < 0) {
    printf("socket() error.\n");
    return -1;
  }
  c = socket(AF_INET, SOCK_STREAM, 0);

  srv.sin_family = AF_INET;
  srv.sin_addr.s_addr =
      0; // binds the socket to all available network interfaces.
  srv.sin_port = htons(PORT);

  if (bind(s, (struct sockaddr *)&srv, sizeof(srv)) !=
      0) { // binding structure with socket fd
    printf("bind() error.\n");
    close(s);
    return -1;
  }

  if (listen(s, 5) != 0) {
    printf("listen() error.\n");
    close(s);
    return -1;
  }
  printf("Listening on 0.0.0.0:%d\n", PORT);
  // the second parameter defines how many connections we can have

  // simultaneously, eg, if it is 5, we can have 5 connections at a
  // time
  // if we run `netstat -an | grep LISTEN` or `ss -tulnp`, it will show we are
  // listening on 0.0.0.0:8181
  c = accept(s, (struct sockaddr *)&srv, &addrlen);
  // On success, these system calls return a file descriptor for the accepted
  // socket (a nonnegative integer).  On error, -1 is returned, errno is set to
  // indicate the error, and addrlen is left unchanged.

  if (c < 0) {
    printf("accept() error.\n");
    close(s);
    return -1;
  }
  // we are server and we got clients fd and we are writing and readig data from
  // it

  printf("Client connected\n");
  read(c, buffer, 511);
  data = "httpd v1.0\n";
  write(c, data, strlen(data));

  close(c);
  close(s);
  return 0;
}
