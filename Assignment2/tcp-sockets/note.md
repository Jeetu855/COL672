a socket is a IP connection
we will do a TCP connection
we are not going to use a DNS to resolve domain to IP, we will provide hard coded IP
we can find IP usin the `host` command or `nslookup` or just `ping` the domain
we are not going to use IPv6, just IPv4

In Unix-like operating systems, file descriptors are integers that uniquely identify
open files or other input/output resources, such as pipes, sockets, or terminals,
within a process. When a program wants to interact with a file or any I/O
resource, the operating system provides the program with a file descriptor to
represent that resource.

**When You Open a File or Create a Network Connection.Your computer gives you a file
descriptor (a number) to represent that file or connection.**

**Does that mean my mouse and keyboard also have a fd related them?**
Yes, that's correct! In Unix-like operating systems, almost everything is treated as a
file, including your mouse, keyboard, and other input/output devices. These devices are usually
represented by special files in the /dev directory, and when your operating system interacts with
these devices, it uses file descriptors.

In the context of networking, file descriptors are used to represent network connections,
such as sockets, in a manner similar to how they represent files. A file descriptor for a
socket allows a program to perform operations like sending and receiving data over a network.

Network file descriptors don't directly "store" data themselves. Instead, they act as a reference to:

- Socket State: The current state of the socket (e.g., listening, connected, closed).
- Associated Buffers: The operating system manages buffers for incoming and outgoing data associated with the socket. The file descriptor is your handle to these buffers.
- Connection Information: Information about the connection, such as the remote IP address and port, is associated with the socket and can be accessed through the file descriptor.

socket(AF_INET, SOCK_STREAM, 0) creates a new socket and returns a file descriptor. The socket function takes three arguments:

- AF_INET: This specifies the address family. AF_INET indicates that the socket is for IPv4.
- SOCK_STREAM: This specifies the socket type. SOCK_STREAM indicates a stream socket (TCP),
  which provides a connection-oriented, reliable communication channel.
- 0: This specifies the protocol. Passing 0 lets the system choose the appropriate
  p rotocol for the given socket type (for SOCK_STREAM, it usually means TCP).
- The socket function returns a non-negative integer (the file descriptor) on success.
  If it fails, it returns -1 and sets the global errno variable to indicate the error.

- Reading Data: Use read(c, buffer, size) to receive data sent by the client.
- Sending Data: Use write(c, data, size) to send data to the client.

**So if we have lets say 5 clients, we need 5 accept() and 5 fd for clients?**
Yep, In a scenario where you have multiple clients connecting to your server, each client connection
requires a separate file descriptor. Here’s how it works:

**You only need one accept() call to handle each incoming client connection, but you need to call accept()
multiple times if you want to handle multiple clients.**

1. Listening Socket (s):

- You have one listening socket (s) that waits for incoming connection requests from clients.
- The listening socket is used with accept() to establish new connections.

2. Accepting Connections:

- Each time a new client connects, the accept() function is called.
- accept() returns a new file descriptor for each accepted client connection. This new
  file descriptor is specific to that client and is used for communication with that client.

3. File Descriptors for Clients:

- For each client connection, you will get a unique file descriptor from accept(). If
  you have 5 clients, you will end up with 5 separate file descriptors, one for each client connection.

Changes in the code

```c
#define MAX_CLIENTS 5
int client_fds[MAX_CLIENTS];
listen(s, MAX_CLIENTS);
  for (int i = 0; i < MAX_CLIENTS; i++) {
        client_fds[i] = accept(s, (struct sockaddr *)&client, &addrlen);
        if (client_fds[i] < 0) {
            printf("accept() error.\n");
            close(s);
            return -1;
        }
        printf("Client %d connected\n", i + 1);
    }
char buffer[512];
    for (int i = 0; i < MAX_CLIENTS; i++) {
        read(client_fds[i], buffer, sizeof(buffer));
        printf("Received from client %d: %s\n", i + 1, buffer);
        write(client_fds[i], "Hello, client!", 14);
        close(client_fds[i]);

```

One Listening Socket (s): Used to listen for incoming connections.
Multiple Client Sockets (client_fds[i]): Each client connection has its own file
descriptor obtained from accept(). You need as many file descriptors as there are
clients you are handling simultaneously.
