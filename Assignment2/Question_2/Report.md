#### Client Code:

- The client reads the server IP, port, packet size, and maximum word count from the config.json file.
- It establishes a connection with the server and receives an assigned client ID.
- The client sends an offset to the server, receives words, and accumulates them.
- After processing the received words, the client writes the word counts to a file named output_<client_id>.txt.

#### Server Code:

- The server reads its configuration from config.json, including the IP, port, packet size, and input file.
- It loads words from a CSV file into memory.
- The server listens for incoming client connections using a TCP socket.
- Upon receiving a connection, it assigns a client ID and spawns a thread to handle the client.
- The server sends words in batches based on the client’s requested offset and packet size.
- After serving the client, it sends an "EOF" message and closes the connection.