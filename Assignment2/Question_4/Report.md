#### Client Code:

- The client reads the server configuration (IP, port, max words, packet size, and number of clients) from config.json.
- It establishes a connection to the server using a TCP socket and sends a request containing an offset, which represents the- starting point of the words it wants to retrieve.
- After sending the offset, the client receives a response containing a set number of words (up to the specified packet size) from the server.
- The client accumulates these words and continues reading until it receives the end-of-file ("EOF") marker from the server or reaches the word limit.
- Once all data is received, the client processes the received words and outputs any necessary information to the console.
- If more words are needed, the client sends a new request with an updated offset, incrementing by the number of words previously received, and the process repeats until all words are retrieved.

#### Server Code:

- The server reads configuration details (IP, port, number of clients, input file, max words, and packet size) from config.json and loads all words from the input file into memory for processing.
- A socket is created and bound to the specified IP and port, and the server begins listening for client connections.
- A separate connection acceptor thread accepts incoming client connections in a First-In-First-Out (FIFO) manner. It enqueues each connected client socket into a queue, ensuring that clients are served in the order they connect.
- A client handler thread processes the queued client sockets one by one, maintaining FIFO order. The handler dequeues a client, reads the client's offset request, and sends a corresponding chunk of words back to the client.
- For each client, the handler retrieves words starting from the requested offset, prepares a response containing up to the specified packet size of words, and sends the response back to the client.
- The server continues to send words to the client until all requested data is delivered. If the offset exceeds the number of available words, the server sends "EOF" to indicate the end of the word list.
- Once the communication with a client is complete, the handler writes the frequency of words processed for that client into a file named output_<client_id>.txt.
- The server continues serving clients in the FIFO queue until all clients have been processed, ensuring each client is handled sequentially and fairly based on their connection order.

