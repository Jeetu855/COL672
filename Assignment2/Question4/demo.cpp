#include <arpa/inet.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <nlohmann/json.hpp>
#include <pthread.h>
#include <signal.h>
#include <sstream>
#include <stdexcept>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <algorithm>
using json = nlohmann::json;
vector<bool> lock ;
int count=0;

void FCFS()
{
               int s, c, fd;
  signal(SIGPIPE, handle_sigpipe);
  socklen_t addrlen;
  std::ifstream config_file("config.json");
  if (!config_file.is_open()) {
    std::cerr << "Failed to open config.json\n";
    return -1;
  }
  // need a stream object to read into this
  json config;
  config_file >> config;

  // Read values from the JSON config
  std::string IP = config["server_ip"];
  int PORT = config["server_port"];
  int PACKET_SIZE = config["p"];
  int MAX_WORDS = config["k"];
  std::string file_to_read = config["file_to_read"];

  // Open the specified file
  fd = open(file_to_read.c_str(), O_RDONLY);
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
    printf("socket() error");
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

  if (listen(s, 34) != 0) {
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
        pthread_t thread;
       int* client_sock_ptr = new int;    // Create a new pthread to handle the client
        *client_sock_ptr = c; 
        if(pthread_create(&thread,NULL,&handle_client_fcfs,(void*)client_sock_ptr)!=0)
                {
                                    perror("failed to create thread\n");
                                    return 2;
                }
        
    pthread_join(thread,NULL); 
    
    close(c);
  }

  close(s);


}
void* handle_client_round_robin(void *arg)    //&handle_client_round_robin
   {
       int c=*(int*)arg;
       delete(int*)arg;
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
          printf("bytes_sent : %zd \n", bytes_sent);
          if (bytes_sent == -1) {
            std::cout << "write() error\n";
            break;
          } else if (bytes_sent != static_cast<ssize_t>(response_str.size())) {
            std::cout << "Partial write occurred" << "\n";
          }

          //usleep(100000);
        }
      } else {
        response << "End of connection";
        std::string response_str = response.str();
        write(c, response_str.c_str(), response_str.size());
        std::cout << "Sent: " << response_str << "\n";
      }
    }
       return NULL;
   };

void handle_sigpipe(int sig) {
  std::cout << "Caught SIGPIPE (Client disconnected abruptly)\n";
} 


void Round_Robin()
{
  int s, c, fd;
  signal(SIGPIPE, handle_sigpipe);
  socklen_t addrlen;
  std::ifstream config_file("config.json");
  if (!config_file.is_open()) {
    std::cerr << "Failed to open config.json\n";
    return -1;
  }
  // need a stream object to read into this
  json config;
  config_file >> config;

  // Read values from the JSON config
  std::string IP = config["server_ip"];
  int PORT = config["server_port"];
  int PACKET_SIZE = config["p"];
  int MAX_WORDS = config["k"];
  std::string file_to_read = config["file_to_read"];

  // Open the specified file
  fd = open(file_to_read.c_str(), O_RDONLY);
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
    printf("socket() error");
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

  if (listen(s, 34) != 0) {
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
    else {
              if(count==0)
                  { 
                    lock.push_back(true);
                    count=count+1;
                  }
               else {
                       lock.push_back(false);
                       count=count+1; 
                    }    
         }
    std::cout << "Client connected" << "\n";
        pthread_t thread;
       int* client_sock_ptr = new int;    // Create a new pthread to handle the client
        *client_sock_ptr = c; 
        if(pthread_create(&thread,NULL,&handle_client_round_robin,(void*)client_sock_ptr)!=0)
                {
                                    perror("failed to create thread\n");
                                    return 2;
                }
        
    pthread_join(thread,NULL); 
    
    close(c);
  }

  close(s);

}
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: ./client <protocol> <n>" << std::endl;
        std::cout << "Protocols: fcfs round-robin" << std::endl;
        return 1;
    }
    std::string protocol = argv[1];
    
   
    if (protocol == "fcfs") {
        FCFS();
    }
    else if (protocol == "round-robin") {
        Round_Robin();
    }
    else {
        std::cout<< "Unknown protocol: " << protocol <<"\n";
        
        return 1;
    }
    for (size_t i = 0; i < mutexes.size(); ++i) {
        pthread_mutex_destroy(&mutexes[i]);
    return 0;
}