#include <algorithm>
#include <arpa/inet.h>
// #include <bits/stdc++.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <chrono>
#include <algorithm>
#include <cstdlib>
#include<sstream>
#include<string>
#include <fstream>
// #include <jsoncpp/json/json.h>
#include<iostream>
#include <netinet/in.h>
#include <nlohmann/json.hpp>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
pthread_mutex_t mutex;
#define BUFFER_SIZE 10240
using json = nlohmann::json; // like alias in bash
void * connect_server(void * arg)
{
  std::map<std::string, int> freq; // contain frequency of corresponding word
  int s;
  struct sockaddr_in sock;
  char buffer[BUFFER_SIZE];
  char request[100];
  int offset = 0;
  int bytes_read;

  // open file as input file stream
  std::ifstream config_file("config.json");
  if (!config_file.is_open()) {
    std::cout << "Failed to open config.json\n";
    //return -1;
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
   // return -1;
  }

  sock.sin_addr.s_addr = inet_addr(IP.c_str());
  sock.sin_port = htons(PORT);
  sock.sin_family = AF_INET;

  if (connect(s, (struct sockaddr *)&sock, sizeof(struct sockaddr_in)) != 0) {
    printf("connect() error");
    close(s);
    //return -1;
  }
  
  while (1) {
    pthread_mutex_lock(&mutex);                            //we use mutex to prevent race condition 
    snprintf(request, sizeof(request), "%d", offset);
    pthread_mutex_unlock(&mutex);
    if (write(s, request, strlen(request)) < 0) {
      printf("write() error");
      close(s);
      //return -1;
    }

   // printf("Response from offset %d:\n", offset);
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
       // printf("\nEOF received.\n");
        eof_received = true;
        break;
      }

      if (words_received >= MAX_WORDS) {
        break;
      }
    }
   // printf("%s\n", response_str.c_str()); // to C style
    if (bytes_read < 0) {
      printf("read() error");
      close(s);
      //return -1;
    }

    if (eof_received) {
      break;
    }

    offset += MAX_WORDS;

    //printf("\nSending new request for offset %d\n", offset);
  }
  
  close(s);
  return NULL;
  //return 0;
};
int main() {
        std ::vector<int> client_count;
        std ::cout<<"No. of client :";
        client_count.push_back(1);
        std ::cout<<client_count[0]<<" ";
        for (int i=1;i<=8;i++)
            {
                client_count.push_back(i*4);    //initialize no. of client connect at a time
                //std::cout<<client_count[i]<<" ";
            }
        
        for(int i=0;i<client_count.size();i++)
           {
                std :: vector<pthread_t> th(client_count[i]);    
                for(int j=0;j<client_count[i];j++)   //create thread
                    {
                              if(pthread_create(&th[j],NULL,&connect_server,NULL)!=0)
                                 {
                                    perror("failed to create thread\n");
                                    return 2;
                                 }
                    };
                for(int j=0;j<client_count[i];j++)   //join thread
                   {
                              if(pthread_join(th[j],NULL)!=0)
                                 {
                                    perror("failed to join thread\n");
                                    std::cout<<client_count[i]<<" :"<<j;
                                    return 3;
                                 }
                               else {
                                         std::cout<<i<<":"<<j<<" Complete :\n";
                                    } ; 
                   };
                    
                
           }
           return 1;

}
