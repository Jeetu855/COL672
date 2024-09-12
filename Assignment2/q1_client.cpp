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
#include<bits/stdc++.h>
#include<algorithm>
using namespace std;
#define BUFFER_SIZE 4096
map<string,int> freq;
void print_freq()
            {
                     map<string,int> ::iterator it=freq.begin();
                     while(it!=freq.end())
                        {
                          cout<<it->first<< " "<<it->second<<endl;
                          ++it;
          
                        }
            };
void removeNewLinesWithcomma(string &str)
{
           replace(str.begin(),str.end(),'\n',','),str.end();

};
void  frequency(string response_str)
      {
           removeNewLinesWithcomma(response_str);
           for(int i=0;i<response_str.size();i++)
            {
                    string s1="";
                    while(i<response_str.size() && response_str[i]!=',' && response_str[i]!=' ')
                            {
                                    s1=s1+response_str[i];
                                    i++;
                            };      
                    freq[s1]=freq[s1]+1;        
            }
      };

int main() {
  map<string,int> freq;  //contain frequency of corresponding word
  int s;
  struct sockaddr_in sock;
  char buffer[BUFFER_SIZE];
  char request[100];
  int offset = 0;
  int bytes_read;

  std::ifstream config_file("config.json", std::ifstream::binary);
  Json::Value config;
  config_file >> config;

  std::string IP = config["server_ip"].asString();
  int PORT = config["server_port"].asInt();
  int MAX_WORDS = config["k"].asInt();
  int PACKET_SIZE = config["p"].asInt();

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    printf("socket");
    return -1;
  }

  sock.sin_addr.s_addr = inet_addr(IP.c_str());
  sock.sin_port = htons(PORT);
  sock.sin_family = AF_INET;

  if (connect(s, (struct sockaddr *)&sock, sizeof(struct sockaddr_in)) != 0) {
    printf("connect");
    close(s);
    return -1;
  }

  while (1) {
    snprintf(request, sizeof(request), "%d", offset);
    if (write(s, request, strlen(request)) < 0) {
      printf("write");
      close(s);
      return -1;
    }

    printf("Response from offset %d:\n", offset);
    int words_received = 0;
    bool eof_received = false;
    std::string response_str = "";

    while (words_received < MAX_WORDS &&
           (bytes_read = read(s, buffer, sizeof(buffer) - 1)) > 0) {
      buffer[bytes_read] = '\0';
      response_str += buffer;
      
      int count = 0;
      for (int i = 0; buffer[i] != '\0'; i++) {
        if (buffer[i] == ',') {
          count++;
        }
      }
      words_received += count + 1;

      if (strstr(buffer, "EOF") != NULL) {
        printf("\nEOF received.\n");
        eof_received = true;
        break;
      }

      if (words_received >= MAX_WORDS) {
        break;
      }
    }

    printf("%s\n", response_str.c_str());       //to C style
    frequency(response_str.c_str());
    if (bytes_read < 0) {
      printf("read");
      close(s);
      return -1;
    }

    if (eof_received) {
      break;
    }

    offset += MAX_WORDS;

    printf("\nSending new request for offset %d\n", offset);
  }
  print_freq();
  close(s);
  return 0;
}
