#include "dns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void print_bytes(uint8_t *buffer, size_t length) {
  int i;
  for (i = 0; i < length; i++) {
    if (i > 0)
      printf(" ");
    printf("%02X", buffer[i]);
  }
  printf("\n");
}

int main() {
  // Disable output buffering
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  // You can use print statements as follows for debugging, they'll be visible
  // when running tests.
  printf("Logs from your program will appear here!\n");

  int udpSocket, client_addr_len;
  struct sockaddr_in clientAddress;

  udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
  if (udpSocket == -1) {
    printf("Socket creation failed: %s...\n", strerror(errno));
    return 1;
  }

  // Since the tester restarts your program quite often, setting REUSE_PORT
  // ensures that we don't run into 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) <
      0) {
    printf("SO_REUSEPORT failed: %s \n", strerror(errno));
    return 1;
  }

  struct sockaddr_in serv_addr = {
      .sin_family = AF_INET,
      .sin_port = htons(2053),
      .sin_addr = {htonl(INADDR_ANY)},
  };

  if (bind(udpSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
    printf("Bind failed: %s \n", strerror(errno));
    return 1;
  }

  ssize_t bytesRead;
  char buffer[512];
  socklen_t clientAddrLen = sizeof(clientAddress);

  while (1) {
    // Receive data
    bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0,
                         (struct sockaddr *)&clientAddress, &clientAddrLen);
    if (bytesRead == -1) {
      perror("Error receiving data");
      break;
    }

    buffer[bytesRead] = '\0';
    print_bytes((uint8_t *)buffer, bytesRead);

    DNSMessage received_message =
        dns_message_from_buffer((uint8_t *)buffer, bytesRead);

    uint16_t response_flags = received_message.header.flags | 0x8000;
    // if OPCODE != 0
    if (dns_header_get_flag(received_message.header, OPCODE) != 0) {
      response_flags |= 4;
    }

    DNSHeader header = dns_header_new(received_message.header.packet_identifier,
                                      response_flags, 1, 1, 0, 0);
    DNSQuestion question = dns_question_new(1, 1);
    DNSAnswer answer = dns_answer_new(1, 1, 60, 4);
    DNSMessage message = dns_message_new(header, "codecrafters.io", question,
                                         "codecrafters.io", answer, "8.8.8.8");

    size_t message_length = 0;
    uint8_t *msg = dns_message_to_buffer(message, &message_length);
    print_bytes((uint8_t *)msg, message_length);

    // Send response
    if (sendto(udpSocket, msg, message_length, 0,
               (struct sockaddr *)&clientAddress,
               sizeof(clientAddress)) == -1) {
      perror("Failed to send response");
    }
  }

  close(udpSocket);

  return 0;
}
