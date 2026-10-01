#include "dns.h"
#include "resolver.h"

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
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

int main(int argc, char *argv[]) {
  int opt;
  int opt_index = 0;
  char *resolver_address = NULL;

  static struct option options[] = {{"resolver", required_argument, 0, 0},
                                    {0, 0, 0, 0}};

  opt = getopt_long(argc, argv, "", options, &opt_index);

  if (opt != -1) {
    switch (opt) {
    case 0:
      if (optarg) {
        resolver_address = strdup(optarg);
      }
    }
  }

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

  DNSResolver *resolver = NULL;
  if (resolver_address != NULL) {
    resolver = dns_resolver_new(resolver_address,
                                dns_resolver_make_default_processor());
  }

  while (1) {
    // Receive data
    bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0,
                         (struct sockaddr *)&clientAddress, &clientAddrLen);
    if (bytesRead == -1) {
      perror("Error receiving data");
      break;
    }

    DNSMessage *received_message;
    DNSResult result = dns_message_from_buffer((uint8_t *)buffer, bytesRead,
                                               &received_message);

    if (result != DNS_OK) {
      perror("Malformed DNS message");
    }

    DNSMessage *response;

    if (resolver) {
      response = dns_resolver_handle_message(resolver, received_message);
    } else {
      response = dns_response_for_message(received_message);
    }

    size_t message_length = 0;
    uint8_t *msg = dns_message_to_buffer(*response, &message_length);

    // Send response
    if (sendto(udpSocket, msg, message_length, 0,
               (struct sockaddr *)&clientAddress,
               sizeof(clientAddress)) == -1) {
      perror("Failed to send response");
    }
  }

  close(udpSocket);
  dns_resolver_free(resolver);

  return 0;
}
