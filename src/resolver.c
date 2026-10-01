#include "resolver.h"
#include "dns.h"
#include "list.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

DNSResolver *dns_resolver_new(char *address, DNSResolverProcessor processor) {
  DNSResolver *resolver = calloc(1, sizeof(*resolver));

  resolver->address = strdup(address);
  resolver->processor = processor;

  return resolver;
}

DNSMessage *dns_resolver_handle_message(DNSResolver *resolver,
                                        DNSMessage *request) {
  // For each question, create a new DNSMessage
  DNSQuestion *question;
  DNSHeader *header = dns_header_new(request->header.packet_identifier,
                                     request->header.flags, 1, 0, 0, 0);

  struct list_head *answers = calloc(1, sizeof(*answers));
  INIT_LIST_HEAD(answers);
  size_t answers_count = 0;

  list_for_each_entry(question, request->questions, list) {
    DNSMessage *message = dns_message_new(header);

    // Making copy cause request->questions is needed later,
    // and adding question to another list would change its pointers.
    DNSQuestion *tmp = calloc(1, sizeof(*tmp));
    memcpy(tmp, question, sizeof(*question));

    list_add_tail(&tmp->list, message->questions);

    DNSMessage *response = resolver->processor(resolver->address, message);

    // Extract answer
    DNSResource *answer;
    DNSResource *next;
    // Needs to be safe because we are adding the answer to the answers list.
    // Don't need to make a copy of the answer because we aren't reusing
    // the response->answers later.
    list_for_each_entry_safe(answer, next, response->answers, list) {
      list_add_tail(&answer->list, answers);
      answers_count++;
    }
  }

  DNSMessage *response = dns_response_for_message(request);

  // Insert the responses we got from the processor
  response->header.ancount = answers_count;
  response->answers = answers;

  return response;
}

DNSMessage *returning_processor(char *address, DNSMessage *message) {
  return message;
}

long long safe_strtonum(const char *nptr, long long minval, long long maxval,
                        const char **errstr) {
  long long val;
  char *endptr;

  if (minval > maxval) {
    if (errstr)
      *errstr = "invalid range";
    errno = EINVAL;
    return 0;
  }

  errno = 0;
  val = strtoll(nptr, &endptr, 10);

  if (errno == ERANGE || val < minval || val > maxval) {
    if (errstr)
      *errstr = (val < minval) ? "too small" : "too large";
    return 0;
  }

  if (endptr == nptr || *endptr != '\0') {
    if (errstr)
      *errstr = "invalid digits";
    errno = EINVAL;
    return 0;
  }

  if (errstr)
    *errstr = NULL;
  return val;
}

#define BUFFER_SIZE 1024

DNSMessage *working_processor(char *address, DNSMessage *message) {
  // Parse address into <ip>:<port>
  char *delimiter = ":";

  char *ip = address;
  char *s_port = strchr(address, delimiter[0]);
  uint32_t port = 0;

  if (s_port != NULL) {
    *s_port = '\0';
    s_port++;

    const char *errstr;
    port = strtonum(s_port, 0, UINT32_MAX, &errstr);
    if (errstr != NULL) {
      perror(errstr);
      return NULL;
    }
  } else {
    perror("Failed to parse address into <ip>:<port>");
    return NULL;
  }

  int sockfd;
  uint8_t buffer[BUFFER_SIZE];

  struct sockaddr_in server_addr;
  socklen_t addr_len = sizeof(server_addr);

  // Create a UDP Socket
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("Socket creation failed");
    return NULL;
  }

  // Clear and set up server address structure
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = port;

  // Convert IP address from text to binary
  if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
    perror("Invalid address / Address not supported");
    close(sockfd);
    return NULL;
  }

  // Send packet
  size_t message_length = 0;
  uint8_t *buffer_message = dns_message_to_buffer(*message, &message_length);

  int bytes_sent = sendto(sockfd, buffer_message, message_length, 0,
                          (struct sockaddr *)&server_addr, addr_len);
  if (bytes_sent < 0) {
    perror("Message transmission failed");
    close(sockfd);
    return NULL;
  }

  // Wait and receive response
  int bytes_received = recvfrom(sockfd, buffer, BUFFER_SIZE - 1, 0,
                                (struct sockaddr *)&server_addr, &addr_len);

  if (bytes_received < 0) {
    perror("Receive failed");
    close(sockfd);
    return NULL;
  }

  // Deserialize message into a DNSMessage
  DNSMessage *received_message;
  DNSResult result =
      dns_message_from_buffer(buffer, bytes_received, &received_message);

  if (result != DNS_OK) {
    perror("Deserialization failed");
    close(sockfd);
    return NULL;
  }

  close(sockfd);
  return received_message;
}

DNSResolverProcessor dns_resolver_make_default_processor() {
  return working_processor;
}
