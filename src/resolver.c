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

typedef struct dns_resolver {
  char *address;
  int socket_fd;
  DNSResolverProcessor processor;
} DNSResolver;

DNSResolver *dns_resolver_new(char *address, DNSResolverProcessor processor) {
  DNSResolver *resolver = calloc(1, sizeof(*resolver));

  if (resolver == NULL) {
    return NULL;
  }

  resolver->address = strdup(address);

  if (resolver->address == NULL) {
    free(resolver);
    return NULL;
  }

  resolver->socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

  if (resolver->socket_fd < 0) {
    free(resolver->address);
    free(resolver);
    return NULL;
  }

  resolver->processor = processor;

  return resolver;
}

void dns_resolver_free(DNSResolver *resolver) {
  if (resolver == NULL) {
    return;
  }

  close(resolver->socket_fd);
  free(resolver->address);
  free(resolver);
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

    DNSMessage *response = resolver->processor(resolver, message);

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

DNSMessage *working_processor(DNSResolver *resolver, DNSMessage *message) {
  // Parse address into <ip>:<port>
  char *delimiter = strchr(resolver->address, ':');

  if (delimiter == NULL) {
    return NULL;
  }

  char ip[INET_ADDRSTRLEN];

  size_t ip_length = delimiter - resolver->address;

  if (ip_length >= sizeof(ip)) {
    return NULL;
  }

  memcpy(ip, resolver->address, ip_length);
  ip[ip_length] = '\0';

  const char *s_port = delimiter + 1;
  uint16_t port = 0;

  const char *errstr;
  port = safe_strtonum(s_port, 0, UINT32_MAX, &errstr);
  if (errstr != NULL) {
    perror(errstr);
    return NULL;
  }

  struct sockaddr_in server_addr;

  // Clear and set up server address structure
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);

  // Convert IP address from text to binary
  if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
    perror("Invalid address / Address not supported");
    return NULL;
  }

  // Send packet
  size_t message_length = 0;
  uint8_t *buffer_message = dns_message_to_buffer(*message, &message_length);

  int bytes_sent =
      sendto(resolver->socket_fd, buffer_message, message_length, 0,
             (struct sockaddr *)&server_addr, sizeof(server_addr));

  free(buffer_message);

  if (bytes_sent < 0) {
    perror("Message transmission failed");
    return NULL;
  }

  if ((size_t)bytes_sent != message_length) {
    perror("Incomplete DNS message sent");
    return NULL;
  }

  // Wait and receive response
  uint8_t buffer[BUFFER_SIZE];

  struct sockaddr_in response_addr = {0};
  socklen_t response_addr_length = sizeof(response_addr);

  int bytes_received =
      recvfrom(resolver->socket_fd, buffer, sizeof(buffer), 0,
               (struct sockaddr *)&response_addr, &response_addr_length);

  if (bytes_received < 0) {
    perror("Receive failed");
    return NULL;
  }

  // Deserialize message into a DNSMessage
  DNSMessage *received_message;
  DNSResult result =
      dns_message_from_buffer(buffer, bytes_received, &received_message);

  if (result != DNS_OK) {
    perror("Deserialization failed");
    return NULL;
  }

  return received_message;
}

DNSResolverProcessor dns_resolver_make_default_processor() {
  return working_processor;
}
