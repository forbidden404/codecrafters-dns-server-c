#include "dns.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

DNSHeader dns_header_new(uint16_t packet_identifier, uint16_t flags,
                         uint16_t qdcount, uint16_t ancount, uint16_t nscount,
                         uint16_t arcount) {
  DNSHeader header = {0};
  header.packet_identifier = htons(packet_identifier);
  header.flags = htons(flags);
  header.qdcount = htons(qdcount);
  header.ancount = htons(ancount);
  header.nscount = htons(nscount);
  header.arcount = htons(arcount);
  return header;
}

DNSHeader dns_header_from_buffer(const char *buffer) {
  DNSHeader header;
  memset(&header, 0, sizeof(header));

  size_t length = strlen(buffer);
  if (length < 12) {
    return header;
  }

  memcpy(&header, buffer, sizeof(header));

  return header;
}
