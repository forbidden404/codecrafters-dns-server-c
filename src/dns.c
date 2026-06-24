#include "dns.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

DNSHeader dns_header_new(uint16_t packet_identifier, struct flags flags,
                         uint16_t qdcount, uint16_t ancount, uint16_t nscount,
                         uint16_t arcount) {
  DNSHeader header;
  memset(&header, 0, sizeof(header));
  header.packet_identifier = htons(packet_identifier);

  memcpy(&header.flags, &flags, sizeof(flags));

  header.qdcount = ntohs(qdcount);
  header.ancount = ntohs(ancount);
  header.nscount = ntohs(nscount);
  header.arcount = ntohs(arcount);
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
