#include "dns.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

DNSHeader dns_header_new(uint16_t packet_identifier, struct flags flags,
                         uint16_t qdcount, uint16_t ancount, uint16_t nscount,
                         uint16_t arcount) {
  DNSHeader header = calloc(1, sizeof(*header));
  header->packet_identifier = htons(packet_identifier);

  header->flags.aa = htons(flags.aa);
  header->flags.opcode = htons(flags.opcode);
  header->flags.qr = htons(flags.qr);
  header->flags.ra = htons(flags.ra);
  header->flags.rcode = htons(flags.rcode);
  header->flags.rd = htons(flags.rd);
  header->flags.tc = htons(flags.tc);
  header->flags.z = htons(flags.z);

  header->qdcount = htons(qdcount);
  header->ancount = htons(ancount);
  header->nscount = htons(nscount);
  header->arcount = htons(arcount);
  return header;
}

DNSHeader dns_header_from_buffer(const char *buffer) {
  size_t length = strlen(buffer);
  if (length < 12) {
    return NULL;
  }

  DNSHeader header = calloc(1, sizeof(*header));

  memcpy(header, buffer, sizeof(*header));

  return header;
}

void dns_header_delete(DNSHeader header) {
  if (header) {
    free(header);
  }
}
