#include "dns.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

uint16_t from_buffer(const char *buffer, int *index) {
  int local_index = *index;
  uint16_t result = 0;

  result = (buffer[*index] << 8) | buffer[*index + 1];

  *index += 2;
  return result;
}

DNSHeader dns_header_new(uint16_t packet_identifier, uint16_t qr_to_rcode,
                         uint16_t qdcount, uint16_t ancount, uint16_t nscount,
                         uint16_t arcount) {
  DNSHeader header = calloc(1, sizeof(*header));
  header->packet_identifier = packet_identifier;
  header->qr_to_rcode = qr_to_rcode;
  header->qdcount = qdcount;
  header->ancount = ancount;
  header->nscount = nscount;
  header->arcount = arcount;
  return header;
}

DNSHeader dns_header_from_buffer(const char *buffer) {
  size_t length = strlen(buffer);
  if (length < 12) {
    return NULL;
  }

  DNSHeader header = calloc(1, sizeof(*header));

  int index = 0;
  header->packet_identifier = from_buffer(buffer, &index);
  header->qr_to_rcode = from_buffer(buffer, &index);
  header->qdcount = from_buffer(buffer, &index);
  header->ancount = from_buffer(buffer, &index);
  header->nscount = from_buffer(buffer, &index);
  header->arcount = from_buffer(buffer, &index);

  return header;
}

void dns_header_delete(DNSHeader header) {
  if (header) {
    free(header);
  }
}

void dns_header_set(DNSHeader header, enum qr_to_rcode_options option,
                    uint8_t value) {
  header->qr_to_rcode |= (value & option);
}

uint8_t dns_header_get(DNSHeader header, enum qr_to_rcode_options option) {
  return header->qr_to_rcode & option;
}
