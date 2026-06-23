#include "dns.h"

#include <arpa/inet.h>
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
  header->packet_identifier = ntohs(packet_identifier);
  header->qr_to_rcode = ntohs(qr_to_rcode);
  header->qdcount = ntohs(qdcount);
  header->ancount = ntohs(ancount);
  header->nscount = ntohs(nscount);
  header->arcount = ntohs(arcount);
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

uint16_t range(enum qr_to_rcode_options option) {
  switch (option) {
  case QR:
    return 1;
  case OPCODE:
    return 4;
  case AA:
    return 1;
  case TC:
    return 1;
  case RD:
    return 1;
  case RA:
    return 1;
  case Z:
    return 3;
  case RCODE:
    return 4;
  }
}

uint16_t create_mask(uint16_t initial, uint16_t end) {
  uint16_t mask = 0;
  for (uint8_t i = initial; i <= end; i++) {
    mask |= 1 << i;
  }
  return mask;
}

void dns_header_set(DNSHeader header, enum qr_to_rcode_options option,
                    uint8_t value) {
  uint16_t r = range(option);
  uint16_t mask = create_mask(0, r - 1);
  header->qr_to_rcode |= ((mask & value) << option);
}

uint8_t dns_header_get(DNSHeader header, enum qr_to_rcode_options option) {
  return header->qr_to_rcode & option;
}
