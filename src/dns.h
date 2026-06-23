#ifndef _DNS_H
#define _DNS_H

#include <stdint.h>
#include <sys/types.h>

typedef struct dns_header {
  uint16_t packet_identifier;
  uint16_t qr_to_rcode;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} *DNSHeader;

enum qr_to_rcode_options {
  QR = 0b1000000000000000,
  OPCODE = 0b0111100000000000,
  AA = 0b0000010000000000,
  TC = 0b0000001000000000,
  RD = 0b0000000100000000,
  RA = 0b0000000010000000,
  Z = 0b0000000001110000,
  RCODE = 0b0000000000001111,
};

DNSHeader dns_header_new(uint16_t packet_identifier, uint16_t qr_to_rcode,
                         uint16_t qdcount, uint16_t ancount, uint16_t nscount,
                         uint16_t arcount);
DNSHeader dns_header_from_buffer(const char *buffer);
void dns_header_delete(DNSHeader header);

void dns_header_set(DNSHeader header, enum qr_to_rcode_options option,
                    uint8_t value);
uint8_t dns_header_get(DNSHeader header, enum qr_to_rcode_options option);

#endif
