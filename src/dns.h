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
  QR = 15,
  OPCODE = 11,
  AA = 10,
  TC = 9,
  RD = 8,
  RA = 7,
  Z = 4,
  RCODE = 0,
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
