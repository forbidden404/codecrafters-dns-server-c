#ifndef _DNS_H
#define _DNS_H

#include <stdint.h>
#include <sys/types.h>

#pragma pack(push, 1)
typedef struct dns_header {
  uint16_t packet_identifier;
  struct flags {
    uint16_t rcode : 4;
    uint16_t z : 3;
    uint16_t ra : 1;
    uint16_t rd : 1;
    uint16_t tc : 1;
    uint16_t aa : 1;
    uint16_t opcode : 4;
    uint16_t qr : 1;
  } flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} *DNSHeader;
#pragma pack(pop)

DNSHeader dns_header_new(uint16_t packet_identifier, struct flags flags,
                         uint16_t qdcount, uint16_t ancount, uint16_t nscount,
                         uint16_t arcount);
DNSHeader dns_header_from_buffer(const char *buffer);
void dns_header_delete(DNSHeader header);

#endif
