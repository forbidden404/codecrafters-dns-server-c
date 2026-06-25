#ifndef _DNS_H
#define _DNS_H

#include <assert.h>
#include <stdint.h>
#include <sys/types.h>

static_assert(1);
#pragma pack(push, 1)
typedef struct dns_header {
  uint16_t packet_identifier;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} DNSHeader;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct dns_question {
  uint16_t type;
  uint16_t cls;
} DNSQuestion;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct dns_message {
  DNSHeader header;
  char *label;
  size_t label_length;
  DNSQuestion question;
} DNSMessage;
#pragma pack(pop)

DNSHeader dns_header_new(uint16_t packet_identifier, uint16_t flags,
                         uint16_t qdcount, uint16_t ancount, uint16_t nscount,
                         uint16_t arcount);
DNSHeader dns_header_from_buffer(const char *buffer);

DNSQuestion dns_question_new(uint16_t type, uint16_t cls);

DNSMessage dns_message_new(DNSHeader header, char *label, DNSQuestion question);
uint8_t *dns_message_to_buffer(DNSMessage message, size_t *message_length);

#endif
