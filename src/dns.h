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
typedef struct dns_answer {
  uint16_t type;
  uint16_t cls;
  uint32_t ttl;
  uint16_t length;
} DNSAnswer;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct dns_message {
  DNSHeader header;
  char *label;
  size_t label_length;
  DNSQuestion question;
  char *answer_label;
  size_t answer_length;
  DNSAnswer answer;
  char *data;
  size_t data_length;
} DNSMessage;
#pragma pack(pop)

DNSHeader dns_header_new(uint16_t packet_identifier, uint16_t flags,
                         uint16_t qdcount, uint16_t ancount, uint16_t nscount,
                         uint16_t arcount);

DNSQuestion dns_question_new(uint16_t type, uint16_t cls);
DNSAnswer dns_answer_new(uint16_t type, uint16_t cls, uint32_t ttl,
                         uint16_t length);

DNSMessage dns_message_new(DNSHeader header, char *label, DNSQuestion question,
                           char *answer_label, DNSAnswer answer, char *data);
uint8_t *dns_message_to_buffer(DNSMessage message, size_t *message_length);

DNSMessage dns_message_from_buffer(const char *buffer);

#endif
