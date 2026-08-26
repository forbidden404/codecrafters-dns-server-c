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
  uint32_t data;
} DNSMessage;
#pragma pack(pop)

typedef enum flags_option {
  QR = 0b1000000000000000,
  OPCODE = 0b0111100000000000,
  AA = 0b0000010000000000,
  TC = 0b0000001000000000,
  RD = 0b0000000100000000,
  RA = 0b0000000010000000,
  Z = 0b0000000001110000,
  RCODE = 0b0000000000001111,
} DNSFlagOption;

DNSHeader dns_header_new(uint16_t packet_identifier, uint16_t flags,
                         uint16_t qdcount, uint16_t ancount, uint16_t nscount,
                         uint16_t arcount);

uint8_t dns_header_get_flag(DNSHeader header, DNSFlagOption flag);
void dns_header_set_flag(DNSHeader header, DNSFlagOption flag, uint8_t value);

DNSQuestion dns_question_new(uint16_t type, uint16_t cls);
DNSAnswer dns_answer_new(uint16_t type, uint16_t cls, uint32_t ttl,
                         uint16_t length);

DNSMessage dns_message_new(DNSHeader header, char *label, DNSQuestion question,
                           char *answer_label, DNSAnswer answer, uint32_t data);
uint8_t *dns_message_to_buffer(DNSMessage message, size_t *message_length);

DNSMessage dns_message_from_buffer(uint8_t *buffer, size_t length);

void dns_message_debug_string(DNSMessage message);

#endif
