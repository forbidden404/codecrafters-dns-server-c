#ifndef _DNS_H
#define _DNS_H

#include <assert.h>
#include <stdint.h>
#include <sys/types.h>

#include "list.h"

typedef struct dns_header {
  uint16_t packet_identifier;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} DNSHeader;

typedef struct dns_question {
  char *qname;
  uint16_t type;
  uint16_t cls;
  struct list_head list;
} DNSQuestion;

typedef struct dns_resource {
  char *name;
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rdlength;
  uint8_t *rdata;
  struct list_head list;
} DNSResource;

typedef struct dns_message {
  DNSHeader header;

  struct list_head *questions;
  struct list_head *answers;
  struct list_head *authorities;
  struct list_head *additionals;
} DNSMessage;

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

typedef enum {
  DNS_OK = 0,
  DNS_ERROR_TRUNCATED,
  DNS_ERROR_INVALID_NAME,
  DNS_ERROR_INVALID_PACKET,
  DNS_ERROR_OUT_OF_MEMORY
} DNSResult;

// Header declarations
DNSHeader *dns_header_new(uint16_t packet_identifier, uint16_t flags,
                          uint16_t qdcount, uint16_t ancount, uint16_t nscount,
                          uint16_t arcount);

DNSHeader *dns_header_from_buffer(uint8_t *buffer, size_t length,
                                  size_t *offset);

uint8_t dns_header_get_flag(DNSHeader header, DNSFlagOption flag);
void dns_header_set_flag(DNSHeader *header, DNSFlagOption flag, uint8_t value);

// Question declarations
DNSQuestion *dns_question_new(char *qname, uint16_t type, uint16_t cls);
DNSResult dns_questions_from_buffer(uint8_t *buffer, size_t count,
                                    struct list_head *list, size_t length,
                                    size_t *offset);

// Resource declarations
DNSResource *dns_resource_new(char *name, uint16_t type, uint16_t class,
                              uint32_t ttl, uint16_t rdlength, uint8_t *rdata);
DNSResult dns_resources_from_buffer(uint8_t *buffer, size_t count,
                                    struct list_head *list, size_t length,
                                    size_t *offset);

// Message declarations
DNSMessage *dns_message_new(DNSHeader *header);
uint8_t *dns_message_to_buffer(DNSMessage message, size_t *message_length);
void dns_message_free(DNSMessage *message);

// Response declaration
DNSMessage *dns_response_for_message(DNSMessage *message,
                                     size_t *message_length);

DNSResult dns_message_from_buffer(const uint8_t *buffer, size_t length,
                                  DNSMessage **message);

#endif
