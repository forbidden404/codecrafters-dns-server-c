#include "dns.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define DNS_QNAME_MAX_LEN 255

DNSHeader dns_header_new(uint16_t packet_identifier, uint16_t flags,
                         uint16_t qdcount, uint16_t ancount, uint16_t nscount,
                         uint16_t arcount) {
  DNSHeader header = {0};
  header.packet_identifier = htons(packet_identifier);
  header.flags = htons(flags);
  header.qdcount = htons(qdcount);
  header.ancount = htons(ancount);
  header.nscount = htons(nscount);
  header.arcount = htons(arcount);
  return header;
}

DNSHeader dns_header_from_buffer(const char *buffer) {
  DNSHeader header;
  memset(&header, 0, sizeof(header));

  size_t length = strlen(buffer);
  if (length < 12) {
    return header;
  }

  memcpy(&header, buffer, sizeof(header));

  return header;
}

void encode_name(uint8_t *dst, size_t *dst_len, uint8_t *name) {
  uint8_t *current = name;
  uint8_t *start = name;
  uint8_t *begin = dst;

  while ((current - name) < DNS_QNAME_MAX_LEN) {
    if (*current == '.' || *current == 0) {
      uint8_t len = current - start;

      *dst++ = len;
      memcpy(dst, start, len);
      dst += len;
      start = current + 1;

      if (*current == 0) {
        *dst = 0;
        *dst_len = dst - begin + 1;
        break;
      }
    }

    current++;
  }
}

DNSQuestion dns_question_new(char *name, uint16_t type, uint16_t cls) {
  DNSQuestion question = {0};

  uint8_t encoded_name[DNS_QNAME_MAX_LEN];
  size_t encoded_name_length = 0;
  encode_name(&encoded_name[0], &encoded_name_length, (uint8_t *)name);

  question.name = calloc(1, encoded_name_length + 1);
  strncpy(question.name, (char *)encoded_name, encoded_name_length);
  question.type = htons(type);
  question.cls = htons(cls);

  return question;
}
