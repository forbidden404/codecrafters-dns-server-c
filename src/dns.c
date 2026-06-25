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

DNSQuestion dns_question_new(uint16_t type, uint16_t cls) {
  DNSQuestion question = {0};

  question.type = htons(type);
  question.cls = htons(cls);

  return question;
}

DNSAnswer dns_answer_new(uint16_t type, uint16_t cls, uint32_t ttl,
                         uint16_t length) {
  DNSAnswer answer = {0};

  answer.type = htons(type);
  answer.cls = htons(cls);
  answer.ttl = htons(ttl);
  answer.length = htons(length);

  return answer;
}

DNSMessage dns_message_new(DNSHeader header, char *label, DNSQuestion question,
                           char *answer_label, DNSAnswer answer, char *data) {
  DNSMessage message = {0};
  message.header = header;

  uint8_t encoded_name[DNS_QNAME_MAX_LEN];
  size_t encoded_name_length = 0;
  encode_name(&encoded_name[0], &encoded_name_length, (uint8_t *)label);

  message.label = calloc(1, encoded_name_length + 1);
  strncpy(message.label, (char *)encoded_name, encoded_name_length);
  message.label_length = encoded_name_length;

  message.question = question;

  uint8_t encoded_answer[DNS_QNAME_MAX_LEN];
  size_t encoded_answer_length = 0;
  encode_name(&encoded_answer[0], &encoded_answer_length,
              (uint8_t *)answer_label);
  message.answer_label = calloc(1, encoded_answer_length + 1);
  strncpy(message.data, (char *)encoded_answer, encoded_answer_length);
  message.answer_length = encoded_answer_length;

  message.answer = answer;

  uint8_t encoded_data[DNS_QNAME_MAX_LEN];
  size_t encoded_data_length = 0;
  encode_name(&encoded_data[0], &encoded_data_length, (uint8_t *)data);
  message.data = calloc(1, encoded_data_length + 1);
  strncpy(message.data, (char *)encoded_data, encoded_data_length);
  message.data_length = encoded_data_length;

  return message;
}

uint8_t *dns_message_to_buffer(DNSMessage message, size_t *message_length) {
  *message_length = sizeof(message.header) + message.label_length +
                    sizeof(message.question) + message.answer_length +
                    sizeof(message.answer) + message.data_length;
  uint8_t *msg = calloc(1, *message_length);
  memcpy(msg, &message.header, sizeof(message.header));
  memcpy(msg + sizeof(message.header), message.label, message.label_length);
  memcpy(msg + sizeof(message.header) + message.label_length, &message.question,
         sizeof(message.question));
  memcpy(msg + sizeof(message.header) + message.label_length +
             sizeof(message.question),
         message.answer_label, message.answer_length);
  memcpy(msg + sizeof(message.header) + message.label_length +
             sizeof(message.question) + message.answer_length,
         &message.answer, sizeof(message.answer));
  memcpy(msg + sizeof(message.header) + message.label_length +
             sizeof(message.question) + message.answer_length +
             sizeof(message.answer),
         message.data, message.data_length);
  return msg;
}
