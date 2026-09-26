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

DNSHeader dns_header_from_buffer(uint8_t *buffer, size_t length, int *offset) {
  DNSHeader header;
  memset(&header, 0, sizeof(header));

  if (length < 12) {
    return header;
  }

  uint8_t *current = buffer + *offset;

  uint16_t packet_identifier = 0;
  memcpy(&packet_identifier, current, 2);
  header.packet_identifier = ntohs(packet_identifier);
  current += 2;

  uint16_t flags = 0;
  memcpy(&flags, current, 2);
  header.flags = ntohs(flags);
  current += 2;

  uint16_t qdcount = 0;
  memcpy(&qdcount, current, 2);
  header.qdcount = ntohs(qdcount);
  current += 2;

  uint16_t ancount = 0;
  memcpy(&ancount, current, 2);
  header.ancount = ntohs(ancount);
  current += 2;

  uint16_t nscount = 0;
  memcpy(&nscount, current, 2);
  header.nscount = ntohs(nscount);
  current += 2;

  uint16_t arcount = 0;
  memcpy(&arcount, current, 2);
  header.arcount = ntohs(arcount);
  current += 2;

  *offset = current - buffer;
  return header;
}

uint8_t dns_header_get_flag_shift(DNSFlagOption flag) {
  switch (flag) {
  case QR:
    return 15;
  case OPCODE:
    return 11;
  case AA:
    return 10;
  case TC:
    return 9;
  case RD:
    return 8;
  case RA:
    return 7;
  case Z:
    return 4;
  case RCODE:
    return 0;
  }
}

uint8_t dns_header_get_flag(DNSHeader header, DNSFlagOption flag) {
  return (header.flags & flag) >> (dns_header_get_flag_shift(flag));
}

void dns_header_set_flag(DNSHeader *header, DNSFlagOption flag, uint8_t value) {
  uint8_t shift = dns_header_get_flag_shift(flag);

  header->flags &= ~flag;
  header->flags |= (uint16_t)(value << shift) & flag;
}

DNSResult dns_message_from_buffer(const uint8_t *buffer, size_t length,
                                  DNSMessage *message) {
  int offset = 0;
  DNSHeader header = dns_header_from_buffer((uint8_t *)buffer, length, &offset);

  DNSQuestion question;
  DNSAnswer answer;

  *message = dns_message_new(header, "", question, "", answer, NULL, 0);

  return DNS_OK;
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
  answer.ttl = htonl(ttl);
  answer.length = htons(length);

  return answer;
}

DNSMessage dns_message_new(DNSHeader header, char *label, DNSQuestion question,
                           char *answer_label, DNSAnswer answer, uint8_t *data,
                           size_t rdata_length) {
  DNSMessage message = {0};

  message.header = header;

  size_t name_length = strlen(label);
  message.label = calloc(1, name_length + 1);
  if (message.label == NULL) {
    return message;
  }

  memcpy(message.label, label, name_length);
  message.label_length = name_length;

  message.question = question;

  size_t answer_length = strlen(answer_label);
  if (answer_length > 0) {
    message.answer_label = calloc(1, answer_length + 1);
    if (message.answer_label == NULL) {
      free(message.label);
      message.label = NULL;
      return message;
    }

    memcpy(message.answer_label, answer_label, answer_length);
  }

  message.answer_length = answer_length;
  message.answer = answer;

  message.rdata_length = rdata_length;

  if (rdata_length > 0) {
    message.rdata = malloc(rdata_length);

    if (message.rdata == NULL) {
      free(message.label);
      free(message.answer_label);

      message.label = NULL;
      message.answer_label = NULL;
      message.rdata_length = 0;

      return message;
    }

    memcpy(message.rdata, data, rdata_length);
  }

  return message;
}

uint8_t *dns_message_to_buffer(DNSMessage message, size_t *message_length) {
  size_t encoded_label_length = 0;
  size_t encoded_answer_label_length = 0;

  uint8_t encoded_label[DNS_QNAME_MAX_LEN + 2];
  uint8_t encoded_answer_label[DNS_QNAME_MAX_LEN + 2];

  encode_name(encoded_label, &encoded_label_length, (uint8_t *)message.label);

  encode_name(encoded_answer_label, &encoded_answer_label_length,
              (uint8_t *)message.answer_label);

  size_t header_length = sizeof(message.header);
  size_t question_length = sizeof(message.question);
  size_t answer_length = sizeof(message.answer);

  *message_length = header_length + encoded_label_length + question_length +
                    encoded_answer_label_length + answer_length +
                    message.rdata_length;

  uint8_t *msg = calloc(1, *message_length);

  if (msg == NULL) {
    *message_length = 0;
    return NULL;
  }

  size_t offset = 0;

  memcpy(msg + offset, &message.header, sizeof(message.header));
  offset += sizeof(message.header);

  memcpy(msg + offset, encoded_label, encoded_label_length);
  offset += encoded_label_length;

  memcpy(msg + offset, &message.question, sizeof(message.question));
  offset += sizeof(message.question);

  memcpy(msg + offset, encoded_answer_label, encoded_answer_label_length);
  offset += encoded_answer_label_length;

  memcpy(msg + offset, &message.answer, sizeof(message.answer));
  offset += sizeof(message.answer);

  if (message.rdata_length > 0) {
    memcpy(msg + offset, message.rdata, message.rdata_length);
    offset += message.rdata_length;
  }

  return msg;
}
