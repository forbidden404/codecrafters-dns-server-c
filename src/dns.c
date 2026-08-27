#include "dns.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
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

void dns_header_set_flag(DNSHeader header, DNSFlagOption flag, uint8_t value) {
  header.flags |= (flag & (value << dns_header_get_flag_shift(flag)));
}

uint8_t *decode_name(uint8_t *src, int *dst_length) {
  if (src == NULL) {
    return NULL;
  }

  *dst_length = 0;
  uint8_t *current = src;

  uint8_t *name = calloc(1, sizeof(uint8_t));

  while (*current != 0 && *dst_length < DNS_QNAME_MAX_LEN) {
    uint8_t size = *current;

    // add '.'
    if (current != src) {
      name[*dst_length] = '.';
      *dst_length += 1;
    }

    current++;

    // copy size bytes to str
    uint8_t *end = name + *dst_length;
    *dst_length += size;
    name = realloc(name, *dst_length);
    memcpy(end, current, size);

    current += size;
  }

  name[*dst_length] = 0;
  return name;
}

DNSQuestion dns_question_from_buffer(uint8_t *buffer, size_t length,
                                     int *offset) {
  DNSQuestion question;
  memset(&question, 0, sizeof(question));

  uint8_t *current = buffer + *offset;

  uint16_t type = 0;
  memcpy(&type, current, 2);
  question.type = ntohs(type);
  current += 2;

  uint16_t cls = 0;
  memcpy(&cls, current, 2);
  question.cls = ntohs(cls);
  current += 2;

  *offset = current - buffer;

  return question;
}

DNSAnswer dns_answer_from_buffer(uint8_t *buffer, size_t length, int *offset) {
  DNSAnswer answer;
  memset(&answer, 0, sizeof(answer));

  uint8_t *current = buffer + *offset;

  uint16_t type = 0;
  memcpy(&type, current, 2);
  answer.type = ntohs(type);
  current += 2;

  uint16_t cls = 0;
  memcpy(&cls, current, 2);
  answer.cls = ntohs(cls);
  current += 2;

  uint32_t ttl = 0;
  memcpy(&ttl, current, 4);
  answer.ttl = ntohl(ttl);
  current += 4;

  uint16_t len = 0;
  memcpy(&len, current, 2);
  answer.length = ntohs(len);
  current += 2;

  *offset = current - buffer;

  return answer;
}

DNSMessage dns_message_from_buffer(uint8_t *buffer, size_t length) {
  int offset = 0;
  DNSHeader header = dns_header_from_buffer((uint8_t *)buffer, length, &offset);

  int question_name_len = 0;
  uint8_t *question_name = decode_name(buffer + offset, &question_name_len);
  offset += question_name_len + 1;

  DNSQuestion question =
      dns_question_from_buffer((uint8_t *)buffer, length, &offset);

  int answer_name_len = 0;
  uint8_t *answer_name = decode_name(buffer + offset, &answer_name_len);
  offset += answer_name_len + 1;

  DNSAnswer answer = dns_answer_from_buffer((uint8_t *)buffer, length, &offset);

  uint32_t data = *(buffer + offset);

  DNSMessage message = dns_message_new(header, (char *)question_name, question,
                                       (char *)answer_name, answer, data);

  return message;
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
                           char *answer_label, DNSAnswer answer,
                           uint32_t data) {
  DNSMessage message = {0};
  message.header = header;

  size_t name_length = strlen(label);

  message.label = calloc(1, name_length + 1);
  strncpy(message.label, label, name_length);
  message.label_length = htonl(name_length);

  message.question = question;

  size_t answer_length = strlen(answer_label);

  message.answer_label = calloc(1, answer_length + 1);
  strncpy(message.answer_label, answer_label, answer_length);
  message.answer_length = htonl(answer_length);

  message.answer = answer;

  message.data = data;

  return message;
}

uint8_t *dns_message_to_buffer(DNSMessage message, size_t *message_length) {
  *message_length = sizeof(message.header) + message.label_length +
                    sizeof(message.question) + message.answer_length +
                    sizeof(message.answer) + 4;
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
         &message.data, 4);
  return msg;
}

#define print_with_tagline(t_, f_, ...)                                        \
  printf("[%s]: " f_ "\n", t_, ##__VA_ARGS__)

typedef uint32_t (*Parse32)(uint32_t);
typedef uint16_t (*Parse16)(uint16_t);

void dns_header_debug_string(DNSHeader header, char *tag, int sending) {
  print_with_tagline(tag, "\tHeader");

  Parse32 parse32 = sending ? &ntohl : &htonl;
  Parse16 parse16 = sending ? &ntohs : &htons;

  print_with_tagline(tag, "\t\tpacket_identifier: %u",
                     parse16(header.packet_identifier));
  print_with_tagline(tag, "\t\tflags: %u", parse16(header.flags));
  print_with_tagline(tag, "\t\tqdcount: %u", parse16(header.qdcount));
  print_with_tagline(tag, "\t\tancount: %u", parse16(header.ancount));
  print_with_tagline(tag, "\t\tnscount: %u", parse16(header.nscount));
  print_with_tagline(tag, "\t\tarcount: %u", parse16(header.arcount));
}

void dns_question_debug_string(DNSQuestion question, char *tag, int sending) {
  print_with_tagline(tag, "\tQuestion");

  Parse32 parse32 = sending ? &ntohl : &htonl;
  Parse16 parse16 = sending ? &ntohs : &htons;

  print_with_tagline(tag, "\t\ttype: %u", parse16(question.type));
  print_with_tagline(tag, "\t\tcls: %u", parse16(question.cls));
}

void dns_answer_debug_string(DNSAnswer answer, char *tag, int sending) {
  print_with_tagline(tag, "\tAnswer");

  Parse32 parse32 = sending ? &ntohl : &htonl;
  Parse16 parse16 = sending ? &ntohs : &htons;

  print_with_tagline(tag, "\t\ttype: %u", parse16(answer.type));
  print_with_tagline(tag, "\t\tcls: %u", parse16(answer.cls));
  print_with_tagline(tag, "\t\tttl: %lu", parse32(answer.ttl));
  print_with_tagline(tag, "\t\tlength: %u", parse16(answer.length));
}

void dns_message_debug_string(DNSMessage message, char *tag, int sending) {
  dns_header_debug_string(message.header, tag, sending);

  Parse32 parse32 = sending ? &ntohl : &htonl;
  Parse16 parse16 = sending ? &ntohs : &htons;

  print_with_tagline(tag, "\t\tlabel: %s", message.label);
  print_with_tagline(tag, "\t\tlabel_length: %lu",
                     parse32(message.label_length));

  dns_question_debug_string(message.question, tag, sending);

  dns_answer_debug_string(message.answer, tag, sending);

  print_with_tagline(tag, "\t\tanswer: %s", message.answer_label);
  print_with_tagline(tag, "\t\tanswer_length: %lu",
                     parse32(message.answer_length));

  print_with_tagline(tag, "\tData");
  print_with_tagline(tag, "\tdata: %lu", message.data);
}
