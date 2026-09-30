#include "dns.h"
#include "list.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DNS_QNAME_MAX_LEN 255
#define DNS_HEADER_LENGTH 12

DNSHeader *dns_header_new(uint16_t packet_identifier, uint16_t flags,
                          uint16_t qdcount, uint16_t ancount, uint16_t nscount,
                          uint16_t arcount) {
  DNSHeader *header = calloc(1, sizeof(*header));
  header->packet_identifier = packet_identifier;
  header->flags = flags;
  header->qdcount = qdcount;
  header->ancount = ancount;
  header->nscount = nscount;
  header->arcount = arcount;
  return header;
}

DNSHeader *dns_header_from_buffer(uint8_t *buffer, size_t length,
                                  size_t *offset) {
  DNSHeader *header = calloc(1, sizeof(*header));

  if (*offset > length || length - *offset < DNS_HEADER_LENGTH) {
    return header;
  }

  uint8_t *current = buffer + *offset;

  uint16_t packet_identifier = 0;
  memcpy(&packet_identifier, current, 2);
  header->packet_identifier = ntohs(packet_identifier);
  current += 2;

  uint16_t flags = 0;
  memcpy(&flags, current, 2);
  header->flags = ntohs(flags);
  current += 2;

  uint16_t qdcount = 0;
  memcpy(&qdcount, current, 2);
  header->qdcount = ntohs(qdcount);
  current += 2;

  uint16_t ancount = 0;
  memcpy(&ancount, current, 2);
  header->ancount = ntohs(ancount);
  current += 2;

  uint16_t nscount = 0;
  memcpy(&nscount, current, 2);
  header->nscount = ntohs(nscount);
  current += 2;

  uint16_t arcount = 0;
  memcpy(&arcount, current, 2);
  header->arcount = ntohs(arcount);
  current += 2;

  *offset = current - buffer;
  return header;
}

uint8_t *decode_name(uint8_t *src, size_t *dst_length,
                     size_t *consumed_length) {
  if (src == NULL) {
    return NULL;
  }

  *dst_length = 0;
  *consumed_length = 0;

  uint8_t *current = src;
  uint8_t *name = calloc(1, 1);

  if (name == NULL) {
    return NULL;
  }

  while (*current != 0 && *dst_length < DNS_QNAME_MAX_LEN) {
    uint8_t size = *current;

    current++;
    *consumed_length += 1;

    if (*dst_length > 0) {
      uint8_t *tmp = realloc(name, *dst_length + 2);

      if (tmp == NULL) {
        free(name);
        return NULL;
      }

      name = tmp;
      name[*dst_length] = '.';
      *dst_length += 1;
    }

    uint8_t *tmp = realloc(name, *dst_length + size + 1);

    if (tmp == NULL) {
      free(name);
      return NULL;
    }

    name = tmp;

    memcpy(name + *dst_length, current, size);
    *dst_length += size;

    current += size;
    *consumed_length += size;
  }

  if (*current == 0) {
    *consumed_length += 1;
    name[*dst_length] = '\0';
  }

  return name;
}

DNSResult dns_question_from_buffer(uint8_t *buffer, size_t length,
                                   size_t *offset, DNSQuestion *question) {
  size_t qname_len = 0;
  size_t qname_consumed = 0;

  question->qname =
      (char *)decode_name(buffer + *offset, &qname_len, &qname_consumed);
  *offset += qname_consumed;

  uint8_t *current = buffer + *offset;

  uint16_t type = 0;
  memcpy(&type, current, 2);
  question->type = ntohs(type);
  current += 2;

  uint16_t cls = 0;
  memcpy(&cls, current, 2);
  question->cls = ntohs(cls);
  current += 2;

  *offset = current - buffer;

  return DNS_OK;
}

DNSResult dns_questions_from_buffer(uint8_t *buffer, size_t count,
                                    struct list_head *list, size_t length,
                                    size_t *offset) {
  for (int i = 0; i < count; i++) {
    DNSQuestion *question = calloc(1, sizeof(*question));
    if (question == NULL) {
      return DNS_ERROR_OUT_OF_MEMORY;
    }

    DNSResult result =
        dns_question_from_buffer(buffer, length, offset, question);

    if (result != DNS_OK) {
      free(question);
      return result;
    }

    list_add_tail(&question->list, list);
  }

  return DNS_OK;
}

DNSResult dns_resource_from_buffer(uint8_t *buffer, size_t length,
                                   size_t *offset, DNSResource *resource) {
  size_t name_len = 0;
  size_t name_consumed = 0;

  resource->name =
      (char *)decode_name(buffer + *offset, &name_len, &name_consumed);
  *offset += name_consumed;

  uint8_t *current = buffer + *offset;

  uint16_t type = 0;
  memcpy(&type, current, 2);
  resource->type = ntohs(type);
  current += 2;

  uint16_t cls = 0;
  memcpy(&cls, current, 2);
  resource->class = ntohs(cls);
  current += 2;

  uint32_t ttl = 0;
  memcpy(&ttl, current, 4);
  resource->ttl = ntohl(ttl);
  current += 4;

  uint16_t len = 0;
  memcpy(&len, current, 2);
  resource->rdlength = ntohs(len);
  current += 2;

  if (resource->rdlength > 0) {
    resource->rdata = calloc(resource->rdlength, sizeof(uint8_t));
    if (resource->rdata == NULL) {
      return DNS_ERROR_OUT_OF_MEMORY;
    }

    for (int i = 0; i < resource->rdlength; i++, current++) {
      resource->rdata[i] = *current;
    }
  }

  *offset = current - buffer;

  return DNS_OK;
}

DNSResult dns_resources_from_buffer(uint8_t *buffer, size_t count,
                                    struct list_head *list, size_t length,
                                    size_t *offset) {
  for (int i = 0; i < count; i++) {
    DNSResource *resource = calloc(1, sizeof(*resource));
    if (resource == NULL) {
      return DNS_ERROR_OUT_OF_MEMORY;
    }

    DNSResult result =
        dns_resource_from_buffer(buffer, length, offset, resource);

    if (result != DNS_OK) {
      free(resource);
      return result;
    }

    list_add_tail(&resource->list, list);
  }

  return DNS_OK;
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
                                  DNSMessage **message) {
  size_t offset = 0;
  DNSHeader *header =
      dns_header_from_buffer((uint8_t *)buffer, length, &offset);

  *message = dns_message_new(header);

  DNSResult result = DNS_OK;

  result = dns_questions_from_buffer((uint8_t *)buffer, header->qdcount,
                                     (*message)->questions, length, &offset);
  if (result != DNS_OK) {
    dns_message_free(*message);
    return result;
  }

  result = dns_resources_from_buffer((uint8_t *)buffer, header->ancount,
                                     (*message)->answers, length, &offset);
  if (result != DNS_OK) {
    dns_message_free(*message);
    return result;
  }

  result = dns_resources_from_buffer((uint8_t *)buffer, header->nscount,
                                     (*message)->authorities, length, &offset);
  if (result != DNS_OK) {
    dns_message_free(*message);
    return result;
  }

  result = dns_resources_from_buffer((uint8_t *)buffer, header->arcount,
                                     (*message)->additionals, length, &offset);
  if (result != DNS_OK) {
    dns_message_free(*message);
    return result;
  }

  return DNS_OK;
}

DNSResult encode_name(const char *name, uint8_t *buffer, size_t buffer_length,
                      size_t *encoded_length) {
  if (name == NULL || buffer == NULL || encoded_length == NULL) {
    return DNS_ERROR_INVALID_PACKET;
  }

  size_t name_length = strlen(name);

  // If DNS root.
  if (name_length == 0) {
    if (buffer_length < 1) {
      return DNS_ERROR_TRUNCATED;
    }

    buffer[0] = 0;
    *encoded_length = 1;
    return DNS_OK;
  }

  size_t input_offset = 0;
  size_t output_offset = 0;

  while (input_offset < name_length) {
    // Find the next '.'
    size_t label_start = input_offset;

    while (input_offset < name_length && name[input_offset] != '.') {
      input_offset++;
    }

    size_t label_length = input_offset - label_start;

    // DNS labels are limited to 63 octets.
    if (label_length == 0 || label_length > 63) {
      return DNS_ERROR_INVALID_NAME;
    }

    // 1 byte for label length + label_length bytes
    if (output_offset + 1 + label_length >= buffer_length) {
      return DNS_ERROR_TRUNCATED;
    }

    buffer[output_offset++] = (uint8_t)label_length;

    memcpy(buffer + output_offset, name + label_start, label_length);

    output_offset += label_length;

    // Skip '.'
    if (input_offset < name_length) {
      input_offset++;
    }
  }

  // Root terminator
  if (output_offset >= buffer_length) {
    return DNS_ERROR_TRUNCATED;
  }

  buffer[output_offset++] = 0;

  *encoded_length = output_offset;

  return DNS_OK;
}

DNSQuestion *dns_question_new(char *qname, uint16_t type, uint16_t cls) {
  DNSQuestion *question = calloc(1, sizeof(*question));

  question->qname = strdup(qname);

  question->type = type;
  question->cls = cls;

  return question;
}

DNSResource *dns_resource_new(char *name, uint16_t type, uint16_t cls,
                              uint32_t ttl, uint16_t length, uint8_t *rdata) {
  DNSResource *resource = calloc(1, sizeof(*resource));

  resource->name = strdup(name);

  resource->type = type;
  resource->class = cls;
  resource->ttl = ttl;
  resource->rdlength = length;

  if (rdata != NULL) {
    resource->rdata = malloc(sizeof(uint8_t) * length);
    memcpy(resource->rdata, rdata, length);
  }

  return resource;
}

DNSMessage *dns_message_new(DNSHeader *header) {
  DNSMessage *message = calloc(1, sizeof(*message));
  if (message == NULL) {
    return NULL;
  }

  message->header = *header;

  message->questions = calloc(1, sizeof(*(message->questions)));
  message->answers = calloc(1, sizeof(*(message->answers)));
  message->authorities = calloc(1, sizeof(*(message->authorities)));
  message->additionals = calloc(1, sizeof(*(message->additionals)));

  INIT_LIST_HEAD(message->questions);
  INIT_LIST_HEAD(message->answers);
  INIT_LIST_HEAD(message->authorities);
  INIT_LIST_HEAD(message->additionals);

  return message;
}

void dns_message_free(DNSMessage *message) {
  if (message == NULL) {
    return;
  }

  DNSQuestion *question;
  DNSQuestion *next;
  list_for_each_entry_safe(question, next, message->questions, list) {
    if (question != NULL) {
      if (question->qname != NULL) {
        free(question->qname);
      }
      free(question);
    }
  }

  DNSResource *answer;
  DNSResource *answer_next;
  list_for_each_entry_safe(answer, answer_next, message->answers, list) {
    if (answer != NULL) {
      if (answer->name != NULL) {
        free(answer->name);
      }
      if (answer->rdata != NULL) {
        free(answer->rdata);
      }
      free(answer);
    }
  }

  DNSResource *authority;
  DNSResource *authority_next;
  list_for_each_entry_safe(authority, authority_next, message->authorities,
                           list) {
    if (authority != NULL) {
      if (authority->name != NULL) {
        free(authority->name);
      }
      if (authority->rdata != NULL) {
        free(authority->rdata);
      }
      free(authority);
    }
  }

  DNSResource *additional;
  DNSResource *additional_next;
  list_for_each_entry_safe(additional, additional_next, message->additionals,
                           list) {
    if (additional != NULL) {
      if (additional->name != NULL) {
        free(additional->name);
      }
      if (additional->rdata != NULL) {
        free(additional->rdata);
      }
      free(additional);
    }
  }

  free(message);
}

DNSResult dns_header_to_buffer(DNSHeader header, uint8_t **buffer,
                               size_t *offset, size_t *current_size) {
  size_t header_length = sizeof(header);

  size_t available_size = *current_size - *offset;
  if (available_size < header_length) {
    uint8_t *tmp_buffer =
        realloc(*buffer, *current_size + (header_length - available_size));
    if (tmp_buffer == NULL) {
      return DNS_ERROR_OUT_OF_MEMORY;
    }
    *current_size += (header_length - available_size);
    *buffer = tmp_buffer;
  }

  uint16_t value;

  value = ntohs(header.packet_identifier);
  memcpy(*buffer + *offset, &value, sizeof(value));
  *offset += sizeof(value);

  value = ntohs(header.flags);
  memcpy(*buffer + *offset, &value, sizeof(value));
  *offset += sizeof(value);

  value = ntohs(header.qdcount);
  memcpy(*buffer + *offset, &value, sizeof(value));
  *offset += sizeof(value);

  value = ntohs(header.ancount);
  memcpy(*buffer + *offset, &value, sizeof(value));
  *offset += sizeof(value);

  value = ntohs(header.nscount);
  memcpy(*buffer + *offset, &value, sizeof(value));
  *offset += sizeof(value);

  value = ntohs(header.arcount);
  memcpy(*buffer + *offset, &value, sizeof(value));
  *offset += sizeof(value);

  return DNS_OK;
}

DNSResult dns_question_to_buffer(DNSQuestion *question, uint8_t **buffer,
                                 size_t *offset, size_t *current_size) {
  size_t encoded_label_length = 0;
  uint8_t encoded_label[DNS_QNAME_MAX_LEN + 2];

  encode_name(question->qname, encoded_label, DNS_QNAME_MAX_LEN + 2,
              &encoded_label_length);

  size_t question_length = 4 + encoded_label_length;

  size_t available_size = *current_size - *offset;
  if (available_size < question_length) {
    uint8_t *tmp_buffer =
        realloc(*buffer, *current_size + (question_length - available_size));
    if (tmp_buffer == NULL) {
      return DNS_ERROR_OUT_OF_MEMORY;
    }
    *current_size += (question_length - available_size);
    *buffer = tmp_buffer;
  }

  memcpy(*buffer + *offset, encoded_label, encoded_label_length);
  *offset += encoded_label_length;

  uint16_t value;

  value = ntohs(question->type);
  memcpy(*buffer + *offset, &value, sizeof(value));
  *offset += sizeof(value);

  value = ntohs(question->cls);
  memcpy(*buffer + *offset, &value, sizeof(value));
  *offset += sizeof(value);

  return DNS_OK;
}

DNSResult dns_questions_to_buffer(struct list_head *questions, uint8_t **buffer,
                                  size_t *offset, size_t *current_size) {
  DNSQuestion *question;
  list_for_each_entry(question, questions, list) {
    if (question != NULL) {
      DNSResult result =
          dns_question_to_buffer(question, buffer, offset, current_size);
      if (result != DNS_OK) {
        return result;
      }
    }
  }

  return DNS_OK;
}

DNSResult dns_resource_to_buffer(DNSResource *resource, uint8_t **buffer,
                                 size_t *offset, size_t *current_size) {
  size_t encoded_label_length = 0;
  uint8_t encoded_label[DNS_QNAME_MAX_LEN + 2];

  encode_name(resource->name, encoded_label, DNS_QNAME_MAX_LEN + 2,
              &encoded_label_length);

  size_t resource_length = encoded_label_length + 10 + resource->rdlength;

  size_t available_size = *current_size - *offset;
  if (available_size < resource_length) {
    uint8_t *tmp_buffer =
        realloc(*buffer, *current_size + (resource_length - available_size));
    if (tmp_buffer == NULL) {
      return DNS_ERROR_OUT_OF_MEMORY;
    }
    *current_size += (resource_length - available_size);
    *buffer = tmp_buffer;
  }

  memcpy(*buffer + *offset, encoded_label, encoded_label_length);
  *offset += encoded_label_length;

  uint16_t value;

  value = ntohs(resource->type);
  memcpy(*buffer + *offset, &value, sizeof(value));
  *offset += sizeof(value);

  value = ntohs(resource->class);
  memcpy(*buffer + *offset, &value, sizeof(value));
  *offset += sizeof(value);

  uint32_t lvalue = ntohl(resource->ttl);
  memcpy(*buffer + *offset, &lvalue, sizeof(lvalue));
  *offset += sizeof(lvalue);

  value = ntohs(resource->rdlength);
  memcpy(*buffer + *offset, &value, sizeof(value));
  *offset += sizeof(value);

  memcpy(*buffer + *offset, resource->rdata, resource->rdlength);
  *offset += resource->rdlength;

  return DNS_OK;
}

DNSResult dns_resources_to_buffer(struct list_head *head, uint8_t **buffer,
                                  size_t *offset, size_t *current_size) {
  DNSResource *resource;
  list_for_each_entry(resource, head, list) {
    if (resource != NULL) {
      DNSResult result =
          dns_resource_to_buffer(resource, buffer, offset, current_size);
      if (result != DNS_OK) {
        return result;
      }
    }
  }

  return DNS_OK;
}

uint8_t *dns_message_to_buffer(DNSMessage message, size_t *message_length) {
  uint8_t *buffer = calloc(1, DNS_HEADER_LENGTH);
  size_t offset = 0;
  *message_length = DNS_HEADER_LENGTH;

  DNSResult result =
      dns_header_to_buffer(message.header, &buffer, &offset, message_length);
  if (result != DNS_OK) {
    return NULL;
  }

  result = dns_questions_to_buffer(message.questions, &buffer, &offset,
                                   message_length);
  if (result != DNS_OK) {
    return NULL;
  }

  result = dns_resources_to_buffer(message.answers, &buffer, &offset,
                                   message_length);
  if (result != DNS_OK) {
    return NULL;
  }

  result = dns_resources_to_buffer(message.authorities, &buffer, &offset,
                                   message_length);
  if (result != DNS_OK) {
    return NULL;
  }

  result = dns_resources_to_buffer(message.additionals, &buffer, &offset,
                                   message_length);
  if (result != DNS_OK) {
    return NULL;
  }

  return buffer;
}

DNSMessage *dns_response_for_message(DNSMessage *message,
                                     size_t *message_length) {
  uint16_t response_flags = message->header.flags | 0x8000;
  // if OPCODE != 0
  if (dns_header_get_flag(message->header, OPCODE) != 0) {
    response_flags |= 4;
  }

  DNSHeader *header =
      dns_header_new(message->header.packet_identifier, response_flags,
                     message->header.qdcount, message->header.ancount,
                     message->header.nscount, message->header.arcount);
  DNSMessage *response = dns_message_new(header);

  return response;
}
