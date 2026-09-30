
#include "dns.h"
#include "list.h"
#include "unity.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void setUp(void) {}

void tearDown(void) {}

/*
 * Helpers
 */

static uint16_t read_u16(const uint8_t *buffer) {
  uint16_t value;

  memcpy(&value, buffer, sizeof(value));

  return ntohs(value);
}

static uint32_t read_u32(const uint8_t *buffer) {
  uint32_t value;

  memcpy(&value, buffer, sizeof(value));

  return ntohl(value);
}

/*
 * Header
 */

void test_dns_header_new_preserves_all_fields(void) {
  DNSHeader *header = dns_header_new(0x1234, 0x8180, 1, 1, 2, 3);

  TEST_ASSERT_EQUAL_UINT16(0x1234, header->packet_identifier);

  TEST_ASSERT_EQUAL_UINT16(0x8180, header->flags);

  TEST_ASSERT_EQUAL_UINT16(1, header->qdcount);
  TEST_ASSERT_EQUAL_UINT16(1, header->ancount);
  TEST_ASSERT_EQUAL_UINT16(2, header->nscount);
  TEST_ASSERT_EQUAL_UINT16(3, header->arcount);
}

void test_dns_header_gets_qr_flag(void) {
  DNSHeader *header = dns_header_new(1, 0x8000, 0, 0, 0, 0);

  TEST_ASSERT_EQUAL_UINT8(1, dns_header_get_flag(*header, QR));
}

void test_dns_header_gets_rd_and_ra_flags(void) {
  DNSHeader *header = dns_header_new(1, 0x0180, 0, 0, 0, 0);

  TEST_ASSERT_EQUAL_UINT8(1, dns_header_get_flag(*header, RD));

  TEST_ASSERT_EQUAL_UINT8(1, dns_header_get_flag(*header, RA));
}

void test_dns_header_gets_opcode(void) {
  /*
   * OPCODE = 5
   */
  DNSHeader *header = dns_header_new(1, 0x2800, 0, 0, 0, 0);

  TEST_ASSERT_EQUAL_UINT8(5, dns_header_get_flag(*header, OPCODE));
}

void test_dns_header_gets_rcode(void) {
  /*
   * RCODE = 3 (NXDOMAIN)
   */
  DNSHeader *header = dns_header_new(1, 0x0003, 0, 0, 0, 0);

  TEST_ASSERT_EQUAL_UINT8(3, dns_header_get_flag(*header, RCODE));
}

void test_dns_header_set_flag_sets_flag(void) {
  DNSHeader *header = dns_header_new(1, 0, 0, 0, 0, 0);

  dns_header_set_flag(header, QR, 1);

  TEST_ASSERT_EQUAL_UINT8(1, dns_header_get_flag(*header, QR));
}

void test_dns_header_set_flag_does_not_change_other_flags(void) {
  DNSHeader *header = dns_header_new(1, 0, 0, 0, 0, 0);

  dns_header_set_flag(header, QR, 1);
  dns_header_set_flag(header, RD, 1);

  TEST_ASSERT_EQUAL_UINT8(1, dns_header_get_flag(*header, QR));

  TEST_ASSERT_EQUAL_UINT8(1, dns_header_get_flag(*header, RD));
}

void test_dns_header_set_flag_can_clear_flag(void) {
  DNSHeader *header = dns_header_new(1, 0x8000, 0, 0, 0, 0);

  TEST_ASSERT_EQUAL_UINT8(1, dns_header_get_flag(*header, QR));

  dns_header_set_flag(header, QR, 0);

  TEST_ASSERT_EQUAL_UINT8(0, dns_header_get_flag(*header, QR));
}

/*
 * Header parsing
 */

void test_dns_header_from_buffer_parses_wire_header(void) {
  const uint8_t packet[] = {
      0x12, 0x34, /* ID */
      0x81, 0x80, /* FLAGS */
      0x00, 0x01, /* QDCOUNT */
      0x00, 0x01, /* ANCOUNT */
      0x00, 0x00, /* NSCOUNT */
      0x00, 0x00  /* ARCOUNT */
  };

  size_t offset = 0;

  DNSHeader *header =
      dns_header_from_buffer((uint8_t *)packet, sizeof(packet), &offset);

  TEST_ASSERT_EQUAL_UINT16(0x1234, header->packet_identifier);

  TEST_ASSERT_EQUAL_UINT16(0x8180, header->flags);

  TEST_ASSERT_EQUAL_UINT16(1, header->qdcount);
  TEST_ASSERT_EQUAL_UINT16(1, header->ancount);
  TEST_ASSERT_EQUAL_UINT16(0, header->nscount);
  TEST_ASSERT_EQUAL_UINT16(0, header->arcount);

  TEST_ASSERT_EQUAL_INT(12, offset);
}

void test_dns_header_from_buffer_rejects_truncated_header(void) {
  const uint8_t packet[] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x01,
                            0x00, 0x01, 0x00, 0x00, 0x00};

  size_t offset = 0;

  DNSHeader *header =
      dns_header_from_buffer((uint8_t *)packet, sizeof(packet), &offset);

  /*
   * A truncated header should not be interpreted as
   * a valid DNS header.
   */
  TEST_ASSERT_EQUAL_UINT16(0, header->packet_identifier);
  TEST_ASSERT_EQUAL_UINT16(0, header->flags);
  TEST_ASSERT_EQUAL_UINT16(0, header->qdcount);
  TEST_ASSERT_EQUAL_UINT16(0, header->ancount);
  TEST_ASSERT_EQUAL_UINT16(0, header->nscount);
  TEST_ASSERT_EQUAL_UINT16(0, header->arcount);
}

/*
 * Question
 */

void test_dns_question_new_preserves_type_and_class(void) {
  DNSQuestion *question = dns_question_new("", 1, /* A */
                                           1      /* IN */
  );

  TEST_ASSERT_EQUAL_UINT16(1, question->type);

  TEST_ASSERT_EQUAL_UINT16(1, question->cls);
}

void test_dns_question_supports_aaaa(void) {
  DNSQuestion *question = dns_question_new("", 28, /* AAAA */
                                           1       /* IN */
  );

  TEST_ASSERT_EQUAL_UINT16(28, question->type);

  TEST_ASSERT_EQUAL_UINT16(1, question->cls);
}

/*
 * Answer
 */

void test_dns_resource_new_preserves_all_fields(void) {
  DNSResource *answer = dns_resource_new("", 1, /* A */
                                         1,     /* IN */
                                         3600,  /* TTL */
                                         4,     /* RDLENGTH */
                                         NULL);

  TEST_ASSERT_EQUAL_UINT16(1, answer->type);

  TEST_ASSERT_EQUAL_UINT16(1, answer->class);

  TEST_ASSERT_EQUAL_UINT32(3600, answer->ttl);

  TEST_ASSERT_EQUAL_UINT16(4, answer->rdlength);
}

void test_dns_answer_uses_32_bit_ttl(void) {
  /*
   * This intentionally uses a value that exposes the difference
   * between htons() and htonl().
   */
  DNSResource *answer = dns_resource_new("", 1, 1, 0x12345678, 4, NULL);

  TEST_ASSERT_EQUAL_UINT32(0x12345678, answer->ttl);
}

void test_dns_answer_supports_maximum_ttl(void) {
  DNSResource *answer = dns_resource_new("", 1, 1, UINT32_MAX, 4, NULL);

  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, answer->ttl);
}

/*
 * DNS message construction
 */

void test_dns_message_new_copies_rdata(void) {
  uint8_t rdata[] = {0x08, 0x08, 0x08, 0x08};

  DNSHeader *header = dns_header_new(0x1234, 0x8180, 1, 1, 0, 0);

  DNSQuestion *question = dns_question_new("example.com", 1, 1);

  DNSResource *answer =
      dns_resource_new("example.com", 1, 1, 300, sizeof(rdata), rdata);

  DNSMessage *message = dns_message_new(header);

  list_add_tail(&question->list, message->questions);
  list_add_tail(&answer->list, message->answers);

  DNSResource *entry = list_first_entry(message->answers, DNSResource, list);

  TEST_ASSERT_NOT_NULL(entry);

  TEST_ASSERT_EQUAL_UINT(sizeof(rdata), entry->rdlength);

  TEST_ASSERT_EQUAL_UINT8_ARRAY(rdata, entry->rdata, sizeof(rdata));

  dns_message_free(message);
}

void test_dns_message_new_supports_zero_length_rdata(void) {
  DNSHeader *header = dns_header_new(1, 0, 1, 1, 0, 0);

  DNSQuestion *question = dns_question_new("example.com", 1, 1);

  DNSResource *answer = dns_resource_new("example.com", 1, 1, 60, 0, NULL);

  DNSMessage *message = dns_message_new(header);

  list_add_tail(&question->list, message->questions);
  list_add_tail(&answer->list, message->answers);

  DNSResource *entry = list_first_entry(message->answers, DNSResource, list);

  TEST_ASSERT_EQUAL_UINT(0, entry->rdlength);

  TEST_ASSERT_NULL(entry->rdata);

  dns_message_free(message);
}

/*
 * Serialization
 *
 * The expected wire layout is:
 *
 *   Header
 *   QNAME
 *   QTYPE
 *   QCLASS
 *   Answer NAME
 *   TYPE
 *   CLASS
 *   TTL
 *   RDLENGTH
 *   RDATA
 */

void test_dns_message_serializes_header(void) {
  DNSHeader *header = dns_header_new(0x1234, 0x8180, 1, 1, 0, 0);

  DNSQuestion *question = dns_question_new("example.com", 1, 1);

  uint8_t rdata[] = {8, 8, 8, 8};

  DNSResource *answer =
      dns_resource_new("example.com", 1, 1, 300, sizeof(rdata), rdata);

  DNSMessage *message = dns_message_new(header);

  list_add_tail(&question->list, message->questions);
  list_add_tail(&answer->list, message->answers);

  size_t length = 0;

  uint8_t *buffer = dns_message_to_buffer(*message, &length);

  TEST_ASSERT_NOT_NULL(buffer);

  TEST_ASSERT_EQUAL_UINT16(0x1234, read_u16(buffer));

  TEST_ASSERT_EQUAL_UINT16(0x8180, read_u16(buffer + 2));

  TEST_ASSERT_EQUAL_UINT16(1, read_u16(buffer + 4));

  TEST_ASSERT_EQUAL_UINT16(1, read_u16(buffer + 6));

  TEST_ASSERT_EQUAL_UINT16(0, read_u16(buffer + 8));

  TEST_ASSERT_EQUAL_UINT16(0, read_u16(buffer + 10));

  free(buffer);
  dns_message_free(message);
}

void test_dns_message_serializes_qname_correctly(void) {
  DNSHeader *header = dns_header_new(1, 0, 1, 1, 0, 0);

  DNSQuestion *question = dns_question_new("www.example.com", 1, 1);

  uint8_t rdata[] = {8, 8, 8, 8};

  DNSResource *answer =
      dns_resource_new("www.example.com", 1, 1, 60, sizeof(rdata), rdata);

  DNSMessage *message = dns_message_new(header);

  list_add_tail(&question->list, message->questions);
  list_add_tail(&answer->list, message->answers);

  size_t length = 0;

  uint8_t *buffer = dns_message_to_buffer(*message, &length);

  TEST_ASSERT_NOT_NULL(buffer);

  const uint8_t expected[] = {3,   'w', 'w', 'w', 7,   'e', 'x', 'a', 'm',
                              'p', 'l', 'e', 3,   'c', 'o', 'm', 0};

  TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, buffer + 12, sizeof(expected));

  free(buffer);
  dns_message_free(message);
}

void test_dns_message_serializes_question_correctly(void) {
  DNSHeader *header = dns_header_new(1, 0, 1, 1, 0, 0);

  DNSQuestion *question = dns_question_new("example.com", 28, 1);

  uint8_t rdata[16] = {0};

  DNSResource *answer =
      dns_resource_new("example.com", 28, 1, 300, sizeof(rdata), rdata);

  DNSMessage *message = dns_message_new(header);

  list_add_tail(&question->list, message->questions);
  list_add_tail(&answer->list, message->answers);

  size_t length = 0;

  uint8_t *buffer = dns_message_to_buffer(*message, &length);

  TEST_ASSERT_NOT_NULL(buffer);

  /*
   * Header = 12 bytes
   * example.com = 13 bytes
   *
   * QTYPE starts at:
   *
   * 12 + 13 = 25
   */
  TEST_ASSERT_EQUAL_UINT16(28, read_u16(buffer + 25));

  TEST_ASSERT_EQUAL_UINT16(1, read_u16(buffer + 27));

  free(buffer);
  dns_message_free(message);
}

void test_dns_message_serializes_answer_fields(void) {
  DNSHeader *header = dns_header_new(1, 0, 1, 1, 0, 0);

  DNSQuestion *question = dns_question_new("example.com", 1, 1);

  uint8_t rdata[] = {8, 8, 8, 8};

  DNSResource *answer =
      dns_resource_new("example.com", 1, 1, 0x12345678, sizeof(rdata), rdata);

  DNSMessage *message = dns_message_new(header);

  list_add_tail(&question->list, message->questions);
  list_add_tail(&answer->list, message->answers);

  size_t length = 0;

  uint8_t *buffer = dns_message_to_buffer(*message, &length);

  TEST_ASSERT_NOT_NULL(buffer);

  /*
   * Header      = 12
   * QNAME       = 13
   * Question    = 4
   * Answer name = 13
   *
   * Answer starts at 42.
   */
  const size_t answer_offset = 42;

  TEST_ASSERT_EQUAL_UINT16(1, read_u16(buffer + answer_offset));

  TEST_ASSERT_EQUAL_UINT16(1, read_u16(buffer + answer_offset + 2));

  TEST_ASSERT_EQUAL_UINT32(0x12345678, read_u32(buffer + answer_offset + 4));

  TEST_ASSERT_EQUAL_UINT16(4, read_u16(buffer + answer_offset + 8));

  free(buffer);
  dns_message_free(message);
}

void test_dns_message_serializes_variable_length_rdata(void) {
  DNSHeader *header = dns_header_new(1, 0, 1, 1, 0, 0);

  DNSQuestion *question = dns_question_new("example.com", 1, 1);

  /*
   * Deliberately arbitrary data. The DNS message layer should
   * treat RDATA as opaque bytes.
   */
  uint8_t rdata[] = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03};

  DNSResource *answer =
      dns_resource_new("example.com", 1, 1, 300, sizeof(rdata), rdata);

  DNSMessage *message = dns_message_new(header);

  list_add_tail(&question->list, message->questions);
  list_add_tail(&answer->list, message->answers);

  size_t length = 0;

  uint8_t *buffer = dns_message_to_buffer(*message, &length);

  TEST_ASSERT_NOT_NULL(buffer);

  /*
   * Header      = 12
   * QNAME       = 13
   * Question    = 4
   * Answer name = 13
   * Answer      = 10
   * RDATA       = 7
   *
   * Total       = 59
   */
  TEST_ASSERT_EQUAL_UINT(59, length);

  const size_t answer_offset = 42;
  const size_t rdata_length_offset = answer_offset + 8;
  const size_t rdata_offset = answer_offset + 10;

  TEST_ASSERT_EQUAL_UINT16(sizeof(rdata),
                           read_u16(buffer + rdata_length_offset));

  TEST_ASSERT_EQUAL_UINT8_ARRAY(rdata, buffer + rdata_offset, sizeof(rdata));

  free(buffer);
  dns_message_free(message);
}

void test_dns_message_serializes_zero_length_rdata(void) {
  DNSHeader *header = dns_header_new(1, 0, 1, 1, 0, 0);

  DNSQuestion *question = dns_question_new("example.com", 1, 1);

  DNSResource *answer = dns_resource_new("example.com", 1, 1, 60, 0, NULL);

  DNSMessage *message = dns_message_new(header);

  list_add_tail(&question->list, message->questions);
  list_add_tail(&answer->list, message->answers);

  size_t length = 0;

  uint8_t *buffer = dns_message_to_buffer(*message, &length);

  TEST_ASSERT_NOT_NULL(buffer);

  /*
   * Header      = 12
   * QNAME       = 13
   * Question    = 4
   * Answer name = 13
   * Answer      = 10
   *
   * Total       = 52
   */
  TEST_ASSERT_EQUAL_UINT(52, length);

  const size_t answer_offset = 42;

  TEST_ASSERT_EQUAL_UINT16(0, read_u16(buffer + answer_offset + 8));

  free(buffer);
  dns_message_free(message);
}

void test_dns_message_serializes_aaaa_rdata(void) {
  DNSHeader *header = dns_header_new(1, 0, 1, 1, 0, 0);

  DNSQuestion *question = dns_question_new("example.com", 28, 1);

  uint8_t rdata[] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

  DNSResource *answer =
      dns_resource_new("example.com", 28, 1, 300, sizeof(rdata), rdata);

  DNSMessage *message = dns_message_new(header);

  list_add_tail(&question->list, message->questions);
  list_add_tail(&answer->list, message->answers);

  size_t length = 0;

  uint8_t *buffer = dns_message_to_buffer(*message, &length);

  TEST_ASSERT_NOT_NULL(buffer);

  const size_t answer_offset = 42;
  const size_t rdata_offset = answer_offset + 10;

  TEST_ASSERT_EQUAL_UINT16(16, read_u16(buffer + answer_offset + 8));

  TEST_ASSERT_EQUAL_UINT8_ARRAY(rdata, buffer + rdata_offset, sizeof(rdata));

  free(buffer);
  dns_message_free(message);
}

/*
 * Parsing
 *
 * These tests describe the desired behavior of
 * dns_message_from_buffer().
 */

void test_dns_message_from_buffer_parses_a_response(void) {
  const uint8_t packet[] = {
      /*
       * Header
       *
       * ID      = 0x1234
       * FLAGS   = 0x8180
       * QDCOUNT = 1
       * ANCOUNT = 1
       */
      0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,

      /*
       * QNAME: example.com
       */
      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,

      /*
       * QTYPE = A
       * QCLASS = IN
       */
      0x00, 0x01, 0x00, 0x01,

      /*
       * Answer NAME = example.com
       */
      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,

      /*
       * TYPE = A
       * CLASS = IN
       * TTL = 300
       * RDLENGTH = 4
       */
      0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04,

      /*
       * RDATA = 8.8.8.8
       */
      0x08, 0x08, 0x08, 0x08};

  DNSMessage *message;
  DNSResult result =
      dns_message_from_buffer((uint8_t *)packet, sizeof(packet), &message);

  TEST_ASSERT_EQUAL(result, DNS_OK);

  TEST_ASSERT_EQUAL_UINT16(0x1234, message->header.packet_identifier);

  TEST_ASSERT_EQUAL_UINT16(0x8180, message->header.flags);

  TEST_ASSERT_EQUAL_UINT16(1, message->header.qdcount);

  TEST_ASSERT_EQUAL_UINT16(1, message->header.ancount);

  DNSQuestion *question =
      list_first_entry(message->questions, DNSQuestion, list);

  TEST_ASSERT_EQUAL_STRING("example.com", question->qname);

  TEST_ASSERT_EQUAL_UINT16(1, question->type);

  TEST_ASSERT_EQUAL_UINT16(1, question->cls);

  DNSResource *answer = list_first_entry(message->answers, DNSResource, list);

  TEST_ASSERT_EQUAL_STRING("example.com", answer->name);

  TEST_ASSERT_EQUAL_UINT16(1, answer->type);

  TEST_ASSERT_EQUAL_UINT16(1, answer->class);

  TEST_ASSERT_EQUAL_UINT32(300, answer->ttl);

  TEST_ASSERT_EQUAL_UINT16(4, answer->rdlength);

  const uint8_t expected_rdata[] = {8, 8, 8, 8};

  TEST_ASSERT_EQUAL_UINT8_ARRAY(expected_rdata, answer->rdata,
                                sizeof(expected_rdata));

  dns_message_free(message);
}

void test_dns_message_round_trip_preserves_rdata(void) {
  DNSHeader *header = dns_header_new(0xCAFE, 0x8180, 1, 1, 0, 0);

  DNSQuestion *question = dns_question_new("example.com", 1, 1);

  uint8_t rdata[] = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03};

  DNSResource *answer =
      dns_resource_new("example.com", 1, 1, 300, sizeof(rdata), rdata);

  DNSMessage *original = dns_message_new(header);

  list_add_tail(&question->list, original->questions);
  list_add_tail(&answer->list, original->answers);

  size_t length = 0;

  uint8_t *buffer = dns_message_to_buffer(*original, &length);

  TEST_ASSERT_NOT_NULL(buffer);

  DNSMessage *parsed;
  DNSResult result = dns_message_from_buffer(buffer, length, &parsed);

  TEST_ASSERT_EQUAL(result, DNS_OK);

  DNSQuestion *original_question =
      list_first_entry(original->questions, DNSQuestion, list);
  DNSQuestion *parsed_question =
      list_first_entry(parsed->questions, DNSQuestion, list);

  TEST_ASSERT_EQUAL_STRING(original_question->qname, parsed_question->qname);

  DNSResource *original_answer =
      list_first_entry(original->answers, DNSResource, list);
  DNSResource *parsed_answer =
      list_first_entry(parsed->answers, DNSResource, list);

  TEST_ASSERT_EQUAL_STRING(original_answer->name, parsed_answer->name);

  TEST_ASSERT_EQUAL_UINT16(original->header.packet_identifier,
                           parsed->header.packet_identifier);

  TEST_ASSERT_EQUAL_UINT16(original->header.flags, parsed->header.flags);

  TEST_ASSERT_EQUAL_UINT16(original_question->type, parsed_question->type);

  TEST_ASSERT_EQUAL_UINT16(original_question->cls, parsed_question->cls);

  TEST_ASSERT_EQUAL_UINT16(original_answer->type, parsed_answer->type);

  TEST_ASSERT_EQUAL_UINT16(original_answer->class, parsed_answer->class);

  TEST_ASSERT_EQUAL_UINT32(original_answer->ttl, parsed_answer->ttl);

  TEST_ASSERT_EQUAL_UINT16(original_answer->rdlength, parsed_answer->rdlength);

  TEST_ASSERT_EQUAL_UINT(sizeof(rdata), parsed_answer->rdlength);

  TEST_ASSERT_EQUAL_UINT8_ARRAY(rdata, parsed_answer->rdata, sizeof(rdata));

  free(buffer);

  dns_message_free(original);

  dns_message_free(parsed);
}

/*
 * Test runner
 */

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_dns_header_new_preserves_all_fields);

  RUN_TEST(test_dns_header_gets_qr_flag);
  RUN_TEST(test_dns_header_gets_rd_and_ra_flags);
  RUN_TEST(test_dns_header_gets_opcode);
  RUN_TEST(test_dns_header_gets_rcode);

  RUN_TEST(test_dns_header_set_flag_sets_flag);
  RUN_TEST(test_dns_header_set_flag_does_not_change_other_flags);
  RUN_TEST(test_dns_header_set_flag_can_clear_flag);

  RUN_TEST(test_dns_header_from_buffer_parses_wire_header);
  RUN_TEST(test_dns_header_from_buffer_rejects_truncated_header);

  RUN_TEST(test_dns_question_new_preserves_type_and_class);
  RUN_TEST(test_dns_question_supports_aaaa);

  RUN_TEST(test_dns_resource_new_preserves_all_fields);
  RUN_TEST(test_dns_answer_uses_32_bit_ttl);
  RUN_TEST(test_dns_answer_supports_maximum_ttl);

  RUN_TEST(test_dns_message_new_copies_rdata);
  RUN_TEST(test_dns_message_new_supports_zero_length_rdata);

  RUN_TEST(test_dns_message_serializes_header);
  RUN_TEST(test_dns_message_serializes_qname_correctly);
  RUN_TEST(test_dns_message_serializes_question_correctly);
  RUN_TEST(test_dns_message_serializes_answer_fields);
  RUN_TEST(test_dns_message_serializes_variable_length_rdata);
  RUN_TEST(test_dns_message_serializes_zero_length_rdata);
  RUN_TEST(test_dns_message_serializes_aaaa_rdata);

  RUN_TEST(test_dns_message_from_buffer_parses_a_response);
  RUN_TEST(test_dns_message_round_trip_preserves_rdata);

  return UNITY_END();
}
