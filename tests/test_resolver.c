#include "dns.h"
#include "list.h"
#include "resolver.h"
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

DNSMessage *mock_processor(DNSResolver *resolver, DNSMessage *message) {
  DNSQuestion *question;
  size_t count = 0;
  list_for_each_entry(question, message->questions, list) {
    uint8_t rdata[] = {0x08, 0x08, 0x08, 0x08};
    DNSResource *resource =
        dns_resource_new(question->qname, question->type, question->cls, 60,
                         sizeof(rdata), rdata);
    list_add_tail(&resource->list, message->answers);
    count++;
  }

  message->header.ancount = count;

  return message;
}

/*
 * Resolver tests
 */
void test_dns_resolver_initializes(void) {
  // Arrange & Act
  DNSResolver *resolver =
      dns_resolver_new("1.1.1.1:53", dns_resolver_make_default_processor());

  // Assert
  TEST_ASSERT_NOT_NULL(resolver);
}

void test_dns_resolver_processes_dns_message(void) {
  // Arrange
  DNSResolver *resolver = dns_resolver_new("1.1.1.1:53", mock_processor);

  DNSHeader *header = dns_header_new(0x1234, 0x8180, 1, 1, 2, 3);
  DNSMessage *request = dns_message_new(header);

  // Act
  DNSMessage *response = dns_resolver_handle_message(resolver, request);

  // Assert
  TEST_ASSERT_EQUAL_UINT16(0x1234, response->header.packet_identifier);

  TEST_ASSERT_EQUAL_UINT16(0x8180, response->header.flags);

  TEST_ASSERT_EQUAL_UINT16(1, response->header.qdcount);
  TEST_ASSERT_EQUAL_UINT16(0, response->header.ancount);
  TEST_ASSERT_EQUAL_UINT16(2, response->header.nscount);
  TEST_ASSERT_EQUAL_UINT16(3, response->header.arcount);
}

void test_dns_resolver_processes_messages_with_two_questions(void) {
  // Arrange
  DNSResolver *resolver = dns_resolver_new("1.1.1.1:53", mock_processor);

  DNSHeader *header = dns_header_new(0x1234, 0x8180, 2, 0, 0, 0);
  DNSMessage *request = dns_message_new(header);

  DNSQuestion *first_question = dns_question_new("www.example.com", 1, 1);
  DNSQuestion *second_question = dns_question_new("www.example2.com", 1, 1);

  list_add_tail(&first_question->list, request->questions);
  list_add_tail(&second_question->list, request->questions);

  // Act
  DNSMessage *response = dns_resolver_handle_message(resolver, request);

  // Assert
  DNSResource *first_answer =
      list_first_entry_or_null(response->answers, DNSResource, list);
  DNSResource *second_answer =
      list_first_entry_or_null(&first_answer->list, DNSResource, list);

  TEST_ASSERT_EQUAL_UINT16(request->header.ancount, 0);
  TEST_ASSERT_EQUAL_UINT16(response->header.ancount, 2);

  TEST_ASSERT_NOT_NULL(first_answer);
  TEST_ASSERT_NOT_NULL(second_answer);

  TEST_ASSERT_EQUAL_STRING(first_answer->name, first_question->qname);
  TEST_ASSERT_EQUAL_STRING(second_answer->name, second_question->qname);
}

/*
 * Test runner
 */

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_dns_resolver_initializes);
  RUN_TEST(test_dns_resolver_processes_dns_message);
  RUN_TEST(test_dns_resolver_processes_messages_with_two_questions);

  return UNITY_END();
}
