#include "dns.h"

typedef DNSMessage *(*DNSResolverProcessor)(char *address, DNSMessage *request);

typedef struct dns_resolver {
  char *address;
  DNSResolverProcessor processor;
} DNSResolver;

DNSResolver *dns_resolver_new(char *address, DNSResolverProcessor processor);

DNSMessage *dns_resolver_handle_message(DNSResolver *resolver,
                                        DNSMessage *request);

DNSResolverProcessor dns_resolver_make_default_processor(void);
