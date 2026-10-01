#include "dns.h"

typedef struct dns_resolver DNSResolver;

typedef DNSMessage *(*DNSResolverProcessor)(DNSResolver *resolver,
                                            DNSMessage *request);

DNSResolver *dns_resolver_new(char *address, DNSResolverProcessor processor);
void dns_resolver_free(DNSResolver *resolver);

DNSMessage *dns_resolver_handle_message(DNSResolver *resolver,
                                        DNSMessage *request);

DNSResolverProcessor dns_resolver_make_default_processor(void);
