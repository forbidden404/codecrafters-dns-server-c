add_library(dns STATIC dns.c)
target_include_directories(dns PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_library(resolver STATIC resolver.c)
target_include_directories(resolver PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
