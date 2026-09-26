add_library(dns STATIC dns.c)
target_include_directories(dns PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
