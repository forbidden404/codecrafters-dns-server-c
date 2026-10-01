add_executable(run_tests test_dns.c)
add_executable(run_tests_resolver test_resolver.c)

# Link against the application logic and the Unity framework
target_link_libraries(run_tests PRIVATE dns unity)
target_link_libraries(run_tests_resolver PRIVATE dns resolver unity)

# Register the executable with CTest
add_test(NAME utest_dns COMMAND run_tests)
add_test(NAME utest_resolver COMMAND run_tests_resolver)
