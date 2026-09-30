add_executable(run_tests test_dns.c)

# Link against the application logic and the Unity framework
target_link_libraries(run_tests PRIVATE dns unity)

# Register the executable with CTest
add_test(NAME utest_dns COMMAND run_tests)
