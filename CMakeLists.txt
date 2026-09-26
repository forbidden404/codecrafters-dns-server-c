cmake_minimum_required(VERSION 3.13)

project(codecrafters-dns-server)

# Enable CTest runner
include(CTest)
enable_testing()

# Automate downloading the Unity testing framework
include(FetchContent)
FetchContent_Declare(
  unity
  GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
  GIT_TAG v2.7.0
)
FetchContent_MakeAvailable(unity)

add_subdirectory(tests)
add_subdirectory(src)

file(GLOB_RECURSE SOURCE_FILES src/*.c src/*.h)

set(CMAKE_C_STANDARD 23) # Enable the C23 standard
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(dns-server ${SOURCE_FILES})
