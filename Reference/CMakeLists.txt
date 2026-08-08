cmake_minimum_required(VERSION 3.15)
project(Reference C)

# Use explicit C standard for these C sources (they are C files)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Sources (explicit list based on your Reference project)
set(REFERENCE_SOURCES
  argon2.c
  blake2b.c
  core.c
  encoding.c
  ref.c
  run.c
  thread.c
)

add_executable(argon2 ${REFERENCE_SOURCES})

target_include_directories(argon2 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Put outputs in a predictable location: Reference/bin/<Config>
# This makes it easy for generator/CI to find the binary.
set_target_properties(argon2 PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin/$<CONFIG>
  RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_CURRENT_SOURCE_DIR}/bin/Debug
  RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_CURRENT_SOURCE_DIR}/bin/Release
)

# Example: set compile flags (adjust for your needs)
if(MSVC)
  target_compile_options(argon2 PRIVATE /W4 /D_CRT_SECURE_NO_WARNINGS)
else()
  target_compile_options(argon2 PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Optionally install the binary (useful for packaging)
install(TARGETS argon2 RUNTIME DESTINATION bin)