cmake_minimum_required(VERSION 3.10)
project(cathook VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -fno-strict-aliasing")

add_library(cathook STATIC
    src/cathook.c
    src/disasm_x64.c
    src/trampoline.c
    src/memory.c
)

target_include_directories(cathook PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

add_subdirectory(test)
