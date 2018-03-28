cmake_minimum_required (VERSION 2.9)

project (syn-scanner C)

set (CFLAGS,
    -g
    -Wall
    -Wextra
    -Werror
    -std=gnu99
    )
string (REPLACE ";" " " CMAKE_C_FLAGS "${C_FLAGS}")

set (CMAKE_C_COMPILER "gcc")

add_executable(syn-scanner scanner.c rand.c main.c)

