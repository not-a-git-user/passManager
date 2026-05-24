cmake_minimum_required(VERSION 3.10)
project(passManager VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(passManager src/main.cpp src/addPass.cpp src/delPass.cpp src/editPass.cpp src/keyDeriv.cpp src/getPass.cpp src/vaultCreation.cpp src/vaultManagement.cpp src/utils.cpp src/delVault.cpp src/config.cpp src/exportVault.cpp src/importVault.cpp src/passwordStrength.cpp)

find_package(nlohmann_json REQUIRED)

# Try to find libsodium (a simple approach)
find_library(SODIUM_LIB sodium)
if(NOT SODIUM_LIB)
  message(FATAL_ERROR "libsodium not found. Install libsodium (sudo pacman -S libsodium).")
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(ARGON2 REQUIRED libargon2)

include_directories(${ARGON2_INCLUDE_DIRS})
target_link_libraries(passManager PRIVATE ${SODIUM_LIB} nlohmann_json::nlohmann_json ${ARGON2_LIBRARIES})

# Compiler warnings (helpful for beginners)
target_compile_options(passManager PRIVATE -Wall -Wextra -Wpedantic)