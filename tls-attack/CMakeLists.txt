cmake_minimum_required(VERSION 3.0) # setting this is required
project(tls-attack)            # this sets the project name

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

file(GLOB_RECURSE sources      src/main/*.cpp src/main/*.h)

add_executable(${PROJECT_NAME} ${sources})

# Just for example add some compiler flags.
target_compile_options(${PROJECT_NAME} PUBLIC -std=c++2a -O3 -Wall -Wextra -fdiagnostics-color=always
    #-ggdb
    #-DDEBUG
    #-fsanitize=address,undefined,leak
    -DMBEDTLS_ALLOW_PRIVATE_ACCESS
-pedantic -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-include-dirs -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Wno-unused
)

target_link_options(${PROJECT_NAME} PUBLIC
    #-fsanitize=address,undefined,leak
)

target_include_directories(${PROJECT_NAME} PUBLIC src/main mbedtls/include)

add_subdirectory(./mbedtls)

target_link_libraries(${PROJECT_NAME} PUBLIC
  -lgivaro
  -lgmp
  MbedTLS::mbedtls
  MbedTLS::mbedcrypto
  MbedTLS::mbedx509
)
# This must be last
include(CPack)
