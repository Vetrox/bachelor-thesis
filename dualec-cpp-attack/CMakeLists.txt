cmake_minimum_required(VERSION 3.0) # setting this is required
project(dualec-attack)              # this sets the project name
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

file(GLOB_RECURSE sources     ../dualec-cpp/src/*.cpp  src/*.cpp)

add_executable(${PROJECT_NAME} ${sources})

target_compile_options(${PROJECT_NAME} PRIVATE -std=c++2a -O3 -Wall -Wextra -fdiagnostics-color=always
    #-ggdb
    #-DDEBUG
    #-DDEC_EXPORT_STRIPPED_BITS
    #-fsanitize=address,undefined,leak
-pedantic -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-include-dirs -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Wno-unused
)

target_link_options(${PROJECT_NAME} PRIVATE
    #-fsanitize=address,undefined,leak
)

target_include_directories(${PROJECT_NAME} PRIVATE ../dualec-cpp/src/include src)

target_link_libraries(${PROJECT_NAME} PRIVATE
  -lgivaro
  -lgmp
)
include(CPack)
