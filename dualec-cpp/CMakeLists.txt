cmake_minimum_required(VERSION 3.0) # setting this is required
project(dualec)            # this sets the project name

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

###############################################################################
## file globbing ##############################################################
###############################################################################

#These instructions search the directory tree when cmake is
#invoked and put all files that match the pattern in the variables
# `sources` and `data`.
file(GLOB_RECURSE sources      src/*.cpp)
# use globbing to find files automatically.

###############################################################################
## target definitions #########################################################
###############################################################################

# The data is just added to the executable, because in some IDEs (QtCreator)
# files are invisible when they are not explicitly part of the project.
add_executable(dualec ${sources})# ${data})

# Just for example add some compiler flags.
target_compile_options(dualec PUBLIC -std=c++2a -O3 -Wall -Wextra -fdiagnostics-color=always
    #-ggdb
    #-DDEBUG
    #-fsanitize=address,undefined,leak
-pedantic -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-include-dirs -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Wno-unused
)

target_link_options(dualec PUBLIC
    #-fsanitize=address,undefined,leak
)

# This allows to include files relative to the root of the src directory with a <> pair
target_include_directories(dualec PUBLIC src/include)

# This copies all resource files in the build directory.
# We need this, because we want to work with paths relative to the executable.
# file(COPY ${data} DESTINATION resources)

###############################################################################
## dependencies ###############################################################
###############################################################################

# This defines the variables Boost_LIBRARIES that contains all library names
# that we need to link into the program.
# find_package(Boost 1.36.0 COMPONENTS filesystem system REQUIRED)

target_link_libraries(dualec PUBLIC
  # ${Boost_LIBRARIES}
  # here you can add any library dependencies
  -lgivaro
  -lgmp
)

###############################################################################
## packaging ##################################################################
###############################################################################

# All install commands get the same destination. This allows us to use paths
# relative to the executable.
install(TARGETS dualec DESTINATION example_destination)

# Now comes everything we need, to create a package
# there are a lot more variables you can set, and some
# you need to set for some package types, but we want to
# be minimal here.
set(CPACK_PACKAGE_NAME "DualEC_PackageName")
set(CPACK_PACKAGE_VERSION "1.0.0")

# We don't want to split our program up into several incomplete pieces.
set(CPACK_MONOLITHIC_INSTALL 1)

# This must be last
include(CPack)
