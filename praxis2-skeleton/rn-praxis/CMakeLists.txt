cmake_minimum_required (VERSION 3.5)
project (RN-Praxis)
set (CMAKE_C_STANDARD 11)

add_executable (webserver executables/webserver.c executables/http.c executables/util.c executables/data.c)
target_compile_options (webserver PRIVATE -Wall -Wextra -Wpedantic)
# target_link_libraries(webserver PRIVATE -lm)

target_include_directories(webserver PRIVATE executable)

#include OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(webserver PRIVATE ${OPENSSL_LIBRARIES} -lm)

# Packaging
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES
  ${CMAKE_BINARY_DIR}
  /\\..*$
)
set(CPACK_VERBATIM_VARIABLES YES)
include(CPack)
