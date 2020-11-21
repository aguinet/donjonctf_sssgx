project(sss)
add_library(sss SHARED
  hazmat.cpp
  randombytes.cpp
  sss.cpp
  tweetnacl.cpp
)
add_executable(test test.cpp)
target_link_libraries(test PRIVATE sss)
