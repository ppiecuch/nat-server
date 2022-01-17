cmake_minimum_required (VERSION 3.11)
project(NATServer LANGUAGES C CXX)

include(FetchContent)


FetchContent_Declare(
  slikenet
  GIT_REPOSITORY https://github.com/SLikeSoft/SLikeNet
  GIT_TAG master
  GIT_SHALLOW TRUE)

FetchContent_GetProperties(slikenet)
if(NOT slikenet_POPULATED)
  FetchContent_Populate(slikenet)
  SET(SLIKENET_ENABLE_STATIC ON)
  SEt(SLIKENET_ENABLE_DLL OFF)
  SET(SLIKENET_ENABLE_SAMPLES OFF)
  SET(OPENSSL_ROOT_DIR /usr/local/ssl)
  SET(CMAKE_HOME_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
  add_subdirectory(
    ${slikenet_SOURCE_DIR}
    ${slikenet_BINARY_DIR}
    EXCLUDE_FROM_ALL)
  include_directories(${slikenet_SOURCE_DIR}/Source/include)
  include_directories(${slikenet_BINARY_DIR}/include)
endif()


# Include source files and the generated files
include_directories(${CMAKE_CURRENT_BINARY_DIR}/NATServer)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/NATServer)


execute_process(
  COMMAND
    git rev-parse --verify HEAD
  WORKING_DIRECTORY
    ${slikenet_SOURCE_DIR}
  OUTPUT_VARIABLE
    slikenet_git
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

add_definitions(-DSLIKENET_GIT="${slikenet_git}")

add_executable(natserver
    NATServer/main.cpp
    NATServer/CloudServerHelper.cpp
)
target_link_libraries(natserver PRIVATE SLikeNetLibStatic)
