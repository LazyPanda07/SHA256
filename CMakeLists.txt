cmake_minimum_required(VERSION 3.27.0)

set(CMAKE_CXX_STANDARD 17)
option(BUILD_SHARED_LIBS "" OFF)

if (UNIX)
	add_definitions(-D__LINUX__)
endif (UNIX)

if (${BUILD_SHARED_LIBS})
	add_definitions(-DSHA256_DLL)
endif ()

project(SHA256 VERSION 1.7.1)

add_library(
	${PROJECT_NAME}
	src/SHA256.cpp
)

target_include_directories(
	${PROJECT_NAME} PUBLIC
	include
)

if (DEFINED ENV{MARCH} AND NOT "$ENV{MARCH}" STREQUAL "")
	target_compile_options(${PROJECT_NAME} PRIVATE -march=$ENV{MARCH})
endif()

install(
	TARGETS ${PROJECT_NAME}
	ARCHIVE DESTINATION lib
	LIBRARY DESTINATION lib
	RUNTIME DESTINATION dll
)

install(DIRECTORY include DESTINATION .)
