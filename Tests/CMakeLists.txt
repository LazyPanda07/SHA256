cmake_minimum_required(VERSION 3.27.0)

set(CMAKE_CXX_STANDARD 17)
set(DLL ${CMAKE_SOURCE_DIR}/../SHA256)
set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR})
set(GTEST_VERSION 1.17.0)

if (UNIX)
	set(DLL ${DLL}/lib/libSHA256.so)

	add_definitions(-D__LINUX__)
else ()
	set(DLL ${DLL}/dll/SHA256.dll)
endif (UNIX)

if (EXISTS ${DLL})
	add_definitions(-DSHA256_DLL)

	install(FILES ${DLL} DESTINATION ${CMAKE_BINARY_DIR}/bin)
endif ()

project(Tests)

include(FetchContent)

FetchContent_Declare(
	gtest
	GIT_REPOSITORY https://github.com/google/googletest.git
	GIT_TAG v${GTEST_VERSION}
)

FetchContent_MakeAvailable(gtest)

add_executable(
	${PROJECT_NAME}
	main.cpp
)

target_include_directories(
	${PROJECT_NAME} PUBLIC
	${CMAKE_SOURCE_DIR}/../include
)

target_link_directories(
	${PROJECT_NAME} PUBLIC
	${CMAKE_SOURCE_DIR}/../SHA256/lib
)

target_link_libraries(
	${PROJECT_NAME} PUBLIC
	SHA256
	gtest
	gtest_main
)

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
