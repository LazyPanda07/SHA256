cmake_minimum_required(VERSION 3.27.0)

set(CMAKE_CXX_STANDARD 17)
set(DLL ${CMAKE_SOURCE_DIR}/../SHA256)

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

find_package(GTest)

if(NOT ${GTest_FOUND})
	set(GTEST_BOTH_LIBRARIES gtest gtest_main)
	set(GTEST_INCLUDE_DIRS gtest/include/)
endif()

add_executable(
	${PROJECT_NAME}
	main.cpp
)

target_include_directories(
	${PROJECT_NAME} PUBLIC
	${CMAKE_SOURCE_DIR}/../src
	${GTEST_INCLUDE_DIRS}
)

target_link_directories(
	${PROJECT_NAME} PUBLIC
	${CMAKE_SOURCE_DIR}/../SHA256/lib
	gtest/lib
)

target_link_libraries(
	${PROJECT_NAME} PUBLIC
	SHA256
	${GTEST_BOTH_LIBRARIES}
)

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_BINARY_DIR}/bin)
