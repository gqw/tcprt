cmake_minimum_required (VERSION 3.6)

project(tcprt)

if (WIN32)
	add_definitions(/std:c++17 /utf-8 -D_WIN32_WINNT=0x0601)
else()
	add_definitions(-g -O0 -Wall -std=c++17)
endif()


file(GLOB HEADER_FILES ./src/*.h ./src/*.hpp)
file(GLOB SOURCE_FILES ./src/*.cpp)

add_executable(${PROJECT_NAME} ${HEADER_FILES} ${SOURCE_FILES})
target_include_directories(${PROJECT_NAME} 
	PUBLIC ${CMAKE_SOURCE_DIR}/third/asio/include
	PUBLIC ${CMAKE_SOURCE_DIR}/third/spdlog/include)