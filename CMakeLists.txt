cmake_minimum_required (VERSION 3.7)
project (libplum
	VERSION 0.1.3
	LANGUAGES C)
set(PROJECT_DESCRIPTION "Multi-protocol Port Mapping client library")

option(NO_EXAMPLE "Disable example build" OFF)
option(NO_EXPORT_HEADER "Disable export header" OFF)
option(WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)

set(C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(WIN32)
	add_definitions(-DWIN32_LEAN_AND_MEAN)
	if (MSVC)
		add_definitions(-DNOMINMAX)
		add_definitions(-D_CRT_SECURE_NO_WARNINGS)
	endif()
endif()

set(LIBPLUM_SOURCES
	${CMAKE_CURRENT_SOURCE_DIR}/src/addr.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/client.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/dummytls.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/http.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/log.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/natpmp.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/net.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/noprotocol.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/pcp.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/plum.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/random.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/tcp.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/timestamp.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/udp.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/upnp.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/util.c
)

set(LIBPLUM_HEADERS
	${CMAKE_CURRENT_SOURCE_DIR}/include/plum/plum.h
)

set(EXAMPLE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/example/main.c
)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_library(plum SHARED ${LIBPLUM_SOURCES})
set_target_properties(plum PROPERTIES VERSION ${PROJECT_VERSION})
target_include_directories(plum PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_include_directories(plum PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/plum)
target_include_directories(plum PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(plum PRIVATE $<$<CONFIG:Release>:RELEASE=1>)
target_link_libraries(plum PRIVATE Threads::Threads)

add_library(plum-static STATIC EXCLUDE_FROM_ALL ${LIBPLUM_SOURCES})
set_target_properties(plum-static PROPERTIES VERSION ${PROJECT_VERSION})
target_include_directories(plum-static PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_include_directories(plum-static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/plum)
target_include_directories(plum-static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(plum-static PRIVATE $<$<CONFIG:Release>:RELEASE=1>)
target_link_libraries(plum-static PRIVATE Threads::Threads)

if(WIN32)
	target_link_libraries(plum PRIVATE
		ws2_32 # winsock2
		iphlpapi
		bcrypt)
	target_link_libraries(plum-static PRIVATE
		ws2_32 # winsock2
		iphlpapi
		bcrypt)
endif()

set_target_properties(plum PROPERTIES EXPORT_NAME LibPlum)
add_library(LibPlum::LibPlum ALIAS plum)

set_target_properties(plum-static PROPERTIES EXPORT_NAME LibPlumStatic)
add_library(LibPlum::LibPlumStatic ALIAS plum-static)

install(TARGETS plum EXPORT LibPlumTargets
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
)

install(FILES ${LIBPLUM_HEADERS} DESTINATION include/plum)

# Export Targets
install(
	EXPORT LibPlumTargets
	FILE LibPlumTargets.cmake
	NAMESPACE LibPlum::
	DESTINATION lib/cmake/LibPlum
)

# Export config
install(
    FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/LibPlumConfig.cmake
    DESTINATION lib/cmake/LibPlum
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_BINARY_DIR}/LibPlumConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_BINARY_DIR}/LibPlumConfigVersion.cmake
    DESTINATION lib/cmake/LibPlum)

if(NOT NO_EXPORT_HEADER AND CMAKE_VERSION VERSION_GREATER_EQUAL "3.12")
	include(GenerateExportHeader)
	generate_export_header(plum
		EXPORT_MACRO_NAME PLUM_EXPORT
		NO_EXPORT_MACRO_NAME PLUM_NO_EXPORT
		DEPRECATED_MACRO_NAME PLUM_DEPRECATED
		STATIC_DEFINE PLUM_STATIC)
	target_include_directories(plum PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)
	target_compile_definitions(plum PUBLIC -DPLUM_HAS_EXPORT_HEADER)
	set_target_properties(plum PROPERTIES C_VISIBILITY_PRESET hidden)
	install(FILES ${PROJECT_BINARY_DIR}/plum_export.h DESTINATION include/plum)
else()
	target_compile_definitions(plum PRIVATE PLUM_EXPORTS)
	target_compile_definitions(plum-static PRIVATE PLUM_EXPORTS)
endif()

if(NOT MSVC)
	target_compile_options(plum PRIVATE -Wall -Wextra)
	target_compile_options(plum-static PRIVATE -Wall -Wextra)
endif()

if(WARNINGS_AS_ERRORS)
	if(MSVC)
		target_compile_options(plum PRIVATE /WX)
		target_compile_options(plum-static PRIVATE /WX)
	else()
		target_compile_options(plum PRIVATE -Werror)
		target_compile_options(plum-static PRIVATE -Werror)
	endif()
endif()

# Example
if(NOT NO_EXAMPLE)
	add_executable(plum-example ${EXAMPLE_SOURCES})
	target_include_directories(plum-example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/plum)

	set_target_properties(plum-example PROPERTIES
		VERSION ${PROJECT_VERSION}
		OUTPUT_NAME example)

	set_target_properties(plum-example PROPERTIES
		XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER com.github.paullouisageneau.libplum.example)

	target_link_libraries(plum-example plum Threads::Threads)
endif()

