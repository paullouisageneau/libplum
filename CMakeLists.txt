cmake_minimum_required (VERSION 3.7)
project (libplum
	VERSION 0.1.0
	LANGUAGES C)
set(PROJECT_DESCRIPTION "PLUM Port Lightweight and Universal Mapping")

option(NO_EXAMPLE "Disable example build" OFF)
option(NO_EXPORT_HEADER "Disable export header" OFF)
option(WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)

set(C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/Modules)

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
	${CMAKE_CURRENT_SOURCE_DIR}/src/http.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/log.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/natpmp.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/net.c
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

if (USE_NETTLE)
	find_package(Nettle REQUIRED)
    target_compile_definitions(plum PRIVATE USE_NETTLE=1)
    target_link_libraries(plum PRIVATE Nettle::Nettle)
    target_compile_definitions(plum-static PRIVATE USE_NETTLE=1)
    target_link_libraries(plum-static PRIVATE Nettle::Nettle)
else()
    target_compile_definitions(plum PRIVATE USE_NETTLE=0)
    target_compile_definitions(plum-static PRIVATE USE_NETTLE=0)
endif()

if (NO_SERVER)
	target_compile_definitions(plum PRIVATE NO_SERVER)
	target_compile_definitions(plum-static PRIVATE NO_SERVER)
endif()

if(APPLE)
	# This seems to be necessary on MacOS
	target_include_directories(plum PRIVATE /usr/local/include)
	target_include_directories(plum-static PRIVATE /usr/local/include)
endif()

set_target_properties(plum PROPERTIES EXPORT_NAME LibJuice)
add_library(LibJuice::LibJuice ALIAS plum)

set_target_properties(plum-static PROPERTIES EXPORT_NAME LibJuiceStatic)
add_library(LibJuice::LibJuiceStatic ALIAS plum-static)

install(TARGETS plum EXPORT LibJuiceTargets
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
)

install(FILES ${LIBPLUM_HEADERS} DESTINATION include/plum)

# Export Targets
install(
	EXPORT LibJuiceTargets
	FILE LibJuiceTargets.cmake
	NAMESPACE LibJuice::
	DESTINATION lib/cmake/LibJuice
)

# Export config
install(
        FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/LibJuiceConfig.cmake
        DESTINATION lib/cmake/LibJuice
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_BINARY_DIR}/LibJuiceConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_BINARY_DIR}/LibJuiceConfigVersion.cmake
    DESTINATION lib/cmake/LibJuice)

if(NOT NO_EXPORT_HEADER AND CMAKE_VERSION VERSION_GREATER_EQUAL "3.12")
	include(GenerateExportHeader)
	generate_export_header(plum)
	target_include_directories(plum PUBLIC $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}>)
	target_compile_definitions(plum PUBLIC -DPLUM_HAS_EXPORT_HEADER)
	set_target_properties(plum PROPERTIES C_VISIBILITY_PRESET hidden)
	install(FILES ${PROJECT_BINARY_DIR}/plum_export.h DESTINATION include/plum)
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

# Tests
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

