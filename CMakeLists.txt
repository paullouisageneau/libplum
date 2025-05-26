cmake_minimum_required(VERSION 3.7...4.0)
project (libplum
	VERSION 0.5.1
	LANGUAGES C)
set(PROJECT_DESCRIPTION "Multi-protocol Port Mapping client library")

option(PLUM_NO_EXAMPLE "Disable example build" OFF)
option(PLUM_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

if(MSVC)
	option(PLUM_STATIC_RUNTIME "Build with static runtime library." OFF)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(GNUInstallDirs)

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

add_library(plum ${LIBPLUM_SOURCES})
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
add_library(LibPlum::LibPlumStatic ALIAS plum-static)

install(TARGETS plum EXPORT LibPlumTargets
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Don't install `plum-static` target, since it may not always be
# available in the build tree (i.e. marked with `EXCLUDE_FROM_ALL`).
# CMake doesn't support installing targets with `EXCLUDE_FROM_ALL` set.

install(FILES ${LIBPLUM_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/plum)

# Export Targets
install(
	EXPORT LibPlumTargets
	FILE LibPlumTargets.cmake
	NAMESPACE LibPlum::
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LibPlum
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/LibPlumConfig.cmake.in
    ${CMAKE_BINARY_DIR}/LibPlumConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LibPlum
    NO_SET_AND_CHECK_MACRO
    NO_CHECK_REQUIRED_COMPONENTS_MACRO
)
write_basic_package_version_file(
    ${CMAKE_BINARY_DIR}/LibPlumConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
# Export config and version files
install(FILES
    ${CMAKE_BINARY_DIR}/LibPlumConfig.cmake
    ${CMAKE_BINARY_DIR}/LibPlumConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LibPlum
)

set_target_properties(plum PROPERTIES C_VISIBILITY_PRESET hidden)
target_compile_definitions(plum PRIVATE PLUM_EXPORTS)
if (NOT BUILD_SHARED_LIBS)
	target_compile_definitions(plum PUBLIC PLUM_STATIC)
endif()
target_compile_definitions(plum-static PRIVATE PLUM_EXPORTS PUBLIC PLUM_STATIC)

if(MSVC)
	if(PLUM_STATIC_RUNTIME)
		# Set compiler options.
		set(variables
			CMAKE_C_FLAGS_DEBUG
			CMAKE_C_FLAGS_MINSIZEREL
			CMAKE_C_FLAGS_RELEASE
			CMAKE_C_FLAGS_RELWITHDEBINFO
		)
		# Replace the RuntimeLibrary option with the static alternative (not DLL) via the compiler options.
		foreach(variable ${variables})
			if(${variable} MATCHES "/MD")
				string(REGEX REPLACE "/MD" "/MT" ${variable} "${${variable}}")
			endif()
		endforeach()
	endif()
else()
	target_compile_options(plum PRIVATE -Wall -Wextra)
	target_compile_options(plum-static PRIVATE -Wall -Wextra)
endif()

if(PLUM_WARNINGS_AS_ERRORS)
	if(MSVC)
		target_compile_options(plum PRIVATE /WX)
		target_compile_options(plum-static PRIVATE /WX)
	else()
		target_compile_options(plum PRIVATE -Werror)
		target_compile_options(plum-static PRIVATE -Werror)
	endif()
endif()

# Example
if(NOT PLUM_NO_EXAMPLE)
	add_executable(plum-example ${EXAMPLE_SOURCES})
	target_include_directories(plum-example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/plum)

	set_target_properties(plum-example PROPERTIES
		VERSION ${PROJECT_VERSION}
		OUTPUT_NAME example)

	set_target_properties(plum-example PROPERTIES
		XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER com.github.paullouisageneau.libplum.example)

	target_link_libraries(plum-example plum Threads::Threads)
endif()

