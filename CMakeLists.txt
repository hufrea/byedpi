cmake_minimum_required( VERSION 3.5 )

# Read version number
file( STRINGS main.c MAIN_VERSION_LINE REGEX "#define[ \t]+VERSION[ \t]+" LIMIT_COUNT 1 )
string( REGEX MATCH "([0-9\.]+)" MAIN_VERSION "${MAIN_VERSION_LINE}" )
if( NOT MAIN_VERSION )
    message( FATAL_ERROR "Version not found!" )
endif()
# Prepend version by "0"
string( REGEX MATCHALL "([0-9]+)" MAIN_VERSION "${MAIN_VERSION}" )
list( LENGTH MAIN_VERSION _LENGTH )
if( ${_LENGTH} LESS 2 )
    list( APPEND MAIN_VERSION "0" )
endif()
list( LENGTH MAIN_VERSION _LENGTH )
if( ${_LENGTH} LESS 3 )
    list( PREPEND MAIN_VERSION "0" )
endif()
string( JOIN "." MAIN_VERSION ${MAIN_VERSION} )

# Extract Git revision order number, used as last part of version
find_package( Git )
set( GIT_REVISION "0" )
if( Git_FOUND )
    execute_process( COMMAND "${GIT_EXECUTABLE}" rev-list HEAD --count
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE GIT_REVISION
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

project( ByeDPI
    VERSION      "${MAIN_VERSION}.${GIT_REVISION}"
    DESCRIPTION  "Local SOCKS proxy server to bypass DPI (Deep Packet Inspection)."
    HOMEPAGE_URL "https://github.com/hufrea/byedpi"
    LANGUAGES    C
)

set( PROJECT_VENDOR "hufrea" )
set( PROJECT_COPYRIGHT "Copyright (c) 2024 hufrea" )

set( CMAKE_C_STANDARD 99 )

#add_compile_definitions( _XOPEN_SOURCE=500 )
add_compile_options( -Wall -Wno-unused )
# Optimizations
add_compile_options( $<$<NOT:$<CONFIG:Debug>>:-O2> )
# Link time optimizations
add_compile_options( $<$<NOT:$<CONFIG:Debug>>:-flto> )
# Strip debug symbols
add_link_options( $<$<NOT:$<CONFIG:Debug>>:-s> )

include_directories( . )

set( SOURCES
    packets.c
    main.c
    conev.c
    proxy.c
    desync.c
    mpool.c
    extend.c
)

if( WIN32 )
    list( APPEND SOURCES
        win_service.c
    )
    link_libraries(
        ws2_32
        mswsock
    )
endif()

add_executable( ciadpi ${SOURCES} )

# Installer
set( CPACK_VERBATIM_VARIABLES           ON )
set( CPACK_STRIP_FILES                  ON )
set( CPACK_INCLUDE_TOPLEVEL_DIRECTORY   OFF )
set( CPACK_PACKAGE_NAME                 "${PROJECT_NAME}" )
set( CPACK_PACKAGE_VENDOR               "${PROJECT_VENDOR}" )
set( CPACK_PACKAGE_DESCRIPTION_SUMMARY  "${PROJECT_NAME}" )
set( CPACK_PACKAGE_DESCRIPTION          "${PROJECT_DESCRIPTION}" )
set( CPACK_PACKAGE_INSTALL_DIRECTORY    "${PROJECT_NAME}" )
set( CPACK_PACKAGE_INSTALL_REGISTRY_KEY "${PROJECT_NAME}" )
set( CPACK_PACKAGE_CONTACT              "${PROJECT_VENDOR}" )
set( CPACK_PACKAGE_HOMEPAGE_URL         "${PROJECT_HOMEPAGE_URL}" )
set( CPACK_RESOURCE_FILE_LICENSE        "${CMAKE_SOURCE_DIR}/LICENSE" )
set( CPACK_RESOURCE_FILE_README         "${CMAKE_SOURCE_DIR}/README.md" )

if( WIN32 )
    # NSIS package - https://sourceforge.net/projects/nsis/
    list( APPEND CPACK_GENERATOR NSIS )
    set( CPACK_NSIS_MENU_LINKS
        "README.md"           "Read Me"
        "byedpi.bat"          "Run standalone"
        "proxy_reset.bat"     "Proxy reset"
        "proxy_set.bat"       "Proxy setup"
        "service_delete.bat"  "Service delete"
        "service_install.bat" "Service install and run"
        "service_restart.bat" "Service restart"
    )

    file( WRITE  "${CMAKE_BINARY_DIR}/ver.nsi" "VIProductVersion ${MAIN_VERSION}.0\n" )
    file( APPEND "${CMAKE_BINARY_DIR}/ver.nsi" "VIFileVersion ${PROJECT_VERSION}\n" )
    file( APPEND "${CMAKE_BINARY_DIR}/ver.nsi" "VIAddVersionKey /LANG=0 \"ProductVersion\" \"${MAIN_VERSION}.0\"\n" )
    file( APPEND "${CMAKE_BINARY_DIR}/ver.nsi" "VIAddVersionKey /LANG=0 \"FileVersion\" \"${PROJECT_VERSION}\"\n" )
    file( APPEND "${CMAKE_BINARY_DIR}/ver.nsi" "VIAddVersionKey /LANG=0 \"ProductName\" \"${PROJECT_NAME}\"\n" )
    file( APPEND "${CMAKE_BINARY_DIR}/ver.nsi" "VIAddVersionKey /LANG=0 \"FileDescription\" \"${PROJECT_DESCRIPTION}\"\n" )
    file( APPEND "${CMAKE_BINARY_DIR}/ver.nsi" "VIAddVersionKey /LANG=0 \"CompanyName\" \"${PROJECT_VENDOR}\"\n" )
    file( APPEND "${CMAKE_BINARY_DIR}/ver.nsi" "VIAddVersionKey /LANG=0 \"LegalCopyright\" \"${PROJECT_COPYRIGHT}\"\n" )
    set( CPACK_NSIS_EXECUTABLE_PRE_ARGUMENTS  "V0 ${CMAKE_BINARY_DIR}/ver.nsi" )

    set( CPACK_NSIS_EXTRA_PREINSTALL_COMMANDS "ExecWait \"sc stop ${PROJECT_NAME}\"" )
    set( CPACK_NSIS_EXTRA_INSTALL_COMMANDS    "ExecWait \"$INSTDIR\\service_install.bat\"" )
    set( CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS  "ExecWait \"$INSTDIR\\service_delete.bat\"" )
    set( CPACK_NSIS_CONTACT                   "${PROJECT_VENDOR}" )
    set( CPACK_NSIS_HELP_LINK                 "${PROJECT_HOMEPAGE_URL}" )
    set( CPACK_NSIS_URL_INFO_ABOUT            "${PROJECT_HOMEPAGE_URL}" )
    set( CPACK_NSIS_BRANDING_TEXT             " " )
    set( CPACK_NSIS_COMPRESSOR                "/SOLID lzma" )

    set( CMAKE_INSTALL_BINDIR . )
    set( CMAKE_INSTALL_DOCDIR . )
else()
    # Debian package
    list( APPEND CPACK_GENERATOR DEB )
endif()

# Zip package
list( APPEND CPACK_GENERATOR ZIP )

install( TARGETS ciadpi
    RUNTIME
)

install( FILES
    README.md
    TYPE DOC
)

if( WIN32 )
    install( FILES
        dist/windows/byedpi.bat
        dist/windows/proxy_reset.bat
        dist/windows/proxy_set.bat
        dist/windows/service_delete.bat
        dist/windows/service_install.bat
        dist/windows/service_restart.bat
        TYPE BIN
    )
endif()

include( GNUInstallDirs )
include( CPack )
