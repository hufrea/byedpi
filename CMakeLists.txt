cmake_minimum_required( VERSION 3.5 )

project( ByeDPI
	VERSION			12
	DESCRIPTION		"Local SOCKS proxy server to bypass DPI (Deep Packet Inspection)."
	HOMEPAGE_URL	"https://github.com/hufrea/byedpi"
	LANGUAGES		C
)

set( PROJECT_VENDOR "GitHub" )

set( CMAKE_RUNTIME_OUTPUT_DIRECTORY "$<CONFIG>" )

add_compile_options( -D_XOPEN_SOURCE=500 )

# Optimizations
add_compile_options( $<$<NOT:$<CONFIG:Debug>>:-O3> )
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
set( CPACK_VERBATIM_VARIABLES			ON )
set( CPACK_STRIP_FILES					ON )
set( CPACK_INCLUDE_TOPLEVEL_DIRECTORY	OFF )
set( CPACK_PACKAGE_NAME					${PROJECT_NAME} )
set( CPACK_PACKAGE_VENDOR				${PROJECT_VENDOR} )
set( CPACK_PACKAGE_DESCRIPTION_SUMMARY	${PROJECT_NAME} )
set( CPACK_PACKAGE_DESCRIPTION			${PROJECT_DESCRIPTION} )
set( CPACK_PACKAGE_INSTALL_DIRECTORY	${CPACK_PACKAGE_NAME} )
set( CPACK_PACKAGE_CONTACT				${PROJECT_VENDOR} )
include( GNUInstallDirs )

if( WIN32 )
	# NSIS package - https://sourceforge.net/projects/nsis/
	list( APPEND CPACK_GENERATOR NSIS )
	set( CPACK_NSIS_MENU_LINKS
		"readme.txt"			"Read Me"
		"byedpi.bat"			"Run standalone"
		"proxy_reset.bat"		"Proxy reset"
		"proxy_set.bat"			"Proxy setup"
		"service_delete.bat"	"Service delete"
		"service_install.bat"	"Service install and run"
		"service_restart.bat"	"Service restart"
	)
	set( CPACK_NSIS_EXTRA_PREINSTALL_COMMANDS	"ExecWait \"sc stop ${PROJECT_NAME}\"" )
	set( CPACK_NSIS_EXTRA_INSTALL_COMMANDS		"ExecWait \"$INSTDIR\\service_install.bat\"" )
	set( CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS	"ExecWait \"$INSTDIR\\service_delete.bat\"" )
	set( CMAKE_INSTALL_BINDIR . )
	set( CMAKE_INSTALL_DOCDIR . )
else()
	# Debian package
	list( APPEND CPACK_GENERATOR DEB )
endif()

# Zip package
list( APPEND CPACK_GENERATOR ZIP )

include( CPack )

install( TARGETS ciadpi
	RUNTIME
)

install( FILES
	readme.txt
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
