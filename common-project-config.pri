#-----------------------------------------------------------------------------
# Common variables for all projects.
#-----------------------------------------------------------------------------


#-----------------------------------------------------------------------------
# Common configuration for all projects.
#-----------------------------------------------------------------------------

CONFIG         += link_pkgconfig
#MOC_DIR         = .moc
#OBJECTS_DIR     = .obj
RCC_DIR         = resources
UI_DIR          = ui
UI_HEADERS_DIR  = ui/include
UI_SOURCES_DIR  = ui/src

QMAKE_CXXFLAGS += -fno-exceptions \
    -fno-rtti
# we don't like warnings...
QMAKE_CXXFLAGS -= -Werror

BUILD_DIR = builddir
TOP_SRC_DIR     = $$PWD
TOP_BUILD_DIR   = $${TOP_SRC_DIR}/$${BUILD_DIR}

#DEFINES += QT_NO_DEBUG_OUTPUT
DEFINES += SIGNON_TRACE

# End of File

