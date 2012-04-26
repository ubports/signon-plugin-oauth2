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

TOP_SRC_DIR     = $$PWD

#DEFINES += QT_NO_DEBUG_OUTPUT
DEFINES += SIGNON_TRACE

#-----------------------------------------------------------------------------
# setup the installation prefix
#-----------------------------------------------------------------------------
INSTALL_PREFIX = /usr  # default installation prefix

# default prefix can be overriden by defining PREFIX when running qmake
isEmpty( PREFIX ) {
    message("====")
    message("==== NOTE: To override the installation path run: `qmake PREFIX=/custom/path'")
    message("==== (current installation path is `$${INSTALL_PREFIX}')")
} else {
    INSTALL_PREFIX = $${PREFIX}
    message("====")
    message("==== install prefix set to `$${INSTALL_PREFIX}'")
}

# Setup the library installation directory
exists( meego-release ) {
    ARCH = $$system(tail -n1 meego-release)
} else {
    ARCH = $$system(uname -m)
}

contains( ARCH, x86_64 ) {
    INSTALL_LIBDIR = $${INSTALL_PREFIX}/lib64
} else {
    INSTALL_LIBDIR = $${INSTALL_PREFIX}/lib
}

# default library directory can be overriden by defining LIBDIR when
# running qmake
isEmpty( LIBDIR ) {
    message("====")
    message("==== NOTE: To override the library installation path run: `qmake LIBDIR=/custom/path'")
    message("==== (current installation path is `$${INSTALL_LIBDIR}')")
} else {
    INSTALL_LIBDIR = $${LIBDIR}
    message("====")
    message("==== library install path set to `$${INSTALL_LIBDIR}'")
}

# Default directory for signond extensions
_PLUGINS = $$system(pkg-config --variable=plugindir signon-plugins)
isEmpty(_PLUGINS) {
    error("plugin directory not available through pkg-config")
} else {
    SIGNON_PLUGINS_DIR = $$_PLUGINS
}
SIGNON_PLUGINS_DIR_QUOTED = \\\"$$SIGNON_PLUGINS_DIR\\\"
