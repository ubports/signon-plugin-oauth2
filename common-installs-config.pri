#-----------------------------------------------------------------------------
# Installation configuration for all SSO plugins
#-----------------------------------------------------------------------------

#-----------------------------------------------------------------------------
# default installation target for applications
#-----------------------------------------------------------------------------
contains( TEMPLATE, app ) {
    target.path  = $${INSTALL_PREFIX}/bin
    INSTALLS    += target
    message("====")
    message("==== INSTALLS += target")
}

#-----------------------------------------------------------------------------
# default installation target for libraries
#-----------------------------------------------------------------------------
contains( TEMPLATE, lib ) {
    target.path  = $${SIGNON_PLUGINS_DIR}
    INSTALLS    += target
    message("====")
    message("==== INSTALLS += target")
}

#-----------------------------------------------------------------------------
# target for header files
#-----------------------------------------------------------------------------
!isEmpty( headers.files ) {
    headers.path  = $${INSTALL_PREFIX}/include/signon-plugins
    INSTALLS     += headers
    message("====")
    message("==== INSTALLS += headers")
} else {
    message("====")
    message("==== NOTE: Remember to add your plugin headers into `headers.files' for installation!")
}

#-----------------------------------------------------------------------------
# target for header files
#-----------------------------------------------------------------------------
!isEmpty( pkgconfig.files ) {
    pkgconfig.path  = $${INSTALL_LIBDIR}/pkgconfig
    INSTALLS       += pkgconfig
    message("====")
    message("==== INSTALLS += pkgconfig")
} else {
    message("====")
    message("==== NOTE: Remember to add your pkgconfig into `pkgconfig.files' for installation!")
}

# End of File
