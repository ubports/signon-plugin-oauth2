include( ../common-project-config.pri )
include( ../common-vars.pri )
TEMPLATE = lib
TARGET = oauth2plugin
DESTDIR = lib/signon
QT += core \
    network \
    xmlpatterns
QT -= gui
CONFIG += plugin \
    build_all \
    warn_on \
    link_pkgconfig \
    signon-plugins
public_headers += oauth2data.h oauth1data.h
private_headers = oauth2plugin.h oauth2tokendata.h
HEADERS = $$public_headers \
    $$private_headers
SOURCES += oauth2plugin.cpp
PKGCONFIG += libsignon-qt \
    QJson
headers.files = $$public_headers
include( ../common-installs-config.pri )
target.path = $${INSTALL_PREFIX}/lib/signon
INSTALLS = target
headers.path = $${INSTALL_PREFIX}/include/signon-plugins
INSTALLS += headers
pkgconfig.files = signon-oauth2plugin.pc
pkgconfig.path = $${INSTALL_PREFIX}/lib/pkgconfig
INSTALLS += pkgconfig
