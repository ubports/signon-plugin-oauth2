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
    link_pkgconfig
public_headers += oauth2data.h oauth1data.h
private_headers = \
    base-plugin.h \
    common.h \
    oauth1plugin.h \
    oauth2plugin.h \
    oauth2tokendata.h \
    plugin.h
HEADERS = $$public_headers \
    $$private_headers
SOURCES += \
    base-plugin.cpp \
    oauth1plugin.cpp \
    oauth2plugin.cpp \
    plugin.cpp
PKGCONFIG += \
    libsignon-qt5 \
    signon-plugins

headers.files = $$public_headers
pkgconfig.files = signon-oauth2plugin.pc
include( ../common-installs-config.pri )
