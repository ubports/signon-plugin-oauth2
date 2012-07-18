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
private_headers = oauth2plugin.h oauth2tokendata.h
HEADERS = $$public_headers \
    $$private_headers
SOURCES += oauth2plugin.cpp
PKGCONFIG += libsignon-qt \
    signon-plugins \
    QJson
headers.files = $$public_headers
pkgconfig.files = signon-oauth2plugin.pc
include( ../common-installs-config.pri )
