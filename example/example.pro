include( ../common-project-config.pri )
include( ../common-vars.pri )

TEMPLATE = app
TARGET = oauthclient
INCLUDEPATH += . \
    $$TOP_SRC_DIR/src/

CONFIG += \
    debug \
    link_pkgconfig

PKGCONFIG += libsignon-qt

HEADERS += \
    oauthclient.h
SOURCES += \
    main.cpp \
    oauthclient.cpp

# install
include( ../common-installs-config.pri )

signon-ui.files = \
    m.facebook.com.conf \
    www.facebook.com.conf
signon-ui.path = /etc/signon-ui/webkit-options.d/
INSTALLS += signon-ui

