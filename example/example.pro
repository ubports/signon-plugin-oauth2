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

