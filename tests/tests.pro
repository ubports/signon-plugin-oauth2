include( ../common-project-config.pri )
include( ../common-vars.pri )
TARGET = signon-oauth2plugin-tests
QT += core \
    network \
    testlib
QT -= gui

DEFINES -= SIGNON_TRACE
CONFIG += \
    link_pkgconfig
SOURCES += \
    $${TOP_SRC_DIR}/src/base-plugin.cpp \
    $${TOP_SRC_DIR}/src/oauth2plugin.cpp \
    $${TOP_SRC_DIR}/src/oauth1plugin.cpp \
    $${TOP_SRC_DIR}/src/plugin.cpp \
    oauth2plugintest.cpp
HEADERS += \
    $${TOP_SRC_DIR}/src/base-plugin.h \
    $${TOP_SRC_DIR}/src/oauth2plugin.h \
    $${TOP_SRC_DIR}/src/oauth1plugin.h \
    $${TOP_SRC_DIR}/src/plugin.h \
    oauth2plugintest.h
INCLUDEPATH += . \
    $${TOP_SRC_DIR}/src \
    /usr/include/signon-qt
PKGCONFIG += \
    signon-plugins

lessThan(QT_MAJOR_VERSION, 5) {
    PKGCONFIG += \
        QJson \
        libsignon-qt
} else {
    PKGCONFIG += \
        libsignon-qt5
}

target.path = /usr/bin
testsuite.path = /usr/share/$$TARGET
testsuite.files = tests.xml
INSTALLS += target \
    testsuite

check.depends = $$TARGET
check.commands = ./$$TARGET || :
QMAKE_EXTRA_TARGETS += check

QMAKE_CLEAN += $$TARGET

