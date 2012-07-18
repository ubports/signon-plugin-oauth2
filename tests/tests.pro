include( ../common-project-config.pri )
include( ../common-vars.pri )
TARGET = signon-oauth2plugin-tests
QT += core \
    network
CONFIG += qtestlib \
    link_pkgconfig
SOURCES += oauth2plugintest.cpp
HEADERS += oauth2plugintest.h \
    $${TOP_SRC_DIR}/src/oauth2plugin.h \
    $${TOP_SRC_DIR}/src/oauth2plugin.cpp \
    $${TOP_SRC_DIR}/src/oauth2data.h
INCLUDEPATH += . \
    $${TOP_SRC_DIR}/src \
    /usr/include/signon-qt
PKGCONFIG += libsignon-qt \
    signon-plugins \
    QJson
target.path = /usr/bin
testsuite.path = /usr/share/$$TARGET
testsuite.files = tests.xml
INSTALLS += target \
    testsuite

check.depends = $$TARGET
check.commands = ./$$TARGET || :
QMAKE_EXTRA_TARGETS += check

QMAKE_CLEAN += $$TARGET

