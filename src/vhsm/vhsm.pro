#-------------------------------------------------
#
# Project created by QtCreator 2013-06-27T07:05:41
#
#-------------------------------------------------

QT       -= core gui

TARGET = vhsm
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app

SOURCES += \
    vhsm.cpp \
    ../netlink_transport/VhsmMessageTransport.cpp \
    ../protocol/vhsm_transport.pb.cc \
    VhsmStorage.cpp \
    MessageHandler.cpp \
    vhsm_app.cpp

HEADERS += \
    vhsm.h \
    ../netlink_transport/VhsmMessageTransport.h \
    VhsmStorage.h \
    common.h \
    MessageHandler.h

INCLUDEPATH += ../netlink_transport/ \
            ../protocol/

LIBS += -lprotobuf -lcryptopp -lsqlite3
