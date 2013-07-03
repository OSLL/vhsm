#-------------------------------------------------
#
# Project created by QtCreator 2013-06-27T08:18:05
#
#-------------------------------------------------

QT       -= core gui

TARGET = vhsm_api_prototype_impl
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app


SOURCES += \
    transport_impl.cpp \
    key_mgmt_impl.c

INCLUDEPATH += ../../netlink_transport \
        ../

HEADERS += \
    transport.h
