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
    MessageHandler.cpp \
    ../netlink_transport/VhsmMessageTransport.cpp \
    ../protocol/vhsm_transport.pb.cc \
    EncryptedStorageFactory.cpp \
    esapi_file_impl/FSESNamespace.cpp \
    esapi_file_impl/FSEncryptedStorage.cpp \
    esapi_file_impl/ESCypher.cpp \
    VhsmStorage.cpp

HEADERS += \
    vhsm.h \
    ../netlink_transport/VhsmMessageTransport.h \
    EncryptedStorageFactory.h \
    esapi_file_impl/FsUtil.h \
    esapi_file_impl/FSESNamespace.h \
    esapi_file_impl/FSEncryptedStorage.h \
    esapi_file_impl/ESCypher.h \
    VhsmStorage.h \
    common.h

INCLUDEPATH += ../netlink_transport/ \
            ../protocol/ \
            ./esapi/

LIBS += -lprotobuf -lcryptopp -lsqlite3
