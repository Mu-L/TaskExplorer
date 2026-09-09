# ----------------------------------------------------
# The Visual Studio flavour of CoreHelpers.qc.pro: one fixed configuration,
# used when opening the project in Qt Creator rather than driving it from
# Build/buildRelease.cmd.
# ------------------------------------------------------

TEMPLATE = lib
TARGET = CoreHelpers
DESTDIR = ../x64/Debug
CONFIG += debug
QT = core network core-private
DEFINES += COREHELPERS_LIB
LIBS += -L"."
PRECOMPILED_HEADER = stdafx.h
DEPENDPATH += .
MOC_DIR += ./GeneratedFiles/$(ConfigurationName)
OBJECTS_DIR += debug
UI_DIR += ./GeneratedFiles
RCC_DIR += ./GeneratedFiles
include(CoreHelpers.pri)
