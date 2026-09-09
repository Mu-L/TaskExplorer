# ----------------------------------------------------
# The Visual Studio flavour of GuiHelpers.qc.pro: one fixed configuration,
# used when opening the project in Qt Creator rather than driving it from
# Build/buildRelease.cmd.
# ------------------------------------------------------

TEMPLATE = lib
TARGET = GuiHelpers
DESTDIR = ../x64/Debug
CONFIG += debug
QT += core network widgets
DEFINES += GUIHELPERS_LIB TE_WITH_WIDGETS
LIBS += -L"." \
    -L../x64/Debug -lCoreHelpers -lqextwidgets
PRECOMPILED_HEADER = stdafx.h
DEPENDPATH += .
MOC_DIR += ./GeneratedFiles/$(ConfigurationName)
OBJECTS_DIR += debug
UI_DIR += ./GeneratedFiles
RCC_DIR += ./GeneratedFiles
include(GuiHelpers.pri)
