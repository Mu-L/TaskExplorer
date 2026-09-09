
TEMPLATE = lib
TARGET = CoreHelpers
#
# No widgets. That is the whole point of the split: this library is what
# TaskCore links, and a collector draws nothing. stdafx.h keeps its QtWidgets
# block behind TE_WITH_WIDGETS, which this target does not define, so it cannot
# reach a widget header even by accident.
#
# Assignment, not +=: qmake starts from "core gui", and the CMake target
# links Core and Network only. Leaving gui in would put QtGui back on this
# library after all the trouble taken to get it off.
QT = core network core-private
#CONFIG += debug
DEFINES += COREHELPERS_LIB
#LIBS += -L"."
PRECOMPILED_HEADER = stdafx.h
#DEPENDPATH += .
#MOC_DIR += ./GeneratedFiles/$(ConfigurationName)
#OBJECTS_DIR += debug
#UI_DIR += ./GeneratedFiles
#RCC_DIR += ./GeneratedFiles

MY_ARCH=$$(build_arch)
equals(MY_ARCH, ARM64) {
#  message("Building ARM64")
  CONFIG(debug, debug|release):LIBS = -L../../Bin/ARM64/Debug
  CONFIG(release, debug|release):LIBS = -L../../Bin/ARM64/Release
} else:equals(MY_ARCH, x64) {
#  message("Building x64")
  CONFIG(debug, debug|release):LIBS += -L../../Bin/x64/Debug
  CONFIG(release, debug|release):LIBS += -L../../Bin/x64/Release
} else {
#  message("Building x86")
  CONFIG(debug, debug|release):LIBS = -L../../Bin/Win32/Debug
  CONFIG(release, debug|release):LIBS = -L../../Bin/Win32/Release
}

# No qextwidgets here - that is a widget library and only GuiHelpers needs it.
# These three are for the 7-Zip wrapper and the console helper in Common.cpp.
win32:LIBS += -lUser32 -lShell32 -lOleAut32

!mac:unix:QMAKE_LFLAGS += -Wl,-rpath,'\$\$ORIGIN'
mac:QMAKE_CXXFLAGS += -std=c++11 -w

!win32:QMAKE_LFLAGS +=-rdynamic

CONFIG(release, debug|release):{
QMAKE_CXXFLAGS_RELEASE = $$QMAKE_CFLAGS_RELEASE_WITH_DEBUGINFO
QMAKE_LFLAGS_RELEASE = $$QMAKE_LFLAGS_RELEASE_WITH_DEBUGINFO
}

MY_ARCH=$$(build_arch)
equals(MY_ARCH, ARM64) {
#  message("Building ARM64")
  CONFIG(debug, debug|release):DESTDIR = ../../Bin/ARM64/Debug
  CONFIG(release, debug|release):DESTDIR = ../../Bin/ARM64/Release
} else:equals(MY_ARCH, x64) {
#  message("Building x64")
  CONFIG(debug, debug|release):DESTDIR = ../../Bin/x64/Debug
  CONFIG(release, debug|release):DESTDIR = ../../Bin/x64/Release
} else {
#  message("Building x86")
  CONFIG(debug, debug|release):DESTDIR = ../../Bin/Win32/Debug
  CONFIG(release, debug|release):DESTDIR = ../../Bin/Win32/Release
}

INCLUDEPATH += .
DEPENDPATH += .
#MOC_DIR += ./GeneratedFiles
#OBJECTS_DIR += ./ObjectFiles
#UI_DIR += ./GeneratedFiles
#RCC_DIR += ./GeneratedFiles


include(CoreHelpers.pri)
