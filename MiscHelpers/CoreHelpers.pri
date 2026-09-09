# ----------------------------------------------------
# CoreHelpers - the half of the old MiscHelpers that draws nothing.
#
# QtCore and QtNetwork only. Kept in step with CMakeLists.txt and
# CoreHelpers.vcxproj by hand; a file added to one has to be added to all three.
#
# The old MiscHelpers.pri this replaces was a Visual Studio export that had
# fallen behind - it was missing Compat, MT/ThreadLock, NetworkAccessManager,
# ObjectTracker, OtherFunctions and the whole Archive subtree. This list is the
# one the other two build systems use.
# ------------------------------------------------------

HEADERS += ./corehelpers_global.h \
    ./stdafx.h \
    ./Common/Common.h \
    ./Common/Buffer.h \
    ./Common/Exception.h \
    ./Common/Strings.h \
    ./Common/Types.h \
    ./Common/Variant.h \
    ./Common/VariantDefs.h \
    ./Common/XVariant.h \
    ./Common/Compat.h \
    ./Common/DebugHelpers.h \
    ./Common/FlexError.h \
    ./Common/IPC/Discovery.h \
    ./Common/IPC/IPCServer.h \
    ./Common/IPC/IPCSocket.h \
    ./Common/IPC/VariantCache.h \
    ./Common/MT/ThreadLock.h \
    ./Common/NetworkAccessManager.h \
    ./Common/ObjectTracker.h \
    ./Common/OtherFunctions.h \
    ./Common/Crypto.h \
    ./Common/Settings.h \
    ./Common/Xml.h \
    ./Common/qRC4.h

SOURCES += ./stdafx.cpp \
    ./Common/Common.cpp \
    ./Common/Buffer.cpp \
    ./Common/Strings.cpp \
    ./Common/Variant.cpp \
    ./Common/XVariant.cpp \
    ./Common/Compat.cpp \
    ./Common/DebugHelpers.cpp \
    ./Common/IPC/Discovery.cpp \
    ./Common/IPC/IPCServer.cpp \
    ./Common/IPC/IPCSocket.cpp \
    ./Common/MT/ThreadLock.cpp \
    ./Common/NetworkAccessManager.cpp \
    ./Common/ObjectTracker.cpp \
    ./Common/OtherFunctions.cpp \
    ./Common/Crypto.cpp \
    ./Common/Settings.cpp \
    ./Common/Xml.cpp \
    ./Common/qRC4.cpp

#
# The 7-Zip wrapper. ArchiveHelper.cpp is a unity translation unit that
# #includes Archive.cpp, ArchiveExtractor.cpp, ArchiveInterface.cpp,
# ArchiveOpener.cpp and ArchiveUpdater.cpp, which is why those five are not
# listed. It is built on the Win32 COM shims in Archive/7z/CPP/Common and is
# Windows-only for now.
#
win32 {
    HEADERS += ./Archive/Archive.h \
        ./Archive/ArchiveExtractor.h \
        ./Archive/ArchiveFS.h \
        ./Archive/ArchiveHelper.h \
        ./Archive/ArchiveIO.h \
        ./Archive/ArchiveInterface.h \
        ./Archive/ArchiveOpener.h \
        ./Archive/ArchiveThread.h \
        ./Archive/ArchiveUpdater.h \
        ./Archive/CachedArchive.h \
        ./Archive/SplitFile.h

    SOURCES += ./Archive/ArchiveFS.cpp \
        ./Archive/ArchiveHelper.cpp \
        ./Archive/ArchiveThread.cpp \
        ./Archive/CachedArchive.cpp \
        ./Archive/SplitFile.cpp
}
