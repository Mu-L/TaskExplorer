#
# CoreHelpers and GuiHelpers - what used to be one MiscHelpers library.
#
# The split is not cosmetic. A library's dependencies land on its consumers'
# link lines, so while the widgets and the settings reader lived in one target,
# libTaskCore.so recorded DT_NEEDED for libQt6Widgets and libQt6Gui despite
# referencing zero symbols from either. -Wl,--as-needed did not clear it; only
# separating the two halves does.
#
#   CoreHelpers - QtCore and QtNetwork. Settings, Xml, the formatting helpers,
#                 the archive wrapper, the debug and object-tracking aids.
#                 TaskCore links this and nothing else.
#   GuiHelpers  - QtGui and QtWidgets. The dialogs, the widgets, the item
#                 models, the theme, the icon and menu builders. Only the front
#                 end links this; it links CoreHelpers too.
#
# The files stay where they are, in one directory over two targets: every
# consumer's #include "../MiscHelpers/Common/Settings.h" keeps working, and
# moving them would have touched every include in the tree for no benefit.
#
# Note on the Archive/ subtree: ArchiveHelper.cpp is a unity translation unit
# that #includes Archive.cpp, ArchiveExtractor.cpp, ArchiveInterface.cpp,
# ArchiveOpener.cpp and ArchiveUpdater.cpp, which is why those five are not
# listed separately (the Visual Studio project excluded them for the same
# reason). The whole subtree is a 7-Zip wrapper built on the Win32 COM shims in
# Archive/7z/CPP/Common/MyWindows.h and is Windows-only for now; on Linux it is
# left out and the two call sites in TaskExplorer are guarded instead.
#

set(COREHELPERS_SOURCES
    corehelpers_global.h
    stdafx.cpp
    stdafx.h

    Common/Common.cpp
    Common/Common.h

    #
    # Serialisation, moved out of TaskCore.
    #
    # None of it knows anything about processes: CVariant is a self-describing
    # value with its own packet format, CBuffer is bytes, and the string
    # helpers are string helpers. It sat in TaskCore only because that is where
    # it was first needed, which put it above CoreHelpers and out of reach of
    # the IPC layer that wants it for the wire format.
    #
    # Everything except XVariant is STL-only and Qt-free - TaskHelper compiles
    # the same sources standalone, and must go on being able to.
    #
    Common/Buffer.cpp
    Common/Buffer.h
    Common/Exception.h
    Common/Strings.cpp
    Common/Strings.h
    Common/Types.h
    Common/Variant.cpp
    Common/Variant.h
    Common/VariantDefs.h
    Common/XVariant.cpp
    Common/XVariant.h
    Common/Compat.cpp
    Common/Compat.h
    Common/DebugHelpers.cpp
    Common/DebugHelpers.h

    # The local IPC layer. In CoreHelpers because both front ends and the
    # server need it, and because it is transport plumbing rather than object
    # model - it knows nothing about processes.
    Common/IPC/Discovery.cpp
    Common/IPC/Discovery.h
    Common/IPC/IPCServer.cpp
    Common/IPC/IPCServer.h
    Common/IPC/IPCSocket.cpp
    Common/IPC/IPCSocket.h
    Common/IPC/VariantCache.h
    Common/MT/ThreadLock.cpp
    Common/MT/ThreadLock.h
    Common/NetworkAccessManager.cpp
    Common/NetworkAccessManager.h
    Common/ObjectTracker.cpp
    Common/ObjectTracker.h
    Common/OtherFunctions.cpp
    Common/OtherFunctions.h
    Common/Crypto.cpp
    Common/Status.cpp
    Common/CredentialStore.cpp
    Common/PasswordHash.cpp
    Common/CredentialStore.h
    Common/Status.h
    Common/Crypto.h
    Common/Settings.cpp
    Common/Settings.h
    Common/Xml.cpp
    Common/Xml.h
    Common/qRC4.cpp
    Common/qRC4.h
)

if(WIN32)
    list(APPEND COREHELPERS_SOURCES
        Archive/ArchiveFS.cpp
        Archive/ArchiveFS.h
        Archive/ArchiveHelper.cpp
        Archive/ArchiveThread.cpp
        Archive/CachedArchive.cpp
        Archive/SplitFile.cpp
    )
endif()

#
# GuiHelpers.
#
# The item models are here rather than in CoreHelpers. QAbstractItemModel is
# QtCore, but ListItemModel.h includes TreeViewEx.h and data() hands back a
# QBrush, so the classes are QtWidgets in practice - and nothing in the
# collector uses them.
#
set(GUIHELPERS_SOURCES
    guihelpers_global.h
    MiscHelpers.cpp
    MiscHelpers.h
    stdafx.cpp
    stdafx.h

    Common/CheckableMessageBox.cpp
    Common/CheckableMessageBox.h
    Common/CollapsibleGroupBox.cpp
    Common/CollapsibleGroupBox.h
    Common/ComboInputDialog.cpp
    Common/ComboInputDialog.h
    Common/CommonGui.cpp
    Common/CommonGui.h
    Common/CustomStyles.h

    # Widgets, so GuiHelpers rather than CoreHelpers: IncrementalPlot is a qwt
    # plot and TabPanel is a QWidget.
    Common/IncrementalPlot.cpp
    Common/IncrementalPlot.h
    Common/TabPanel.cpp
    Common/TabPanel.h
    Common/CustomTheme.cpp
    Common/CustomTheme.h
    Common/ExitDialog.h
    Common/Finder.cpp
    Common/Finder.h
    Common/FlowLayout.cpp
    Common/FlowLayout.h
    Common/HistoryGraph.h
    Common/ItemChooser.cpp
    Common/ItemChooser.h
    Common/KeyValueInputDialog.cpp
    Common/KeyValueInputDialog.h
    Common/ListItemModel.cpp
    Common/ListItemModel.h
    Common/MultiLineInputDialog.cpp
    Common/MultiLineInputDialog.h
    Common/PanelView.cpp
    Common/PanelView.h
    Common/ProgressDialog.h
    Common/SettingsWidgets.cpp
    Common/SettingsWidgets.h
    Common/SmartGridWidget.cpp
    Common/SmartGridWidget.h
    Common/SortFilterProxyModel.h
    Common/SplitTreeView.cpp
    Common/SplitTreeView.h
    Common/TreeItemModel.cpp
    Common/TreeItemModel.h
    Common/TreeViewEx.h
    Common/TreeWidgetEx.h
)


# ---------------------------------------------------------------- CoreHelpers

add_library(CoreHelpers STATIC ${COREHELPERS_SOURCES})

target_compile_definitions(CoreHelpers PRIVATE COREHELPERS_LIB)

target_include_directories(CoreHelpers PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

#
# PUBLIC because both are in this library's headers - Settings and Xml hand
# back QVariants, Common formats QStrings and compares QHostAddresses.
#
target_link_libraries(CoreHelpers PUBLIC
    Qt6::Core
    Qt6::Network
)

if(WIN32)
    # ArchiveFS.h pulls in <private/qabstractfileengine_p.h>.
    te_target_qt_private_includes(CoreHelpers QtCore)
    target_link_libraries(CoreHelpers PRIVATE user32 shell32 oleaut32)
endif()

#
# No TE_WITH_WIDGETS. That switch decides what stdafx.h contains and whether
# Common.h reaches CommonGui.h; without it this target cannot include a widget
# header even by accident, which is the point of the split.
#
target_precompile_headers(CoreHelpers PRIVATE stdafx.h)


# ----------------------------------------------------------------- GuiHelpers

add_library(GuiHelpers STATIC ${GUIHELPERS_SOURCES})

target_compile_definitions(GuiHelpers PRIVATE GUIHELPERS_LIB)

target_include_directories(GuiHelpers PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

#
# PUBLIC: Gui and Widgets are in this library's headers - the dialogs are
# QDialog subclasses, CommonGui.h hands back QIcons and QActions - and anything
# linking GuiHelpers is a front end that has them anyway.
#
# CoreHelpers is PUBLIC too: GuiHelpers' headers include Common.h, and the
# dependency only ever points this way.
#
target_link_libraries(GuiHelpers PUBLIC
    CoreHelpers
    Qt6::Gui
    Qt6::Widgets
)

target_link_libraries(GuiHelpers PRIVATE qextwidgets qwt)

#
# PUBLIC here, unlike on the old single target. TE_WITH_WIDGETS is what makes
# Common.h include CommonGui.h, so a consumer that calls MakeAction needs it
# defined as well - and every consumer of GuiHelpers is a front end by
# definition. It was PRIVATE before only to keep it away from TaskCore, which
# no longer links this target at all.
#
target_compile_definitions(GuiHelpers PUBLIC TE_WITH_WIDGETS)

target_precompile_headers(GuiHelpers PRIVATE stdafx.h)
