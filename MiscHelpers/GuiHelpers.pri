# ----------------------------------------------------
# GuiHelpers - the half of the old MiscHelpers that does draw.
#
# QtGui and QtWidgets. Kept in step with CMakeLists.txt and GuiHelpers.vcxproj
# by hand; a file added to one has to be added to all three.
#
# The item models are here rather than in CoreHelpers: QAbstractItemModel is
# QtCore, but ListItemModel.h includes TreeViewEx.h and data() hands back a
# QBrush, and nothing in the collector uses them.
# ------------------------------------------------------

HEADERS += ./MiscHelpers.h \
    ./guihelpers_global.h \
    ./stdafx.h \
    ./Common/CheckableMessageBox.h \
    ./Common/CollapsibleGroupBox.h \
    ./Common/ComboInputDialog.h \
    ./Common/CommonGui.h \
    ./Common/CustomStyles.h \
    ./Common/CustomTheme.h \
    ./Common/ExitDialog.h \
    ./Common/Finder.h \
    ./Common/FlowLayout.h \
    ./Common/HistoryGraph.h \
    ./Common/IncrementalPlot.h \
    ./Common/TabPanel.h \
    ./Common/ItemChooser.h \
    ./Common/KeyValueInputDialog.h \
    ./Common/ListItemModel.h \
    ./Common/MultiLineInputDialog.h \
    ./Common/PanelView.h \
    ./Common/ProgressDialog.h \
    ./Common/SettingsWidgets.h \
    ./Common/SmartGridWidget.h \
    ./Common/SortFilterProxyModel.h \
    ./Common/SplitTreeView.h \
    ./Common/TreeItemModel.h \
    ./Common/TreeViewEx.h \
    ./Common/TreeWidgetEx.h

SOURCES += ./MiscHelpers.cpp \
    ./stdafx.cpp \
    ./Common/CheckableMessageBox.cpp \
    ./Common/CollapsibleGroupBox.cpp \
    ./Common/ComboInputDialog.cpp \
    ./Common/CommonGui.cpp \
    ./Common/CustomTheme.cpp \
    ./Common/IncrementalPlot.cpp \
    ./Common/TabPanel.cpp \
    ./Common/Finder.cpp \
    ./Common/FlowLayout.cpp \
    ./Common/ItemChooser.cpp \
    ./Common/KeyValueInputDialog.cpp \
    ./Common/ListItemModel.cpp \
    ./Common/MultiLineInputDialog.cpp \
    ./Common/PanelView.cpp \
    ./Common/SettingsWidgets.cpp \
    ./Common/SmartGridWidget.cpp \
    ./Common/SplitTreeView.cpp \
    ./Common/TreeItemModel.cpp
