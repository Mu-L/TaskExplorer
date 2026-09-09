#pragma once

#include <QtCore/qglobal.h>

//
// GuiHelpers - the half of the old MiscHelpers that does draw.
//
// The dialogs, the widgets, the item models, the theme and the icon and menu
// builders: QtGui and QtWidgets. Only the front end links this. It links
// CoreHelpers too, and may use anything from it; the dependency never points
// the other way.
//
// See corehelpers_global.h for why each library carries its own static switch
// rather than sharing BUILD_STATIC.
//
//
// The multi-row tab bar from qextwidgets, rather than Qt's own single row with
// scroll arrows.
//
// It has to be decided *here* and not in a front end's stdafx.h. CTabPanel
// keeps a pointer whose type this switch chooses, so the library and everything
// that includes its header must agree - TabPanel.cpp is compiled into
// GuiHelpers and would otherwise construct a plain QTabWidget while
// TaskExplorer's copy of the header believed it was a QTabWidgetEx. That is
// what silently lost the multi-row tabs when TabPanel moved out of TaskExplorer
// and into this library.
//
#define USE_QEXTWIDGETS

#if defined(GUIHELPERS_STATIC) || defined(BUILD_STATIC)
# define GUIHELPERS_EXPORT
#elif defined(GUIHELPERS_LIB)
# define GUIHELPERS_EXPORT Q_DECL_EXPORT
#else
# define GUIHELPERS_EXPORT Q_DECL_IMPORT
#endif
