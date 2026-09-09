#pragma once

#include <QtCore/qglobal.h>

//
// CoreHelpers - the half of the old MiscHelpers that draws nothing.
//
// Settings, Xml, the formatting helpers, the archive wrapper, the debug and
// object-tracking aids: QtCore and QtNetwork only. TaskCore links this one and
// nothing else, which is what keeps QtGui and QtWidgets off the collector's
// link line.
//
// COREHELPERS_STATIC rather than the shared BUILD_STATIC. BUILD_STATIC says
// "the vendored libraries are static archives" and speaks for qextwidgets and
// qhexedit as well; a library that goes static on its own needs a switch of
// its own. Sharing one across libraries that are not all static broke the
// build once already.
//
#if defined(COREHELPERS_STATIC) || defined(BUILD_STATIC)
# define COREHELPERS_EXPORT
#elif defined(COREHELPERS_LIB)
# define COREHELPERS_EXPORT Q_DECL_EXPORT
#else
# define COREHELPERS_EXPORT Q_DECL_IMPORT
#endif
