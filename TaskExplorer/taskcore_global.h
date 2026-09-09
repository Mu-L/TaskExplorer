#pragma once

#include <QtCore/qglobal.h>

//
// TaskCore holds the platform backends and the portable object model: the
// GUI links it, and so will the headless core once that target exists.
//
// Note that a good deal of the model is inline - getters that take the read
// lock and return a member - so the DLL and the executables that load it are
// one unit, built together and shipped together. There is no ABI to keep.
//
//
// This used to key off BUILD_STATIC, which is the *vendored helper libraries'*
// switch - MiscHelpers, qextwidgets and qhexedit are static archives, and the
// CMake root defines it globally for them. TaskCore is not one of them: it is a
// shared library on both platforms, so sharing that switch made
// TASKCORE_EXPORT expand to nothing under CMake. On Linux that happens to work,
// because GCC exports every symbol unless told otherwise; on Windows it would
// produce a DLL with nothing in it. TASKCORE_STATIC is its own switch, and
// nothing defines it today.
//
#if defined(TASKCORE_STATIC)
# define TASKCORE_EXPORT
#elif defined(TASKCORE_LIB)
# define TASKCORE_EXPORT Q_DECL_EXPORT
#else
# define TASKCORE_EXPORT Q_DECL_IMPORT
#endif
