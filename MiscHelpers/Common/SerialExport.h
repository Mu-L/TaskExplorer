#pragma once

//
// The export macro for the serialisation, without pulling Qt in.
//
// corehelpers_global.h would be the obvious place, but it includes
// <QtCore/qglobal.h> to get Q_DECL_EXPORT - and CVariant, CBuffer and the
// string helpers are also compiled standalone by TaskHelper, which has no Qt at
// all and must keep it that way. So the same decision is made here in terms the
// compiler provides directly.
//
// COREHELPERS_STATIC is what TaskHelper defines: it compiles these sources into
// itself rather than importing them from a DLL, and without it the Windows
// build would decorate every one of them with dllimport and fail to link.
//
#if defined(COREHELPERS_STATIC) || defined(BUILD_STATIC) || !defined(_WIN32)
# define SERIAL_EXPORT
#elif defined(COREHELPERS_LIB)
# define SERIAL_EXPORT __declspec(dllexport)
#else
# define SERIAL_EXPORT __declspec(dllimport)
#endif
