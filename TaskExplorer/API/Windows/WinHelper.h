#pragma once
#include "../../taskcore_global.h"
#include "../../../MiscHelpers/Common/Status.h"

//QVariantMap ResolveShortcut(const QString& LinkPath);

//
// The icon picker was never wired up, and the two loaders that went with this -
// LoadWindowsIcon and LoadWindowsIconEx - were the last thing in the core with
// a QPixmap or QIcon in its signature, so they are gone. Anything bringing them
// back should return the bytes of an image the way CModuleInfo::GetFileIcon
// does, for the reasons given there.
//
// The parent window travels as a handle by value: the core has no business
// knowing what a QWidget is.
//
TASKCORE_EXPORT bool PickWindowsIcon(quint64 ParentWnd, QString& Path, quint32& Index);

TASKCORE_EXPORT bool WindowsMoveFile(const QString& From, const QString& To);

TASKCORE_EXPORT bool OpenFileProperties(const QString& Path);

TASKCORE_EXPORT bool OpenFileFolder(const QString& Path);

TASKCORE_EXPORT bool CheckInternet();

TASKCORE_EXPORT QVariantList EnumNICs();

TASKCORE_EXPORT bool IsFullScreenMode();

//
// Startup facts the entry point reports on. Wrapped so nothing outside the
// core has to name a phlib type to ask.
//
TASKCORE_EXPORT bool IsRunningUnderWow64();
TASKCORE_EXPORT quint32 GetWindowsVersion();
TASKCORE_EXPORT QString GetNtStatusMessage(quint32 Status);
TASKCORE_EXPORT QString GetKernelVersionString();

//
// Startup, in the order the entry point performs it. All of this used to be
// phlib and kphlib calls made directly from main(); the core owns them now so
// the executable never has to name a native type.
//
TASKCORE_EXPORT int  InitNativeApi();

// -kx / -kh, which pick how hard the driver tries to load
TASKCORE_EXPORT void SetKernelDriverStartup(bool Max, bool High);

TASKCORE_EXPORT STATUS LoadKernelDriver(const QString& AppDir);
TASKCORE_EXPORT STATUS UnloadKernelDriver();

//
// Whether the driver is already running, asked of the service manager before
// anything tries to load it.
//
// It answers a question only the caller can act on: KPH grants the maximum
// level to a process it saw *created* while the driver was already running, so
// a process that loaded the driver itself can never have it, however elevated
// or verified it is. Knowing which of the two happened is the difference
// between "try again and it will work" and "trying again changes nothing".
//
TASKCORE_EXPORT bool IsKernelDriverRunning();

//
// What the driver granted this process, as CProcessInfo::EKphLevel. Zero when
// there is no driver.
//
TASKCORE_EXPORT int  GetKernelDriverLevel();

// True when the driver refused because it does not know this kernel build,
// which is the one failure the user can fix by updating DynData.
TASKCORE_EXPORT bool IsUnsupportedKernel(quint32 Status);

// The privileges the service mode needs, and the priority the app runs at.
TASKCORE_EXPORT void EnableServicePrivileges();
TASKCORE_EXPORT void SetOwnProcessPriority();

// System-DPI awareness, the -DPIScaling=1 option
TASKCORE_EXPORT void SetSystemDpiAware();
