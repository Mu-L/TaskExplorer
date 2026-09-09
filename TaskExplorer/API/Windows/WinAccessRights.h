#pragma once
#include "../SecurityInfo.h"

//
// One row of an object type's access-right table: which right it is, which
// bits stand for it, and whether it belongs among the few shown first.
//
struct SWinAccessEntry
{
	int			Right;			// EAccessRight
	quint32		Access;
	bool		bGeneral;
	bool		bSpecific;
};

//
// Which rights a granted-access mask actually grants, for an object of the
// given type. The type name is the same identifier CSecurityEditable reports.
//
QList<int> WinAccess__GetGrantedRights(quint32 Access, const QString& Type);

// The same, for a file handle's open mode.
QList<int> WinAccess__GetFileModeRights(quint32 Mode);

// Everything a type understands, for the security dialog.
QList<SAccessRight> WinAccess__GetAccessRights(const QString& Type);
