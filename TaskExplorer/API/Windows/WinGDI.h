#pragma once
#include <qobject.h>
#include "../GdiInfo.h"

//
// The Windows filling of CGdiInfo. Everything the view reads is on the base;
// what is left here is how to get it out of the object manager's handle table.
//
class CWinGDI: public CGdiInfo
{
	Q_OBJECT

	TRACK_OBJECT(CWinGDI)
public:
	CWinGDI(QObject *parent = nullptr);
	virtual ~CWinGDI();

	bool InitData(quint32 index, struct _GDI_HANDLE_ENTRY* handle, const QString& ProcessName);

private:
	// The handle's own bits say what it refers to. Decoded once, here, because
	// it needs GDI_CLIENT_TYPE_FROM_UNIQUE and nothing off Windows has it.
	static quint32 DecodeGdiType(quint32 HandleId);
};
