#pragma once
#include <qobject.h>
#include "../PoolInfo.h"

//
// The Windows half of a pool tag: reading the kernel's tag table. Everything a
// viewer reads is on CPoolEntryInfo, so a remote system can answer it too - see
// the note there.
//
class CWinPoolEntry: public CPoolEntryInfo
{
	Q_OBJECT

	TRACK_OBJECT(CWinPoolEntry)
public:
	CWinPoolEntry(QObject *parent = nullptr);
	virtual ~CWinPoolEntry();

protected:
	friend class CWindowsAPI;

	bool InitStaticData(quint64 TagName, const QString& Driver, const QString& Description);
	bool UpdateDynamicData(struct _SYSTEM_POOLTAG* pPoolTagInfo);
};