#pragma once
#include "../taskcore_global.h"
#include <qobject.h>
#include "AbstractInfo.h"
#include "MiscStats.h"

//
// How much the kernel has allocated under one tag.
//
// Paged and non-paged are the two pools Windows keeps; a target with one pool
// leaves the other at zero rather than pretending the distinction does not
// exist, because a viewer showing two machines side by side needs the columns
// to mean the same thing on both.
//
struct SPoolEntryStats
{
    SDelta64 PagedAllocsDelta;
    SDelta64 PagedFreesDelta;
    SDelta64 PagedCurrentDelta;
    SDelta64 PagedTotalSizeDelta;
    SDelta64 NonPagedAllocsDelta;
    SDelta64 NonPagedFreesDelta;
    SDelta64 NonPagedCurrentDelta;
    SDelta64 NonPagedTotalSizeDelta;
};

//
// One kernel pool tag, and what has been allocated under it.
//
// This was CWinPoolEntry, and the pool view reached it by casting the system to
// CWindowsAPI - a cast that cannot succeed once the system is a remote one.
// Same move as CGdiInfo and CRpcEndpointInfo, for the same reason.
//
// The tag itself is four characters the driver chose, which is a Windows
// notion; the shape - a name, the driver it belongs to, a description and a set
// of allocation counters - is not. A Linux backend reporting slab caches from
// /proc/slabinfo would fill in the same fields.
//
class TASKCORE_EXPORT CPoolEntryInfo : public CAbstractInfoEx
{
	Q_OBJECT

	TRACK_OBJECT(CPoolEntryInfo)
public:
	CPoolEntryInfo(QObject *parent = nullptr);
	virtual ~CPoolEntryInfo();

	virtual quint64 GetTagID() const				{ QReadLocker Locker(&m_Mutex); return m_TagName; }
	virtual quint32 GetTag() const					{ QReadLocker Locker(&m_Mutex); return m_TagName; }
	virtual QString GetDriver() const				{ QReadLocker Locker(&m_Mutex); return m_Driver; }
	virtual QString GetDescription() const			{ QReadLocker Locker(&m_Mutex); return m_Description; }

	virtual SPoolEntryStats GetEntryStats() const	{ QReadLocker Locker(&m_Mutex); return m_EntryStats; }

protected:
	friend class CWindowsAPI;

	quint32			m_TagName = 0;
	QString			m_Driver;
	QString			m_Description;

	SPoolEntryStats	m_EntryStats;
};

typedef QSharedPointer<CPoolEntryInfo> CPoolEntryPtr;
typedef QWeakPointer<CPoolEntryInfo> CPoolEntryRef;
