#pragma once
#include <qobject.h>
#include "AbstractInfo.h"

#include "ModuleInfo.h"

class TASKCORE_EXPORT CHeapInfo: public CAbstractInfoEx
{
	Q_OBJECT

	TRACK_OBJECT(CHeapInfo)
public:
	CHeapInfo(QObject *parent = nullptr);
	virtual ~CHeapInfo();

	virtual quint32 GetFlags() const { QReadLocker Locker(&m_Mutex); return m_Flags; }
	//
	// Heap creation flags, class and kind - by the platform's own numbers,
	// asserted in WinHeap.cpp. A Linux heap reports none of this.
	//
	enum EHeapFlags
	{
		eHeapNoSerialize			= 0x00000001,
		eHeapGrowable				= 0x00000002,
		eHeapGenerateExceptions		= 0x00000004,
		eHeapZeroMemory				= 0x00000008,
		eHeapReallocInPlaceOnly		= 0x00000010,
		eHeapTailChecking			= 0x00000020,
		eHeapFreeChecking			= 0x00000040,
		eHeapDisableCoalesceOnFree	= 0x00000080,
		eHeapCreateSegmentHeap		= 0x00000100,
		eHeapCreateHardened			= 0x00000200,
		eHeapCreateAlign16			= 0x00010000,
		eHeapCreateEnableTracing	= 0x00020000,
		eHeapCreateEnableExecute	= 0x00040000,
	};

	enum EHeapClass
	{
		eHeapClassProcess		= 0x0000,
		eHeapClassPrivate		= 0x1000,
		eHeapClassKernel		= 0x2000,
		eHeapClassGdi			= 0x3000,
		eHeapClassUser			= 0x4000,
		eHeapClassConsole		= 0x5000,
		eHeapClassDesktop		= 0x6000,
		eHeapClassCsrShared		= 0x7000,
		eHeapClassCsrPort		= 0x8000,
	};

	//
	// Which heap implementation this is, and which front end it uses.
	//
	enum EHeapKind
	{
		eHeapUnknown	= 0,
		eHeapNt			= 1,
		eHeapSegment	= 2,
	};
	enum EHeapFrontEnd
	{
		eFrontEndNone		= 0,
		eFrontEndLookaside	= 1,
		eFrontEndLfh		= 2,
	};
	virtual int GetHeapKind() const					{ return eHeapUnknown; }
	virtual int GetFrontEndType() const				{ return eFrontEndNone; }
	virtual quint32 GetClass() const = 0;
	virtual quint32 GetType() const = 0;
	virtual quint32 GetNumberOfEntries() const { QReadLocker Locker(&m_Mutex); return m_NumberOfEntries; }
	virtual quint64 GetBaseAddress() const { QReadLocker Locker(&m_Mutex); return m_BaseAddress; }
	virtual quint64 GetBytesAllocated() const { QReadLocker Locker(&m_Mutex); return m_BytesAllocated; }
	virtual quint64 GetBytesCommitted() const { QReadLocker Locker(&m_Mutex); return m_BytesCommitted; }

protected:

    quint32 m_Flags;
    quint32 m_NumberOfEntries;
    quint64 m_BaseAddress;
    quint64 m_BytesAllocated;
    quint64 m_BytesCommitted;
};

typedef QSharedPointer<CHeapInfo> CHeapPtr;
typedef QWeakPointer<CHeapInfo> CHeapRef;