#include "stdafx.h"
#include "WinHeap.h"

#include "ProcessHacker.h"

CWinHeap::CWinHeap(QObject *parent) : CHeapInfo(parent)
{
	m_Signature = 0;
	m_HeapFrontEndType = 0;
}

CWinHeap::~CWinHeap()
{
}

quint32 CWinHeap::GetFlags() const 
{ 
	QReadLocker Locker(&m_Mutex); 
	return m_Flags & ~HEAP_CLASS_MASK; 
}

quint32 CWinHeap::GetClass() const
{ 
	QReadLocker Locker(&m_Mutex); 
	return m_Flags & HEAP_CLASS_MASK; 
}

quint32 CWinHeap::GetType() const
{
	QReadLocker Locker(&m_Mutex);
	return m_HeapFrontEndType;
}



//
// Which heap this is, as a value. The signature distinguishes the two
// implementations; the front-end type is already a small number.
//
int CWinHeap::GetHeapKind() const
{
	QReadLocker Locker(&m_Mutex);
	switch (m_Signature)
	{
	case RTL_HEAP_SIGNATURE:			return eHeapNt;
	case RTL_HEAP_SEGMENT_SIGNATURE:	return eHeapSegment;
	}
	return eHeapUnknown;
}

int CWinHeap::GetFrontEndType() const
{
	QReadLocker Locker(&m_Mutex);
	return (int)m_HeapFrontEndType;
}

static_assert(CHeapInfo::eHeapNoSerialize          == HEAP_NO_SERIALIZE,             "heap flag drifted");
static_assert(CHeapInfo::eHeapGrowable             == HEAP_GROWABLE,                 "heap flag drifted");
static_assert(CHeapInfo::eHeapGenerateExceptions   == HEAP_GENERATE_EXCEPTIONS,      "heap flag drifted");
static_assert(CHeapInfo::eHeapZeroMemory           == HEAP_ZERO_MEMORY,              "heap flag drifted");
static_assert(CHeapInfo::eHeapReallocInPlaceOnly   == HEAP_REALLOC_IN_PLACE_ONLY,    "heap flag drifted");
static_assert(CHeapInfo::eHeapTailChecking         == HEAP_TAIL_CHECKING_ENABLED,    "heap flag drifted");
static_assert(CHeapInfo::eHeapFreeChecking         == HEAP_FREE_CHECKING_ENABLED,    "heap flag drifted");
static_assert(CHeapInfo::eHeapDisableCoalesceOnFree== HEAP_DISABLE_COALESCE_ON_FREE, "heap flag drifted");
static_assert(CHeapInfo::eHeapCreateSegmentHeap    == HEAP_CREATE_SEGMENT_HEAP,      "heap flag drifted");
static_assert(CHeapInfo::eHeapCreateHardened       == HEAP_CREATE_HARDENED,          "heap flag drifted");
static_assert(CHeapInfo::eHeapCreateAlign16        == HEAP_CREATE_ALIGN_16,          "heap flag drifted");
static_assert(CHeapInfo::eHeapCreateEnableTracing  == HEAP_CREATE_ENABLE_TRACING,    "heap flag drifted");
static_assert(CHeapInfo::eHeapCreateEnableExecute  == HEAP_CREATE_ENABLE_EXECUTE,    "heap flag drifted");

static_assert(CHeapInfo::eHeapClassProcess   == HEAP_CLASS_0, "heap class drifted");
static_assert(CHeapInfo::eHeapClassPrivate   == HEAP_CLASS_1, "heap class drifted");
static_assert(CHeapInfo::eHeapClassKernel    == HEAP_CLASS_2, "heap class drifted");
static_assert(CHeapInfo::eHeapClassGdi       == HEAP_CLASS_3, "heap class drifted");
static_assert(CHeapInfo::eHeapClassUser      == HEAP_CLASS_4, "heap class drifted");
static_assert(CHeapInfo::eHeapClassConsole   == HEAP_CLASS_5, "heap class drifted");
static_assert(CHeapInfo::eHeapClassDesktop   == HEAP_CLASS_6, "heap class drifted");
static_assert(CHeapInfo::eHeapClassCsrShared == HEAP_CLASS_7, "heap class drifted");
static_assert(CHeapInfo::eHeapClassCsrPort   == HEAP_CLASS_8, "heap class drifted");
