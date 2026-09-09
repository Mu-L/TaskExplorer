#pragma once
#include "SecurityInfo.h"
#include <qobject.h>
#include "StackTrace.h"
#include "AbstractTask.h"
#include "TokenInfo.h"

class TASKCORE_EXPORT CThreadInfo: public CAbstractTask
{
	Q_OBJECT

	TRACK_OBJECT(CThreadInfo)
public:
	CThreadInfo(QObject *parent = nullptr);
	virtual ~CThreadInfo();

	virtual quint64 GetThreadId()	const			{ QReadLocker Locker(&m_Mutex); return m_ThreadId; }
	virtual quint64 GetProcessId()	const			{ QReadLocker Locker(&m_Mutex); return m_ProcessId; }

	virtual QString GetStartAddressString() const = 0;
	//
	// What a thread is doing, as the kernel's own state numbering. A thread in
	// eThreadWaiting is described further by its wait reason; every other state
	// stands on its own.
	//
	enum EThreadState
	{
		eThreadInitialized				= 0,
		eThreadReady					= 1,
		eThreadRunning					= 2,
		eThreadStandby					= 3,
		eThreadTerminated				= 4,
		eThreadWaiting					= 5,
		eThreadTransition				= 6,
		eThreadDeferredReady			= 7,
		eThreadGateWait					= 8,
		eThreadWaitingForProcessInSwap	= 9,

		eThreadStateCount				= 10,
	};

	//
	// Why a waiting thread is waiting. The names are the kernel's; only the
	// count and the two values singled out elsewhere are spelled here, since
	// the rest are read from a table indexed by this number.
	//
	enum EWaitReason
	{
		eWaitExecutive		= 0,
		eWaitSuspended		= 5,

		eWaitReasonCount	= 43,
	};

	virtual int GetState()	const					{ QReadLocker Locker(&m_Mutex); return m_State; }

	// Only meaningful while waiting on eWaitSuspended.
	virtual quint32 GetSuspendCount() const			{ return 0; }
	virtual quint64 GetWaitState()	const			{ QReadLocker Locker(&m_Mutex); return ((quint64)m_State) | ((quint64)m_WaitReason << 32); }
	virtual int GetWaitReason()	const				{ QReadLocker Locker(&m_Mutex); return m_WaitReason; }

	virtual void SetMainThread(bool bSet = true)	{ QWriteLocker Locker(&m_Mutex); m_IsMainThread = bSet; }
	virtual bool IsMainThread() const				{ QReadLocker Locker(&m_Mutex); return m_IsMainThread; }

	virtual float GetStackUsagePercent() const		{ QReadLocker Locker(&m_Mutex); return m_StackUsageFloat; }
	virtual quint64 GetStackUsage() const			{ QReadLocker Locker(&m_Mutex); return m_StackUsage; }
	virtual quint64 GetStackLimit() const			{ QReadLocker Locker(&m_Mutex); return m_StackLimit; }

	virtual STaskStats GetCpuStats() const			{ QReadLocker Locker(&m_StatsMutex); return m_CpuStats; }

	virtual SIOStatsEx GetIoStats() const			{ QReadLocker Locker(&m_StatsMutex); return m_IoStats; }

	virtual QSharedPointer<QObject>	GetProcess() const;
	//virtual QSharedPointer<QObject>	GetProcess() const { QReadLocker Locker(&m_Mutex); return m_pProcess; }
	virtual void SetProcess(QSharedPointer<QObject> pProcess) { QWriteLocker Locker(&m_Mutex); m_pProcess = pProcess; }

	//
	// ---- platform surface ----
	//
	// Everything either platform can report, so the models never need to know
	// which one answered. An implementation without the notion does not
	// override; the default below is the honest answer, and whether a column
	// built on it is worth showing is decided by GetOsType()/HasCapability().
	//
	virtual QString GetThreadName() const			{ return QString(); }
	virtual QString GetServiceName() const			{ return QString(); }
	virtual quint64 GetLXSSThreadId() const			{ return 0; }

	virtual QString GetStartAddressFileName() const	{ return QString(); }
	//
	// Which processor the scheduler would rather run this thread on, as a group
	// and a number within it. -1 for either means the platform does not say.
	//
	virtual int     GetIdealProcessorGroup() const	{ return -1; }
	virtual int     GetIdealProcessorNumber() const	{ return -1; }

	virtual quint64 GetBasePriorityIncrement() const		{ return 0; }


	//
	// COM apartment the thread joined, where the platform has such a concept.
	// The type numbering is not the platform's own - COM has no single constant
	// for "which apartment is this" - so it is defined here and the backend maps
	// onto it.
	//
	enum EApartmentType
	{
		eApartmentNone			= 0,
		eApartmentSta			= 1,
		eApartmentMainSta		= 2,
		eApartmentApplicationSta= 3,
		eApartmentMta			= 4,
		eApartmentImplicitMta	= 5,
	};
	virtual int     GetApartmentType() const		{ return eApartmentNone; }

	// A thread in the neutral apartment is there *as well as* in its own.
	virtual bool    IsInNeutralApartment() const	{ return false; }

	// How many times the thread initialized COM without uninitializing it.
	virtual quint32 GetComInitCount() const			{ return 0; }

	//
	// The apartment's own flags, which are the OLE thread-local storage bits.
	//
	enum EApartmentFlag
	{
		eOleLocalTid					= 0x00000001,
		eOleUuidInitialized				= 0x00000002,
		eOleInThreadDetach				= 0x00000004,
		eOleChannelThreadInitialized	= 0x00000008,
		eOleWowThread					= 0x00000010,
		eOleThreadUninitializing		= 0x00000020,
		eOleDisableOle1Dde				= 0x00000040,
		eOleApartmentThreaded			= 0x00000080,
		eOleMultiThreaded				= 0x00000100,
		eOleImpersonating				= 0x00000200,
		eOleDisableEventLogger			= 0x00000400,
		eOleInNeutralApt				= 0x00000800,
		eOleDispatchThread				= 0x00001000,
		eOleHostThread					= 0x00002000,
		eOleAllowCoInit					= 0x00004000,
		eOlePendingUninit				= 0x00008000,
		eOleFirstMtaInit				= 0x00010000,
		eOleFirstNtaInit				= 0x00020000,
		eOleAptInitializing				= 0x00040000,
		eOleUiMsgsInModalLoop			= 0x00080000,
		eOleMarshalingErrorObject		= 0x00100000,
		eOleWinRtInitialize				= 0x00200000,
		eOleApplicationSta				= 0x00400000,
		eOleInShutdownCallbacks			= 0x00800000,
		eOlePointerInputBlocked			= 0x01000000,
		eOleInActivationFilter			= 0x02000000,
		eOleAstaToAstaExemptQuirk		= 0x04000000,
		eOleAstaToAstaExemptProxy		= 0x08000000,
		eOleAstaToAstaExemptIndoubt		= 0x10000000,
		eOleDetectedUserInitialized		= 0x20000000,
		eOleBridgeSta					= 0x40000000,
		eOleNaInitializing				= 0x80000000,
	};
	virtual quint32 GetApartmentFlags() const		{ return 0; }

	// Managed runtime the thread is executing in.
	virtual QString GetAppDomain() const			{ return QString(); }

	//
	// The last system call the thread issued, for a thread sitting in kernel.
	// Reported as its number, the first argument it was given, and how long the
	// thread has been in it.
	//
	// The name comes with it, as text. That is not a table anyone could port:
	// there is no published list of system call numbers, and the mapping is
	// recovered by reading the running machine's own ntdll and win32k and
	// sorting their exports by address. It also changes from one Windows build
	// to the next. So the name is a value only the target can produce, and it
	// travels as one - the same as the wording of a native status.
	//
	virtual bool    HasLastSysCall() const					{ return false; }
	virtual quint32 GetLastSysCallNumber() const			{ return 0; }
	virtual QString GetLastSysCallName() const				{ return QString(); }
	virtual quint64 GetLastSysCallArgument() const			{ return 0; }

	// Milliseconds, or 0 where the platform does not report one.
	virtual quint64 GetLastSysCallWaitTime() const			{ return 0; }

	//
	// The status the thread's last call returned, when it was not success. The
	// number is the value; its wording comes from the platform, the same way
	// CTaskStatus carries a native status and the sentence that goes with it.
	//
	virtual bool    HasLastStatus() const					{ return false; }
	virtual quint32 GetLastStatusValue() const				{ return 0; }
	virtual QString GetLastStatusMessage() const			{ return QString(); }

	//
	// Whether the thread carries an impersonation token, and if so whether it
	// could be read. Distinct from "has a token" because an anonymous one is
	// present but says nothing.
	//
	enum ETokenState
	{
		eTokenStateUnknown,
		eTokenStateNotPresent,
		eTokenStateAnonymous,
		eTokenStatePresent
	};
	virtual ETokenState GetTokenState() const		{ return eTokenStateUnknown; }
	virtual bool HasToken2() const					{ return false; }

	virtual bool IsCriticalThread() const			{ return false; }
	virtual STATUS SetCriticalThread(bool bSet, bool bForce = false)
													{ Q_UNUSED(bSet); Q_UNUSED(bForce); return ERR(TE_NotSupported); }

	// Cancel the thread's outstanding I/O requests.
	virtual STATUS CancelIO()						{ return ERR(TE_NotSupported); }

	//
	// The thread's impersonation token, and the one it was created with. Null
	// where the platform has no per-thread security context.
	//
	virtual CTokenInfoPtr GetToken() const			{ return CTokenInfoPtr(); }
	virtual CTokenInfoPtr GetOriginalToken() const	{ return CTokenInfoPtr(); }

	//
	// The object's access control, for the security dialog. Null when the
	// target cannot offer one - which is what a viewer greys the button on.
	//
	virtual CSecurityEditablePtr GetSecurityObject() const	{ return CSecurityEditablePtr(); }
	virtual bool IsGuiThread() const				{ return false; }
	virtual bool IsFiber() const					{ return false; }
	virtual bool IsSandboxed() const				{ return false; }

	//
	// A sandboxed thread is asked a different question: not what kind of token
	// it has, but whether the box handed it one at all.
	//
	virtual bool HasSandboxToken() const			{ return false; }
	virtual bool IsPowerThrottled() const			{ return false; }
	virtual bool HasPendingIrp() const				{ return false; }
	virtual bool HasRpcState() const				{ return false; }

public slots:
	virtual quint64 TraceStack() = 0;

signals:
	void			StackTraced(const CStackTracePtr& StackTrace);

protected:
	quint64			m_ThreadId;
	quint64			m_ProcessId;

	bool			m_IsMainThread;

	int				m_State;
	int				m_WaitReason;

	float			m_StackUsageFloat;
	quint64			m_StackUsage;
	quint64			m_StackLimit;

	QSharedPointer<QObject>	m_pProcess;

	STaskStats		m_CpuStats;

	SIOStatsEx		m_IoStats;
};

typedef QSharedPointer<CThreadInfo> CThreadPtr;
typedef QWeakPointer<CThreadInfo> CThreadRef;