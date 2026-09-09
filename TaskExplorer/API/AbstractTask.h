#pragma once
#include "../taskcore_global.h"
#include <qobject.h>
#include "../../MiscHelpers/Common/Common.h"
#include "../../MiscHelpers/Common/Status.h"
#include "AbstractInfo.h"
#include "MiscStats.h"

struct STimeUsage
{
	STimeUsage()
	{
		Usage = 0;
	}

	void			Calculate(quint64 totalTime)
	{
		if (!totalTime)
			return;

		Usage = (float)Delta.Delta / totalTime;

		if (Usage > 1)
			Usage = 1;
	}

	SDelta64 		Delta;
	float			Usage; 
};

struct TASKCORE_EXPORT STaskStats
{
	STaskStats()
	{
		CpuUsage = 0.0f;
		CpuKernelUsage = 0.0f;
		CpuUserUsage = 0.0f;
	}

	void			UpdateStats(quint64 sysTotalTime, quint64 sysTotalCycleTime = 0);

	SDelta64 		CpuKernelDelta;
	SDelta64 		CpuUserDelta;
	SDelta64 		CycleDelta;
	SDelta32_64 	ContextSwitchesDelta;

	float			CpuUsage; 
	float			CpuKernelUsage;
	float			CpuUserUsage;
};

class TASKCORE_EXPORT CAbstractTask : public CAbstractInfoEx
{
	Q_OBJECT

public:
	//
	// The kernel's own numbering, repeated here so a viewer on any platform can
	// read a value collected on another. These are protocol, not local detail.
	//
	enum ESchedPolicy
	{
		eSchedOther		= 0,
		eSchedFifo		= 1,
		eSchedRr		= 2,
		eSchedBatch		= 3,
		eSchedIdle		= 5,
		eSchedDeadline	= 6,
	};

	//
	// A Linux I/O priority packs a class and a level into one value.
	//
	enum EIoPrioClass
	{
		eIoPrioNone			= 0,
		eIoPrioRealtime		= 1,
		eIoPrioBestEffort	= 2,
		eIoPrioIdle			= 3,
	};
	static const int eIoPrioClassShift = 13;
	static const int eIoPrioLevelMask = (1 << eIoPrioClassShift) - 1;

	CAbstractTask(QObject *parent = nullptr);
	virtual ~CAbstractTask();
	
	virtual quint64 GetKernelTime()	const			{ QReadLocker Locker(&m_Mutex); return m_KernelTime; }
	virtual quint64 GetUserTime()	const			{ QReadLocker Locker(&m_Mutex); return m_UserTime; }

	virtual QString GetName() const = 0;
	virtual bool HasPriorityBoost() const = 0;
	virtual STATUS SetPriorityBoost(bool Value) = 0;
	//
	// Priority is reported as the target numbers it, not as a word. The two
	// platforms do not mean the same things by these - Windows has priority
	// classes and page priorities, Linux has nice values and no page priority
	// at all - so the value travels with the target's meaning intact and
	// GUI/TaskStrings.cpp picks the reading to match. See ESchedPolicy below.
	//
	virtual qint32 GetPriority()	const				{ QReadLocker Locker(&m_Mutex); return m_Priority; }
	virtual STATUS SetPriority(qint32 Value) = 0;
	virtual qint32 GetBasePriority()	const			{ QReadLocker Locker(&m_Mutex); return m_BasePriority; }
	virtual STATUS SetBasePriority(qint32 Value) = 0;
	virtual qint32 GetPagePriority() const			{ QReadLocker Locker(&m_Mutex); return m_PagePriority; }
	virtual STATUS SetPagePriority(qint32 Value) = 0;
	virtual qint32 GetIOPriority() const				{ QReadLocker Locker(&m_Mutex); return m_IOPriority; }
	virtual STATUS SetIOPriority(qint32 Value) = 0;

	//
	// The scheduling policy, which only Linux has; -1 where the target has no
	// such notion. It is what a Linux target shows as its base priority.
	//
	virtual qint32 GetSchedPolicy() const				{ return -1; }

	virtual quint64 GetAffinityMask() const				{ QReadLocker Locker(&m_Mutex); return m_AffinityMask; }
	virtual STATUS SetAffinityMask(quint64 Value) = 0;

	virtual STATUS Terminate(bool bForce) = 0;

	virtual bool IsSuspended() const = 0;
	virtual STATUS Suspend() = 0;
	virtual STATUS Resume() = 0;


protected:
	quint64						m_KernelTime;
	quint64						m_UserTime;

	long						m_Priority;
    long						m_BasePriority;
	long						m_PagePriority;
	long						m_IOPriority;

	quint64						m_AffinityMask;

	mutable QReadWriteLock		m_StatsMutex;
};


typedef QSharedPointer<CAbstractTask> CTaskPtr;
typedef QWeakPointer<CAbstractTask> CTaskRef;