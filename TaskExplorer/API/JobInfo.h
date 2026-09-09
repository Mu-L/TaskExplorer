#pragma once
#include "SecurityInfo.h"
#include "../taskcore_global.h"
#include <qobject.h>
#include "../../MiscHelpers/Common/Status.h"
#include "AbstractInfo.h"
#include "MiscStats.h"

//
// Forward declared rather than included: CHandleInfo includes this header to
// offer GetJob(), and ProcessInfo.h includes CHandleInfo - pulling the process
// header in here would close that loop.
//
class CProcessInfo;
typedef QSharedPointer<CProcessInfo> CProcessPtr;

//
// A group of processes managed and accounted for as a unit.
//
// On Windows this is a job object; the closest Linux counterpart is a cgroup,
// which is the same idea - a set of processes carrying shared limits and
// shared accounting. The two report different limits, so this class is the
// union of what either can say rather than their intersection.
//

struct SJobStats
{
	SJobStats()
	{
		LastStatUpdate = GetCurTick();
	}

	bool UpdateStats()
	{
		quint64 curTick = GetCurTick();
		quint64 time_ms = curTick - LastStatUpdate;
		LastStatUpdate = curTick;

		Io.UpdateStats(time_ms);

		return true;
	}

	SDelta64	KernelDelta;
	SDelta64	UserDelta;

	SDelta32_64 	PageFaultsDelta;

	quint64		LastStatUpdate;

	SIOStatsEx	Io;
};

class TASKCORE_EXPORT CJobInfo : public CAbstractInfo
{
	Q_OBJECT

public:
	CJobInfo(QObject *parent = nullptr) : CAbstractInfo(parent) {}
	virtual ~CJobInfo() {}

	virtual QString			GetJobName() const			{ return QString(); }

	virtual QMap<quint64, CProcessPtr>	GetProcesses() const { return QMap<quint64, CProcessPtr>(); }

	virtual quint32			GetActiveProcesses() const		{ return 0; }
	virtual quint32			GetTotalProcesses() const		{ return 0; }
	virtual quint32			GetTerminatedProcesses() const	{ return 0; }

	virtual quint32			GetPeakProcessMemoryUsed() const{ return 0; }
	virtual quint32			GetPeakJobMemoryUsed() const	{ return 0; }

	virtual SJobStats		GetStats() const				{ return SJobStats(); }

	//
	// One configured limit, as a name and a typed value. Kept generic because
	// the two platforms limit entirely different things - a job object caps
	// handles and UI access, a cgroup caps memory and cpu shares - and the
	// view only needs to render name/value pairs.
	//
	//
	// One row of a job's limit table: which limit, how to read its value, and
	// the value. Both the limit and the reading are codes, so the whole table
	// crosses the wire as numbers and is worded by the viewer.
	//
	struct SJobLimit
	{
		enum EType
		{
			eString,
			eSize,
			eTimeMs,
			eAddress,
			eNumber,
			ePriorityClass,	// a Windows process priority class, named by the viewer
			eEnabled,
			eLimited
		};

		//
		// The limits Windows lets a job impose. The first group caps a
		// resource; the second forbids a class of action outright, and those
		// all read as eLimited with no number to show.
		//
		enum EWhich
		{
			eLimitUnknown = 0,

			eLimitActiveProcesses,
			eLimitAffinity,
			eLimitBreakawayOk,
			eLimitDieOnUnhandledException,
			eLimitJobMemory,
			eLimitJobTime,
			eLimitKillOnJobClose,
			eLimitPriorityClass,
			eLimitProcessMemory,
			eLimitProcessTime,
			eLimitSchedulingClass,
			eLimitSilentBreakawayOk,
			eLimitWorkingSetMinimum,
			eLimitWorkingSetMaximum,

			eLimitDesktop,
			eLimitDisplaySettings,
			eLimitExitWindows,
			eLimitGlobalAtoms,
			eLimitHandles,
			eLimitReadClipboard,
			eLimitSystemParameters,
			eLimitWriteClipboard,
		};

		SJobLimit(EWhich which, EType type, const QVariant& value)
		{
			Which = which;
			Type = type;
			Value = value;
		}

		EWhich Which;
		EType Type;
		QVariant Value;
	};

	virtual QList<SJobLimit> GetLimits() const			{ return QList<SJobLimit>(); }

	virtual STATUS			Terminate()					{ return ERR(TE_NotSupported); }
	virtual STATUS			Freeze(bool bFreeze)		{ Q_UNUSED(bFreeze); return ERR(TE_NotSupported); }
	virtual STATUS			AddProcess(quint64 ProcessId) { Q_UNUSED(ProcessId); return ERR(TE_NotSupported); }

	//
	// The object's access control, for the security dialog. Null when the
	// target cannot offer one - which is what a viewer greys the button on.
	//
	virtual CSecurityEditablePtr GetSecurityObject() const	{ return CSecurityEditablePtr(); }

public slots:
	virtual bool			UpdateDynamicData()			{ return false; }
};

typedef QSharedPointer<CJobInfo> CJobInfoPtr;
typedef QWeakPointer<CJobInfo> CJobInfoRef;
