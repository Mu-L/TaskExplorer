#pragma once
#include <qobject.h>
#include "../../../MiscHelpers/Common/Status.h"
#include "../ProcessInfo.h"
#include "../AbstractInfo.h"
#include "../JobInfo.h"

class CWinJob : public CJobInfo
{
	Q_OBJECT

	TRACK_OBJECT(CWinJob)
public:
	CWinJob(QObject *parent = nullptr);
	virtual ~CWinJob();

	static CWinJob*	JobFromProcess(const CSystemPtr& pSystem, void* QueryHandle);
	static CWinJob*	JobFromHandle(const CSystemPtr& pSystem, quint64 ProcessId, quint64 HandleId);

	virtual QString			GetJobName() const { QReadLocker Locker(&m_Mutex); return m_JobName; }

	virtual QMap<quint64, CProcessPtr>	GetProcesses() const { QReadLocker Locker(&m_Mutex); return m_Processes; }

	virtual quint32			GetActiveProcesses() const { QReadLocker Locker(&m_Mutex); return m_ActiveProcesses; }
	virtual quint32			GetTotalProcesses() const { QReadLocker Locker(&m_Mutex); return m_TotalProcesses; }
	virtual quint32			GetTerminatedProcesses() const { QReadLocker Locker(&m_Mutex); return m_TerminatedProcesses; }

	virtual quint32			GetPeakProcessMemoryUsed() const { QReadLocker Locker(&m_Mutex); return m_PeakProcessMemoryUsed; }
	virtual quint32			GetPeakJobMemoryUsed() const { QReadLocker Locker(&m_Mutex); return m_PeakJobMemoryUsed; }

	virtual SJobStats		GetStats() const { QReadLocker Locker(&m_Mutex);  return m_Stats; }

	virtual QList<SJobLimit> GetLimits() const { QReadLocker Locker(&m_Mutex);  return m_Limits; }

	virtual STATUS			Terminate();
	virtual STATUS			Freeze(bool bFreeze);
	virtual STATUS			AddProcess(quint64 ProcessId);

	virtual CSecurityEditablePtr GetSecurityObject() const;

	enum EQueryType
	{
		eProcess = 0,
		eHandle
	};

protected:
	friend class CWinProcess;
	friend class CJobView;

	bool InitStaticData();
	bool UpdateDynamicData();

	QString				m_JobName;

	quint32				m_ActiveProcesses;
	quint32				m_TotalProcesses;
	quint32				m_TerminatedProcesses;

	quint64				m_PeakProcessMemoryUsed;
	quint64				m_PeakJobMemoryUsed;

	SJobStats			m_Stats;

	QList<SJobLimit>	m_Limits;

	QMap<quint64, CProcessPtr>	m_Processes;

private:
	struct SWinJob*		m;
};


typedef QSharedPointer<CWinJob> CWinJobPtr;
