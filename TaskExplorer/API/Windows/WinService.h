#pragma once
#include "../ServiceInfo.h"

class CWinService : public CServiceInfo
{
	Q_OBJECT

	TRACK_OBJECT(CWinService)
public:
	CWinService(QObject *parent = nullptr);
	CWinService(const QString& Name, QObject *parent = nullptr);
	virtual ~CWinService();

	virtual quint32 GetType() const					{ QReadLocker Locker(&m_Mutex); return m_Type; }
	virtual quint32 GetState() const				{ QReadLocker Locker(&m_Mutex); return m_State; }
	virtual quint32 GetControlsAccepted() const		{ QReadLocker Locker(&m_Mutex); return m_ControlsAccepted; }
	virtual quint32 GetFlags() const				{ QReadLocker Locker(&m_Mutex); return m_Flags; }
	//
	// SERVICE_RUNS_IN_SYSTEM_PROCESS, named. The editor asks the base this
	// rather than testing the flag word itself.
	//
	virtual bool	RunsInSystemProcess() const;

	virtual quint32 GetWin32ExitCode() const		{ QReadLocker Locker(&m_Mutex); return m_Win32ExitCode; }
	virtual quint32 GetServiceSpecificExitCode() const { QReadLocker Locker(&m_Mutex); return m_ServiceSpecificExitCode; }

	virtual bool IsStopped() const;
	virtual bool IsRunning(bool bStrict = false) const;
	virtual bool IsPaused() const;

	virtual bool IsDriver() const;

	virtual quint32 GetStartType() const			{ QReadLocker Locker(&m_Mutex); return m_StartType; }
	virtual quint32 GetErrorControl() const			{ QReadLocker Locker(&m_Mutex); return m_ErrorControl; }

	virtual QString GetGroupeName() const			{ QReadLocker Locker(&m_Mutex); return m_GroupeName; }
	virtual QString GetDescription() const			{ QReadLocker Locker(&m_Mutex); return m_Description; }

	virtual bool	GetConfig(SConfig& Config) const;
	virtual STATUS	SetConfig(const SConfig& Config);
	virtual bool	GetRecovery(SRecovery& Recovery) const;
	virtual STATUS	SetRecovery(const SRecovery& Recovery);
	virtual bool	GetExtras(SExtras& Extras) const;
	virtual STATUS	SetExtras(const SExtras& Extras);
	virtual QStringList GetDependents() const;

	virtual QList<STrigger> GetTriggers() const;
	virtual STATUS	SetTriggers(const QList<STrigger>& Triggers, bool bHadTriggers);
	virtual QList<STriggerSubtype> GetTriggerSubtypes() const;
	virtual QList<QPair<QString, quint32> > GetTriggerTypes() const;
	virtual QStringList GetEtwPublishers() const;
	virtual SLabeledValues GetServiceTypes() const;
	virtual SLabeledValues GetStartTypes() const;
	virtual SLabeledValues GetErrorControlTypes() const;
	virtual SLabeledValues GetRecoveryActionTypes() const;
	virtual SLabeledValues GetSidTypes() const;
	virtual SLabeledValues GetLaunchProtectionTypes() const;
	virtual QString	GetEtwPublisherName(const QString& Guid) const;
	virtual QString	GetEtwPublisherGuid(const QString& Name) const;
	virtual void	GetTriggerStrings(const STrigger& Trigger, QString& Description, QString& Action) const;

	virtual STATUS Start();
	virtual STATUS Pause();
	virtual STATUS Continue();
	virtual STATUS Stop();
	virtual STATUS Delete(bool bForce = false);

	virtual QString GetRegistryKey() const;
	virtual bool    HasRegistryKey() const			{ return true; }
	virtual CSecurityEditablePtr GetSecurityObject() const;

public slots:
	void			OnAsyncDataDone(bool IsPacked, quint32 ImportFunctions, quint32 ImportModules);

protected:
	friend class CWindowsAPI;

	bool InitStaticData(struct _ENUM_SERVICE_STATUS_PROCESSW* service);
	bool UpdatePID(struct _ENUM_SERVICE_STATUS_PROCESSW* service);
	bool UpdateDynamicData(void* pscManagerHandle, struct _ENUM_SERVICE_STATUS_PROCESSW* service, bool bRefresh);
	void UnInit();

	quint32							m_Type;
	quint32							m_State;
	quint32							m_ControlsAccepted;
	quint32							m_Flags;

	// Config
	quint32							m_StartType;
	quint32							m_ErrorControl;

	// ExitCode
	quint32							m_Win32ExitCode;
	quint32							m_ServiceSpecificExitCode;

	QString							m_GroupeName;
	QString							m_Description;

	quint64							m_KeyLastWriteTime;

	struct SWinService* m;
};
