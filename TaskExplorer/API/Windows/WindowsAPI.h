#pragma once

#define USE_KRABS
//#define USE_ETW_FILE_IO

#include "../SystemAPI.h"
#include "WinProcess.h"
#include "WinSocket.h"
#ifdef USE_KRABS
#include "Monitors/EtwEventMonitor.h"
#else
#include "Monitors/EventMonitor.h"
#endif
#include "Monitors/FwEventMonitor.h"
//#include "Monitors/FirewallMonitor.h"
#include "Monitors/WinDbgMonitor.h"
#include "SandboxieAPI.h"
#include "SidResolver.h"
#include "SymbolProvider.h"
#include "DnsResolver.h"
#include "WinService.h"
#include "WinDriver.h"
#include "WinWnd.h"
#include "WinPoolEntry.h"
#include "RpcEndpoint.h"

enum MISC_WIN_EVENT_TYPE
{
	// ETW Disk events
	EtwDiskReadType = 1,
	EtwDiskWriteType,
	
	// ETW File I/O events
	EtwFileNameType,
	EtwFileCreateType,
	EtwFileDeleteType,
	EtwFileRundownType,
	
	// ETW Network events
	EtwNetworkReceiveType,
	EtwNetworkSendType,

	// Process Events
	EtwProcessStarted,
	EtwProcessStopped,

	// EventLog Firewall events
	EvlFirewallAllowed,
	EvlFirewallBlocked,

	EventTypeUnknow = ULONG_MAX
};


class CWindowsAPI : public CSystemAPI
{
	Q_OBJECT

	TRACK_OBJECT(CWindowsAPI)
public:
	CWindowsAPI(QObject *parent = nullptr);
	virtual ~CWindowsAPI();

	virtual bool Init();

	//virtual QPair<QString, QString> SelectDriver();
	//virtual STATUS InitDriver(QString DeviceName, QString FileName);
	//virtual STATUS InitHackerDriver();

	virtual bool RootAvaiable();

	virtual EOsType GetOsType() const					{ return eOsWindows; }
	virtual quint64 GetCpuTimeDivider() const;   // CPU_TIME_DIVIDER, defined below the class
	virtual void GetSymbolFromAddress(quint64 ProcessId, quint64 Address, QObject* pReceiver, const char* pSlot);

	virtual STATUS PowerAction(EPowerAction Action, bool bForce, int SoftForce);
	virtual STATUS MemoryCommand(EMemoryCommand Command);
	virtual QList<SPrincipal> EnumLsaAccounts() const;
	virtual QList<SPrincipal> EnumLogonSessions() const;
	virtual QList<SPrincipal> EnumSamUsers() const;
	virtual QList<SPrincipal> EnumSamGroups() const;
	virtual QList<SCredential> EnumCredentials() const;
	virtual QList<SPrivilege> EnumPrivileges() const;
	virtual CSecurityEditablePtr GetSecurityObject(ESecurityObject Type, const QString& Name,
								const QByteArray& Sid = QByteArray(), quint32 RelativeId = 0) const;

	virtual STATUS UserSessionAction(quint32 SessionId, EUserAction Action, const QString& Password = QString());
	virtual bool IsSystemMonitorOn() const;
	virtual STATUS SetSystemMonitor(bool bEnable);
	virtual STATUS RunProgram(const SRunOptions& Options);
	virtual QStringList GetRunHistory() const;
	virtual SRunAsChoices GetRunAsChoices() const;
	virtual bool IsServiceAccount(const QString& UserName) const;
	virtual STATUS RunProgramAs(const SRunAsOptions& Options);
	virtual STATUS ShowRunDialog(ERunDialogMode Mode);
	virtual STATUS RestartElevated();
	virtual QStringList EnumRunningObjects() const;

	virtual QString LookupSidByName(const QString& Name) const;
	virtual QString LookupNameBySid(const QString& Sid) const;


	virtual CServiceInfo::SLabeledValues GetNewServiceTypes() const;
	virtual CServiceInfo::SLabeledValues GetNewServiceStartTypes() const;
	virtual CServiceInfo::SLabeledValues GetNewServiceErrorControlTypes() const;

	virtual void	SetMainWindow(quint64 Wnd);
	virtual STATUS CreateNewService(const QString& Name, const QString& DisplayName, const QString& BinaryPath,
									quint32 Type, quint32 StartType, quint32 ErrorControl);
	virtual bool HandleNativeNotify(void* pHeader, qintptr* pResult);
	virtual void DumpObjectCounts() const;

	virtual EArchitecture GetArchitecture() const;
	virtual QString GetStatusMessage(quint32 Status) const;
	virtual SKernelDriver GetKernelDriver() const;
	virtual STATUS LoadDynData(const QString& DriverPath);

	virtual QList<SNtObject> EnumObjectDirectory(const QString& Path) const;

	virtual QList<SAtom> GetAtomTable() const;
	virtual STATUS DeleteAtom(quint32 AtomId);

	virtual SMemoryList GetMemoryList() const;


	virtual QList<SHandleType> GetHandleTypes() const;
	virtual int GetFileHandleTypeIndex() const;
	virtual int GetEtwHandleTypeIndex() const;
	virtual void CancelSymbolJob(quint64 JobId);
	virtual void GetAddressFromSymbol(quint64 ProcessId, const QString& Symbol, QObject* pReceiver, const char* pSlot);
	virtual quint64 GetKernelProcessId() const;
	virtual int    GetDebugMonitor() const;
	virtual STATUS SetDebugMonitor(int Modes);
	virtual bool HasCapability(ECapability Capability) const;

	virtual CProcessPtr GetProcessByID(quint64 ProcessId, bool bAddIfNew = false);

	virtual bool UpdateAll();

	virtual bool UpdateSysStats();

	virtual bool UpdateProcessList();

	virtual int FindHiddenProcesses();

	virtual bool UpdateSocketList();

	virtual CSocketPtr FindSocket(quint64 ProcessId, quint32 ProtocolType, const QHostAddress& LocalAddress, quint16 LocalPort, const QHostAddress& RemoteAddress, quint16 RemotePort, CSocketInfo::EMatchMode Mode);

	virtual bool UpdateOpenFileList();

	virtual bool UpdateServiceList(bool bRefresh = false);

	virtual bool UpdateDriverList();

	virtual void ClearPersistence();

	virtual CSymbolProvider* GetSymbolProvider()		{ return m_pSymbolProvider; }

	virtual CSidResolver* GetSidResolver()				{ return m_pSidResolver; }

	virtual CDnsResolver* GetDnsResolver()				{ return m_pDnsResolver; }

	virtual CSandboxieAPI* GetSandboxieAPI()			{ return m_pSandboxieAPI; }

	virtual bool UpdateDnsCache();
	virtual void FlushDnsCache();

	virtual quint64	GetCpuIdleCycleTime(int index);

	virtual quint32 GetTotalGuiObjects() const			{ QReadLocker Locker(&m_StatsMutex); return m_TotalGuiObjects; }
	virtual quint32 GetTotalUserObjects() const			{ QReadLocker Locker(&m_StatsMutex); return m_TotalUserObjects; }
	virtual quint32 GetTotalWndObjects() const			{ QReadLocker Locker(&m_StatsMutex); return m_TotalWndObjects; }

	virtual QMultiMap<quint64, quint64> GetWindowByPID(quint64 ProcessId) const  { QReadLocker Locker(&m_WindowMutex); return m_WindowMap[ProcessId]; }

	virtual QList<QString> GetServicesByPID(quint64 ProcessId) const			 { QReadLocker Locker(&m_ServiceMutex); return m_ServiceByPID.value(ProcessId); }

	virtual quint64 GetUpTime() const;

	virtual QList<SUser> GetUsers() const;

	virtual bool HasExtProcInfo() const;

	virtual void MonitorETW(bool bEnable);
	virtual bool IsMonitoringETW() const				{ return m_pEventMonitor != NULL; }

	virtual void MonitorFW(bool bEnable);
	virtual bool IsMonitoringFW() const					{ return m_pFirewallMonitor != NULL; }

	virtual STATUS MonitorDbg(CWinDbgMonitor::EModes Mode);
	virtual CWinDbgMonitor::EModes GetDbgMonitor() const{ return m_pDebugMonitor ? m_pDebugMonitor->GetMode() : CWinDbgMonitor::eNone; }

	

	virtual bool IsTestSigning() const					{ QReadLocker Locker(&m_Mutex); return m_bTestSigning; }
	virtual bool IsCKSEnabled() const					{ QReadLocker Locker(&m_Mutex); return m_bCKSEnabled; }

	//virtual bool HasDriverFailed() const				{ QReadLocker Locker(&m_Mutex); return m_uDriverStatus != 0; }
	//virtual quint32 GetDriverStatus() const				{ QReadLocker Locker(&m_Mutex); return m_uDriverStatus; }
	//virtual quint32 GetDriverFeatures() const			{ QReadLocker Locker(&m_Mutex); return m_uDriverFeatures; }
	//virtual QString GetDriverFileName() const			{ QReadLocker Locker(&m_Mutex); return m_DriverFileName; }
	//virtual QString GetDriverDeviceName() const			{ QReadLocker Locker(&m_Mutex); return m_DriverDeviceName; }

	//__inline bool UseDiskCounters() const				{ return m_UseDiskCounters != eDontUse; }
	__inline bool UseDiskCounters() const				{ return m_UseDiskCounters; }

	virtual QMultiMap<QString, CDnsCacheEntryPtr> GetDnsEntryList() const;

	virtual QMap<QString, CRpcEndpointPtr> GetRpcTableList() const { QReadLocker Locker(&m_RpcTableMutex); return m_RpcTableList; }

	virtual QMap<quint64, CPoolEntryPtr> GetPoolTableList() const { QReadLocker Locker(&m_PoolTableMutex); return m_PoolTableList; }

	virtual bool UpdateThreads(CWinProcess* pProcess);

signals:
	void		RpcListUpdated(QSet<QString> Added, QSet<QString> Changed, QSet<QString> Removed);
	void		PoolListUpdated(QSet<quint64> Added, QSet<quint64> Changed, QSet<quint64> Removed);

public slots:
	void		OnNetworkEvent(int Type, quint64 ProcessId, quint64 ThreadId, quint32 ProtocolType, quint32 TransferSize,
								QHostAddress LocalAddress, quint16 LocalPort, QHostAddress RemoteAddress, quint16 RemotePort);
	void		OnDnsResEvent(quint64 ProcessId, quint64 ThreadId, const QString& HostName, const QStringList& Result);
	void		OnFileEvent(int Type, quint64 FileId, quint64 ProcessId, quint64 ThreadId, const QString& FileName);
	void		OnDiskEvent(int Type, quint64 FileId, quint64 ProcessId, quint64 ThreadId, quint32 IrpFlags, quint32 TransferSize, quint64 HighResResponseTime);
	void		OnProcessEvent(int Type, quint32 ProcessId, QString CommandLine, QString FileName, quint32 ParentId, quint64 TimeStamp);

	void		OnDebugMessage(quint64 PID, const QString& Message, const QDateTime& TimeStamp);

	bool		UpdateRpcList();
	bool		UpdatePoolTable();

protected:
	virtual void OnHardwareChanged();

	quint32		EnumWindows();

	void		AddNetworkIO(int Type, quint32 TransferSize, bool bLAN);
	void		AddDiskIO(int Type, quint32 TransferSize);

	bool		InitWindowsInfo();

	QSharedPointer<CWinProcess> TryAddProcessByID_NoLock(quint64 ProcessId);

#ifdef USE_ETW_FILE_IO
	QString		GetFileNameByID(quint64 FileId) const;
#endif

#ifdef USE_KRABS
	CEtwEventMonitor*		m_pEventMonitor;
#else
	CEventMonitor*			m_pEventMonitor;
#endif
	CFwEventMonitor*		m_pFirewallMonitor;
	//CFirewallMonitor*		m_pFirewallMonitor;
	friend void KernelDebugLogger(const QString& Output);
	CWinDbgMonitor*			m_pDebugMonitor;

	CSandboxieAPI*			m_pSandboxieAPI;

#ifdef USE_ETW_FILE_IO
	mutable QReadWriteLock	m_FileNameMutex;
	QMap<quint64, QString>	m_FileNames;
#endif

	// Guard it with		m_OpenFilesMutex
	//QMultiMap<quint64, CHandleRef> m_HandleByObject;

	// Guard it with m_ServiceMutex
	QMap<quint64, QList<QString> > m_ServiceByPID;

	CSymbolProvider*		m_pSymbolProvider;

	CSidResolver*			m_pSidResolver;

	CDnsResolver*			m_pDnsResolver;
	

	// Guard it with		m_StatsMutex
	quint32					m_TotalGuiObjects;
	quint32					m_TotalUserObjects;
	quint32					m_TotalWndObjects;


	/*enum EUseDiskCounters
	{
		eDontUse = 0,
		eForProgramsOnly,
		eUseForSystem
	};
	volatile EUseDiskCounters m_UseDiskCounters;*/
	volatile bool			m_UseDiskCounters;

	mutable QReadWriteLock	m_WindowMutex;
	QHash<quint64, QMultiMap<quint64, quint64> > m_WindowMap; // <pid<tid,hwnd>>
	QHash<quint64, QPair<quint64, quint64> > m_WindowRevMap;

	//bool						m_RpcUpdatePending;
	mutable QReadWriteLock		m_RpcTableMutex;
	QMap<QString, CRpcEndpointPtr>m_RpcTableList;

	mutable QReadWriteLock		m_PoolTableMutex;
	QMap<quint64, CPoolEntryPtr>m_PoolTableList;

private:
	void UpdatePerfStats();
	void UpdateSambaStats();
	quint64 UpdateCpuStats(bool SetCpuUsage);
	quint64 UpdateCpuCycleStats();
	void UpdateCPUCycles(quint64 TotalCycleTime, quint64 IdleCycleTime);
	bool InitCpuCount();

	bool UpdateRpcList(void* server, void* protocol, QMap<QString, CRpcEndpointPtr>& OldRpcTableList, QSet<QString>& Added, QSet<QString>& Changed);

	bool m_bTestSigning;
	bool m_bCKSEnabled;

	//quint32 m_uDriverStatus;
	//quint32 m_uDriverFeatures;
	//QString m_DriverFileName;
	//QString m_DriverDeviceName;

	struct SWindowsAPI* m;
};

extern quint32 g_fileObjectTypeIndex;
extern quint32 g_EtwRegistrationTypeIndex;

#define CPU_TIME_DIVIDER (10 * 1000 * 1000) // the clock resolution is 100ns we need 1sec

quint64 FILETIME2ms(quint64 fileTime);
time_t FILETIME2time(quint64 fileTime);

QString GetPathFromCmd(QString commandLine, quint32 processID, QString imageName/*, DateTime timeStamp*/, quint32 parentID = 0);

QString expandEnvStrings(const QString &command);

//
// Start a program inside a given logon session.
//
// A process only starts in the session its token says, so a service - which
// lives in session 0 with no desktop and nobody looking at it - cannot start
// anything a person will see by asking the ordinary way. It has to build a
// token for the session it means.
//
// Two routes, because two callers are entitled by different means.
// WTSQueryUserToken is the direct one and wants SeTcbPrivilege, which
// LocalSystem has; an elevated administrator does not, and borrows the token of
// a process already in the session instead, which wants SeDebugPrivilege - and
// that one an administrator does have. Neither grants anything: both produce
// the token that session is already running under.
//
// bLinkedToken asks for the *unfiltered* token where the session's user has
// one, which is what an elevated program in that session would run with. It is
// not an escalation - getting this far already required being LocalSystem or an
// elevated administrator - but it is not the default either, because a program
// somebody asked to run unelevated should run unelevated.
//
STATUS StartProcessInSession(quint32 SessionId, const QString& CommandLine,
							 bool bLinkedToken, quint64* pProcessId = NULL);

//
// Which session a person is actually sitting at, or -1 when nobody is.
//
quint32 GetInteractiveSessionId();

//
// Whether this process is somewhere a started program would be seen.
//
// Session 0 is reserved for services and has no interactive desktop, so a
// program started there runs where nobody can look at it - which is not an
// error and produces no error, and is exactly the trap this exists to name.
//
bool IsInInteractiveSession();