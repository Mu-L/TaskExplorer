#pragma once
#include "ProcessSecurity.h"
#include "../taskcore_global.h"
#include <qobject.h>
#include "MiscStats.h"
#include "ProcessInfo.h"
#include "SocketInfo.h"
#include "HandleInfo.h"
#include "ServiceInfo.h"
#include "DriverInfo.h"
#include "WndInfo.h"
#include "../../MiscHelpers/Common/Common.h"
#include "Monitors/GpuMonitor.h"
#include "Monitors/NetMonitor.h"
#include "Monitors/DiskMonitor.h"
#include "DNSEntry.h"
#include "RpcInfo.h"
#include "PoolInfo.h"
#include "PersistentPreset.h"

struct SCpuStats
{
	SCpuStats()
	{
		KernelUsage = 0.0f;
		UserUsage = 0.0f;
	}

	SDelta64 KernelDelta;
	SDelta64 UserDelta;
	SDelta64 IdleDelta;

	float KernelUsage;
	float UserUsage;
};

struct SCpuStatsEx : SCpuStats
{
	SDelta32_64 PageFaultsDelta;
	SDelta32_64 PageReadsDelta;
	SDelta32_64 PageFileWritesDelta;
	SDelta32_64 MappedWritesDelta;

	SDelta32_64 PagedAllocsDelta;
	SDelta32_64 PagedFreesDelta;
	SDelta32_64 NonPagedAllocsDelta;
	SDelta32_64 NonPagedFreesDelta;

	SDelta32_64 ContextSwitchesDelta;
	SDelta32_64 InterruptsDelta;
	SDelta64 DpcsDelta;
	SDelta32_64 SystemCallsDelta;
};

struct SPageFile // on linux swap partition
{
	SPageFile()
	{
		TotalSize = 0;
		TotalInUse = 0;
		PeakUsage = 0;
	}

	QString Path;
    quint64 TotalSize;
    quint64 TotalInUse;
    quint64 PeakUsage;
};

//
// QEnableSharedFromThis so an object being collected can be given a weak
// reference to the system that collected it without every collector having to
// carry the CSystemPtr around - see CAbstractInfo::SetSystem.
//
class TASKCORE_EXPORT CSystemAPI : public QObject, public QEnableSharedFromThis<CSystemAPI>
{
	Q_OBJECT

	TRACK_OBJECT(CSystemAPI)
public:

	//
	// Whether this process takes part in the driver's process-creation *gate*.
	//
	// Not whether it is told about process creation - it still is, and that is
	// where the earliest command line and image path come from. This is the
	// other half of the same callback: with it on, the driver waits for our
	// answer before letting a process start and takes a refusal, so the
	// machine's ability to run programs comes to depend on this process being
	// responsive. Watching is an observation; that is a gate.
	//
	// False in the daemon unless [Server] ProcessBlocking says otherwise - see
	// SServerSetup. Here rather than in the Windows backend because the
	// decision belongs to whoever started this process, and that code is the
	// same on both platforms. It means nothing on Linux.
	//
	static void		SetProcessBlockingAllowed(bool bSet);
	static bool		ProcessBlockingAllowed();
	CSystemAPI(QObject *parent = nullptr);
	virtual ~CSystemAPI();

	//
	// Brings up the local, in-process system and publishes it as theSystem.
	// A remote core is reached the other way round - CRemoteSystem connects
	// itself and is handed over - so this stays specifically about the local one.
	//
	static void InitLocalSystem();

	//
	// The remote face of this machine, or null when it is this one.
	//
	// This is what "is this a remote machine" is asked with. It used to be
	// qobject_cast<CRemoteSystem*>, which needs the class - and the class is
	// now in a module that may not be loaded, so the question had to become one
	// this base can answer. A local backend inherits the null and says nothing.
	//
	// See RemoteApi.h. The interface is declared there and forward-declared
	// here on purpose: nothing about a local system should have to include it.
	//
	virtual class IRemoteSystem* GetRemote() { return NULL; }

	virtual bool RootAvaiable() = 0;

	//
	// Which system is being looked at.
	//
	// Not "which system are we compiled for" - with a remote session those are
	// different questions, and every GUI decision that used to be an #ifdef is
	// really asking this one.
	//
	enum EOsType
	{
		eOsWindows,
		eOsLinux
	};
	virtual EOsType GetOsType() const = 0;

	//
	// What to divide a raw CPU-time counter by to get seconds.
	//
	// A property of the system being observed, not of the one running the GUI:
	// Windows counts in 100ns ticks, Linux in scheduler ticks whose rate the
	// kernel decides. Was a per-platform macro, which would have quietly
	// mis-scaled every CPU time column in a remote session.
	//
	virtual quint64 GetCpuTimeDivider() const = 0;

	//
	// The kinds of kernel object a handle can refer to, for the handle view's
	// type filter.
	//
	// Enumerating them is a system query - the object-type table on Windows,
	// the fd kinds on Linux - so the API answers it and the view just builds a
	// combo box from the result. An empty list means the target has no such
	// classification and the filter is hidden.
	//
	struct SHandleType
	{
		QString	Name;
		int		Index = -1;

		//
		// Which set of handles this type belongs to.
		//
		// A machine can have more than one. A Linux machine running Wine has the
		// kernel's descriptors, which every process there has, and wineserver's
		// objects, which only a process inside a prefix can hold - and no
		// process has a handle of a kind from a group it is not in. A view
		// offers a group only for the processes it applies to.
		//
		// The two sets can use the same word for different things - both call
		// something a File - so a view that shows them together says which is
		// which. Which word it uses for that is the view's business; this is the
		// value it decides from.
		//
		int		Group = 0;

		// So a view can tell whether the machine it is now looking at classifies
		// handles the same way the last one did, and skip rebuilding its filter.
		bool operator==(const SHandleType& Other) const
		{ return Index == Other.Index && Group == Other.Group && Name == Other.Name; }
	};
	enum EHandleGroup
	{
		eHandleGroupNative	= 0,	// the kernel's own objects, whatever kernel that is
		eHandleGroupWine	= 1,	// wineserver's, in a prefix on this machine
	};
	virtual QList<SHandleType> GetHandleTypes() const	{ return QList<SHandleType>(); }

	//
	// Which group one type index belongs to, without walking the list.
	//
	// Asked once per handle per refresh by anything that spells out a type, so
	// it has to be cheap; a target with one group answers with the default.
	//
	virtual int GetHandleTypeGroup(int Index) const		{ Q_UNUSED(Index); return eHandleGroupNative; }

	//
	// Machine-wide commands.
	//
	// These act on the target, not on whatever is running the GUI - shutting down
	// or reclaiming memory on a remote box is a legitimate thing to ask for, so
	// they belong here rather than being spelled out at the call site.
	//
	// SoftForce says how hard to push a shutdown: 0 skips the WM_QUERYENDSESSION
	// courtesy entirely, 1 forces, 2 forces only applications that stopped
	// answering.
	//
	enum EPowerAction
	{
		ePowerLock, ePowerLogOff, ePowerSleep, ePowerHibernate,
		ePowerRestart, ePowerRestartToOptions, ePowerShutdown, ePowerHybridShutdown
	};
	virtual STATUS PowerAction(EPowerAction Action, bool bForce, int SoftForce)
														{ Q_UNUSED(Action); Q_UNUSED(bForce); Q_UNUSED(SoftForce); return ERR(TE_NotSupported); }

	enum EMemoryCommand
	{
		eMemEmptyWorkingSets, eMemFlushModifiedList,
		eMemPurgeStandbyList, eMemPurgeLowPriorityStandby, eMemCombinePages
	};
	virtual STATUS MemoryCommand(EMemoryCommand Command)
														{ Q_UNUSED(Command); return ERR(TE_NotSupported); }

	//
	// Security principals the target knows about: LSA accounts, logon sessions,
	// and the SAM's local users and groups. Which fields are filled depends on
	// what the list is - a logon session has an id, a SAM account a relative id.
	//
	struct SPrincipal
	{
		QString		Name;
		QString		SidString;
		QByteArray	Sid;
		quint32		RelativeId = 0;
		quint32		LogonId = 0;
		QString		Comment;
	};
	virtual QList<SPrincipal> EnumLsaAccounts() const	{ return QList<SPrincipal>(); }
	virtual QList<SPrincipal> EnumLogonSessions() const	{ return QList<SPrincipal>(); }
	virtual QList<SPrincipal> EnumSamUsers() const		{ return QList<SPrincipal>(); }
	virtual QList<SPrincipal> EnumSamGroups() const		{ return QList<SPrincipal>(); }

	struct SCredential
	{
		QString	Target;
		QString	User;
		QString	Comment;
		quint64	LastWritten = 0;	// seconds since the epoch
	};
	virtual QList<SCredential> EnumCredentials() const	{ return QList<SCredential>(); }

	//
	// Privileges the target's security authority defines, with the wording it
	// shows for each. The service properties dialog offers these when adding a
	// required privilege.
	//
	struct SPrivilege
	{
		QString	Name;
		QString	DisplayName;
	};
	virtual QList<SPrivilege> EnumPrivileges() const		{ return QList<SPrivilege>(); }

	//
	// Name <-> SID. Only the machine holding the accounts can do this, so it is
	// asked of the target rather than worked out locally.
	//
	virtual QString	LookupSidByName(const QString& Name) const	{ Q_UNUSED(Name); return QString(); }
	virtual QString	LookupNameBySid(const QString& Sid) const	{ Q_UNUSED(Sid); return QString(); }

	//
	// The access control of one of the system's own securable objects - the
	// service manager, the LSA policy, an account. Same dialog as everything
	// else; see SecurityInfo.h.
	//
	enum ESecurityObject { eSecLsaPolicy, eSecLsaAccount, eSecSamUser, eSecSamGroup, eSecServiceManager };
	virtual CSecurityEditablePtr GetSecurityObject(ESecurityObject Type, const QString& Name,
								const QByteArray& Sid = QByteArray(), quint32 RelativeId = 0) const
	{
		Q_UNUSED(Type); Q_UNUSED(Name); Q_UNUSED(Sid); Q_UNUSED(RelativeId);
		return CSecurityEditablePtr();
	}

	//
	// Act on a logged-on session of the target: connect to it, disconnect it, or
	// log it off. Password is only consulted where connecting needs one.
	//
	enum EUserAction { eUserConnect, eUserDisconnect, eUserLogoff };
	virtual STATUS UserSessionAction(quint32 SessionId, EUserAction Action, const QString& Password = QString())
														{ Q_UNUSED(SessionId); Q_UNUSED(Action); Q_UNUSED(Password); return ERR(TE_NotSupported); }

	//
	// The kernel driver's system-wide monitor, where one exists.
	//
	virtual bool IsSystemMonitorOn() const				{ return false; }
	virtual STATUS SetSystemMonitor(bool bEnable)		{ Q_UNUSED(bEnable); return ERR(TE_NotSupported); }

	//
	// Start a program on the target.
	//
	// Elevated false means the process is created with a filtered token where the
	// caller holds the privilege to do so; InjectDll empty means no injection.
	//
	struct SRunOptions
	{
		QString	Program;
		QString	InjectDll;
		bool	Elevated = true;
		bool	Suspended = false;

		//
		// Which logon session to start it in; zero means "wherever this makes
		// sense", which is the caller's own session for an ordinary program and
		// the one somebody is sitting at when the caller is a service.
		//
		// A number rather than a flag because a machine can have several people
		// logged in, and "the interactive one" is then a guess. Nothing offers
		// the choice yet - the run dialog has no session picker - but the wire
		// carries it and the platform honours it.
		//
		quint32	SessionId = 0;
	};
	virtual STATUS RunProgram(const SRunOptions& Options)
														{ Q_UNUSED(Options); return ERR(TE_NotSupported); }

	// Programs previously started on the target, most recent first.
	virtual QStringList GetRunHistory() const			{ return QStringList(); }

	//
	// What the "run as" dialog can offer: accounts to run as, sessions and
	// desktops to run in, and the logon types the platform recognises. All of it
	// describes the target, which is why the dialog cannot fill itself in.
	//
	struct SRunAsChoices
	{
		QStringList						Accounts;
		QList<QPair<QString, quint32> >	Sessions;	// label, session id
		QStringList						Desktops;
		QList<QPair<QString, quint32> >	LogonTypes;	// label, platform logon type
		quint32							CurrentSessionId = 0;
		QString							CurrentDesktop;
	};
	virtual SRunAsChoices GetRunAsChoices() const		{ return SRunAsChoices(); }

	//
	// A service account signs in without a password, so the dialog greys the
	// password box out; which names count is the platform's business.
	//
	virtual bool IsServiceAccount(const QString& UserName) const
														{ Q_UNUSED(UserName); return false; }

	struct SRunAsOptions
	{
		QString	Program;
		QString	UserName;
		QString	Password;
		QString	Desktop;
		quint32	LogonType = 0;
		quint32	SessionId = 0;
		quint64	ParentPid = 0;		// run as the child of this process instead
		bool	UseLinkedToken = false;
		bool	Suspended = false;
	};
	virtual STATUS RunProgramAs(const SRunAsOptions& Options)
														{ Q_UNUSED(Options); return ERR(TE_NotSupported); }

	//
	// Shell integration on the target machine.
	//
	// A remote system has no screen to put a dialog on, so these refuse rather
	// than pretending; the caller shows the error like any other.
	//
	enum ERunDialogMode { eRunNormal, eRunAsUser, eRunAsLimited, eRunAsTrustedInstaller };
	virtual STATUS ShowRunDialog(ERunDialogMode Mode)	{ Q_UNUSED(Mode); return ERR(TE_NotSupported); }
	virtual STATUS RestartElevated()					{ return ERR(TE_NotSupported); }

	//
	// The choices offered when creating a service, which - unlike the ones on
	// CServiceInfo - have to be available before any service object exists.
	//
	virtual CServiceInfo::SLabeledValues GetNewServiceTypes() const			{ return CServiceInfo::SLabeledValues(); }
	virtual CServiceInfo::SLabeledValues GetNewServiceStartTypes() const		{ return CServiceInfo::SLabeledValues(); }
	virtual CServiceInfo::SLabeledValues GetNewServiceErrorControlTypes() const	{ return CServiceInfo::SLabeledValues(); }

	//
	// The main window, by handle value. Some of the native code needs an owner
	// window for its dialogs and notifications; the core takes the number and
	// never learns what a QWidget is.
	//
	virtual void	SetMainWindow(quint64 Wnd)			{ Q_UNUSED(Wnd); }

	//
	// Register a new service with the manager. The dialog collects the values;
	// the SCM call belongs on this side of the wire.
	//
	virtual STATUS CreateNewService(const QString& Name, const QString& DisplayName, const QString& BinaryPath,
									quint32 Type, quint32 StartType, quint32 ErrorControl)
	{
		Q_UNUSED(Name); Q_UNUSED(DisplayName); Q_UNUSED(BinaryPath);
		Q_UNUSED(Type); Q_UNUSED(StartType); Q_UNUSED(ErrorControl);
		return ERR(TE_NotSupported);
	}


	//
	// Native window messages the platform layer wants a look at - phlib posts
	// notifications for the dialogs it owns. Returns true when it consumed one.
	//
	virtual bool HandleNativeNotify(void* pHeader, qintptr* pResult)
														{ Q_UNUSED(pHeader); Q_UNUSED(pResult); return false; }

	// Debug diagnostic: the platform layer's own object counts.
	virtual void DumpObjectCounts() const				{}

	//
	// The machine architecture the target actually runs, as opposed to the one
	// this build was compiled for - a 32-bit process on a 64-bit box, or an x64
	// process under emulation on ARM64, both report the native one.
	//
	enum EArchitecture { eArchUnknown = 0, eArchX86, eArchAmd64, eArchArm64 };
	virtual EArchitecture GetArchitecture() const		{ return eArchUnknown; }

	//
	// Human-readable text for a status code this system produced. The mapping is
	// platform-specific - NTSTATUS on Windows - so it has to be answered by the
	// side that raised the error, not by whatever is running the GUI.
	//
	virtual QString GetStatusMessage(quint32 Status) const
														{ Q_UNUSED(Status); return QString(); }

	//
	// The kernel driver or privileged helper this system is talking to.
	//
	// Weaknesses is a flag set rather than a list of sentences, so the wording is
	// chosen by the view in the reader's language; see EKernelWeakness.
	//
	enum EKernelLevel
	{
		eKernelLevelNone = 0,
		eKernelLevelMin,
		eKernelLevelLow,
		eKernelLevelMed,
		eKernelLevelHigh,
		eKernelLevelMax
	};

	enum EKernelWeakness
	{
		eKsiNotSecurelyCreated		= 0x0001,
		eKsiUnverifiedImage			= 0x0002,
		eKsiInactiveProtections		= 0x0004,
		eKsiUntrustedImages			= 0x0008,
		eKsiBeingDebugged			= 0x0010,
		eKsiWritableFileObject		= 0x0020,
		eKsiNoCreateNotification	= 0x0040,
		eKsiTamperedImage			= 0x0080
	};

	struct SKernelDriver
	{
		bool	Connected = false;
		bool	DynDataLoaded = false;
		int		Level = eKernelLevelNone;
		quint32	Weaknesses = 0;
	};
	virtual SKernelDriver GetKernelDriver() const		{ return SKernelDriver(); }

	// Whether the target accepts test-signed kernel code, and whether code
	// signing is being enforced at all.
	virtual bool IsTestSigning() const					{ return false; }
	virtual bool IsCKSEnabled() const					{ return false; }

	// Hand the driver the version-specific offsets it needs for this kernel.
	virtual STATUS LoadDynData(const QString& DriverPath)
														{ Q_UNUSED(DriverPath); return ERR(TE_NotSupported); }

	//
	// One level of the kernel object namespace.
	//
	// Type is the object type's name as the system calls it, which the view uses
	// to pick an icon and to decide what is a directory worth descending into.
	//
	struct SNtObject
	{
		QString	Name;
		QString	Type;
	};
	virtual QList<SNtObject> EnumObjectDirectory(const QString& Path) const
														{ Q_UNUSED(Path); return QList<SNtObject>(); }

	//
	// The COM running object table, by display name. Collected here rather than
	// in the view because it is machine state like any other - the view used to
	// walk the monikers itself, which no remote target could do.
	//
	virtual QStringList EnumRunningObjects() const		{ return QStringList(); }

	//
	// The global atom table.
	//
	// Values, not rendered text: whether an atom is pinned and whether its entry
	// could be read are flags, so the view decides how to say so in the reader's
	// language rather than the collector deciding in its own.
	//
	struct SAtom
	{
		quint32	Id = 0;
		QString	Name;
		quint32	RefCount = 0;
		bool	Pinned = false;
		bool	Unreadable = false;	// listed in the table, but the entry would not read
	};
	virtual QList<SAtom> GetAtomTable() const			{ return QList<SAtom>(); }
	virtual STATUS DeleteAtom(quint32 AtomId)			{ Q_UNUSED(AtomId); return ERR(TE_NotSupported); }

	//
	// The kernel's page lists, in bytes. Windows reports these directly; a system
	// with no such notion leaves Available false and the panel stays blank rather
	// than showing a column of convincing zeros.
	//
	struct SMemoryList
	{
		bool	Available = false;
		quint64	Zeroed = 0;
		quint64	Free = 0;
		quint64	Modified = 0;
		quint64	ModifiedNoWrite = 0;
		quint64	Bad = 0;
		quint64	StandbyByPriority[8] = {};
		quint64	RepurposedByPriority[8] = {};
	};
	virtual SMemoryList GetMemoryList() const			{ return SMemoryList(); }

	//
	// Reveal a path in the platform's file manager. Lives here rather than being
	// duplicated on every object that has a file name - the objects delegate.
	//
	//
	// Whether this is the machine the program is running on.
	//
	// A few things a viewer offers only make sense there - opening a folder,
	// pointing a registry editor at a key, showing a certificate dialog. They
	// happen on the desk in front of the person looking, so for any other
	// target the viewer refuses rather than doing them to the wrong machine.
	//
	virtual bool IsLocal() const					{ return true; }

	// Index of the "file" type within the above, or -1 where there is none.
	virtual int GetFileHandleTypeIndex() const			{ return -1; }

	//
	// Index of the ETW-registration type, which the handle view offers to hide
	// because a busy process can hold thousands of them. -1 where absent.
	//
	virtual int GetEtwHandleTypeIndex() const			{ return -1; }

	//
	// Cancel an in-flight symbol resolution started by a stack trace. Symbol
	// lookup happens where the images are, so the API owns the job ids.
	//
	virtual void CancelSymbolJob(quint64 JobId)			{ Q_UNUSED(JobId); }

	//
	// Resolve a kernel symbol to an address, asynchronously. Answered by
	// whoever has the symbol files, which for a remote target is the far side.
	// Does nothing where the platform exposes no symbol server.
	//
	virtual void GetAddressFromSymbol(quint64 ProcessId, const QString& Symbol, QObject* pReceiver, const char* pSlot)
														{ Q_UNUSED(ProcessId); Q_UNUSED(Symbol); Q_UNUSED(pReceiver); Q_UNUSED(pSlot); }

	//
	// Resolve an address inside a process to a symbol, asynchronously. Same
	// reasoning as above: the side holding the images answers.
	//
	virtual void GetSymbolFromAddress(quint64 ProcessId, quint64 Address, QObject* pReceiver, const char* pSlot)
														{ Q_UNUSED(ProcessId); Q_UNUSED(Address); Q_UNUSED(pReceiver); Q_UNUSED(pSlot); }

	//
	// User-mode object counts. Windows accounts for GDI and USER handles and
	// top-level windows system wide; systems without those report zero.
	//
	//
	// The pid of the process that represents the kernel itself - 4 on Windows,
	// 0 on Linux where the kernel is not a process. Symbol lookups for kernel
	// variables are made against it.
	//
	//
	// Optional event monitors the target can be asked to run. Which ones exist
	// is reported by HasCapability(); toggling one that is absent is a no-op.
	//
	virtual bool IsMonitoringETW() const				{ return false; }
	virtual void MonitorETW(bool bEnable)				{ Q_UNUSED(bEnable); }
	virtual bool IsMonitoringFW() const					{ return false; }
	virtual void MonitorFW(bool bEnable)				{ Q_UNUSED(bEnable); }

	// Number of processes the collector believes are hiding from enumeration.
	virtual int  FindHiddenProcesses()					{ return -1; }

	//
	// Which sources of debug output the target is capturing, as a bit set.
	// Windows can listen locally, globally and in the kernel; a system with no
	// such facility stays at eDbgNone and refuses to change.
	//
	enum EDebugMonitor
	{
		eDbgNone	= 0,
		eDbgLocal	= 1,
		eDbgGlobal	= 2,
		eDbgKernel	= 4,
		eDbgAll		= eDbgLocal | eDbgGlobal | eDbgKernel,
	};
	//
	// Re-arms whatever one-shot authorisation a backend needs before it may ask
	// the user again - the polkit prompt behind systemd-resolved's cache, for
	// instance. Called when a view that depends on it becomes visible, which is
	// the moment the user has actually asked for the data.
	//
	virtual void AllowAuthPrompt()						{}

	virtual int    GetDebugMonitor() const				{ return eDbgNone; }
	virtual STATUS SetDebugMonitor(int Modes)			{ Q_UNUSED(Modes); return ERR(TE_NotSupported); }

	virtual quint64 GetKernelProcessId() const			{ return 0; }

	virtual quint32 GetTotalGuiObjects() const			{ return 0; }
	virtual quint32 GetTotalUserObjects() const			{ return 0; }
	virtual quint32 GetTotalWndObjects() const			{ return 0; }

	//
	// Pressure stall information: how long work was held up waiting for a
	// resource, averaged over the trailing 10, 60 and 300 seconds. Linux
	// publishes this in /proc/pressure; Valid stays false where it is absent.
	//
	struct SPressure
	{
		float	SomeAvg10 = 0, SomeAvg60 = 0, SomeAvg300 = 0;
		float	FullAvg10 = 0, FullAvg60 = 0, FullAvg300 = 0;
		quint64	SomeTotal = 0, FullTotal = 0;	// cumulative stall, microseconds
		bool	Valid = false;
	};
	virtual SPressure GetCpuPressure() const			{ return SPressure(); }
	virtual SPressure GetMemoryPressure() const			{ return SPressure(); }
	virtual SPressure GetIoPressure() const				{ return SPressure(); }

	//
	// Whether a given facility is actually available for this target.
	//
	// Separate from GetOsType because availability is not implied by platform:
	// ETW needs a session, the pool table needs the driver, memory writes need
	// rights. Locally these already fail at runtime today and the GUI offers
	// them anyway; asking first fixes that as well as serving remote sessions.
	//
	enum ECapability
	{
		eCapEtw,			// ETW event monitoring
		eCapKernelDriver,	// KSystemInformer / equivalent loaded
		eCapFirewallLog,
		eCapPoolTable,		// kernel pool allocation table
		eCapSandboxie,
		eCapSymbols,		// symbol resolution for stack traces
		eCapRoot,			// administrator / root rights
		eCapMemoryRead,
		eCapMemoryWrite,
		eCapProcessDump,
		eCapServiceControl,
		eCapCGroups,		// Linux resource control groups
		eCapExtProcInfo,	// extended per-process counters beyond the basic snapshot
		eCapProcessFreeze,	// per-process freeze/thaw, distinct from suspend
		eCapSecurityEditor,	// access control can be read and written
		eCapAuditEditor,	// the audit list can be read - needs the audit privilege

		//
		// Append above this line only. These values cross the wire - see
		// API_HS_CAPS - and reordering them would have one machine answer a
		// different question from the one the other asked.
		//
		eCapCount
	};
	virtual bool HasCapability(ECapability Capability) const;

	//
	// ---- what a machine can be asked for ----
	//
	// The viewer's name for a kind of answer. A local collector implements
	// whatever it implements and is never asked; a remote one reports its set at
	// the handshake, and a view greys itself with a reason rather than showing
	// an empty list - see CCluster::CanAnswer.
	//
	// Not the wire's numbering. It used to be exactly that: a tab said
	// API_CMD_SOCKETS and the value was compared against what the handshake
	// carried, which put a protocol header in the include list of a tab view.
	// CRemoteSystem translates now, and the raw ids stay on the wire where a
	// packet dump can still read them.
	//
	// Appending is safe; these values are never sent.
	//
	enum EFeature
	{
		eFeatProcesses = 0,
		eFeatSysInfo,
		eFeatServices,
		eFeatDrivers,
		eFeatSockets,
		eFeatOpenFiles,
		eFeatThreads,
		eFeatModules,
		eFeatHandles,
		eFeatWindows,
		eFeatHeaps,
		eFeatMemory,
		eFeatDnsCache,
		eFeatGdi,
		eFeatDevices,

		eFeatCount
	};

	//
	// ---- which per-process fields the viewer is drawing ----
	//
	// Groups rather than columns: a dozen columns are read out of one block, so
	// what a request can usefully turn off is the block. The viewer names these
	// and only these; what they are called on the wire is the wire's business
	// and is nowhere in the GUI.
	//
	// This used to be the wire's own numbering - CProcessModel named
	// API_PROC_CPUTIME and the value went out verbatim - which made a protocol
	// header reachable from a table of columns, and made the two impossible to
	// change apart. CRemoteSystem translates now; a local collector never sees
	// either numbering.
	//
	// Appending is safe. The values are not sent anywhere, so they may be
	// renumbered freely - the wire ids they map to are the ones that must not
	// move.
	//
	enum EProcField
	{
		eFieldUser = 0,
		eFieldCmdLine,
		eFieldPath,
		eFieldSession,
		eFieldThreads,
		eFieldHandles,
		eFieldWorkingSet,
		eFieldCpuTime,
		eFieldIoStats,
		eFieldDiskNet,
		eFieldMemory,
		eFieldCounts,
		eFieldPriority,
		eFieldFlags,
		eFieldMisc,
		eFieldStatus,
		eFieldToken,
		eFieldMitigations,
		eFieldGpu,
		eFieldFileInfo,

		eFieldCount
	};

	//
	// Nothing for a local collector, which reads what it reads; a remote one
	// puts the set in every process request so the far side can skip producing
	// the rest. On the base so the viewer can say it once to every machine
	// without asking what kind each is.
	//
	virtual void SetWantedFields(const QSet<quint32>& Fields) { Q_UNUSED(Fields); }

	//
	// The namespaces of the target's own init process, for deciding whether a
	// process is in a container: anything differing from these is isolated.
	//
	// On the system rather than read from pid 1 by the caller, because "the
	// host" means the machine being watched and not the one doing the watching.
	//
	virtual SProcessNamespaces GetHostNamespaces() const { return SProcessNamespaces(); }


	virtual QMap<quint64, CProcessPtr> GetProcessList();
	virtual QMap<SProcessUID, CProcessPtr> GetProcessMap();
	virtual CProcessPtr GetProcessByID(quint64 ProcessId, bool bAddIfNew = false);
	virtual CThreadPtr  GetThreadByID(quint64 ThreadId);
	virtual CProcessPtr GetProcessByThreadID(quint64 ThreadId);

	virtual QMultiMap<quint64, CSocketPtr> GetSocketList();

	virtual QMap<quint64, CHandlePtr> GetOpenFilesList();

	virtual QMap<QString, CServicePtr> GetServiceList();
	virtual CServicePtr			GetService(const QString& Name);

	//
	// How a service name is filed and looked up, which is not the same question
	// on both platforms.
	//
	// Windows service names are case insensitive, so CWindowsAPI files them
	// lower cased and this is what makes a lookup find them. systemd unit names
	// are case *sensitive* - NetworkManager.service and
	// networkmanager.service are two different units, and only one of them
	// exists - so the Linux backend files them as given and folding a lookup
	// would make every unit with a capital in it unfindable.
	//
	// A virtual rather than an ifdef because a viewer asks this about the
	// machine it is looking at, which may not be the machine it is running on.
	//
	virtual QString				CanonicalServiceName(const QString& Name) const { return Name.toLower(); }

	virtual QMap<QString, CDriverPtr> GetDriverList();

	//
	// Two lists that only a machine with the notion has, and that the views
	// showing them used to reach by casting the system to CWindowsAPI - which
	// is a cast that cannot succeed once the system is a remote one, whatever
	// platform the viewer runs on. Empty here, so a target without them says so
	// by answering rather than by not being asked; whether the tab is worth
	// showing at all is HasCapability's business, as everywhere else.
	//
	virtual QMap<QString, CRpcEndpointPtr> GetRpcTableList() const	{ return QMap<QString, CRpcEndpointPtr>(); }
	virtual QMap<quint64, CPoolEntryPtr> GetPoolTableList() const	{ return QMap<quint64, CPoolEntryPtr>(); }

	virtual SSysStats			GetStats()			{ QReadLocker Locker(&m_StatsMutex); return m_Stats; }

	virtual float GetCpuUsage() const				{ QReadLocker Locker(&m_StatsMutex); return m_CpuStats.KernelUsage + m_CpuStats.UserUsage; }
	virtual float GetCpuDPCUsage() const			{ QReadLocker Locker(&m_StatsMutex); return m_CpuStatsDPCUsage; }
	virtual float GetCpuKernelUsage() const			{ QReadLocker Locker(&m_StatsMutex); return m_CpuStats.KernelUsage; }
	virtual float GetCpuUserUsage() const			{ QReadLocker Locker(&m_StatsMutex); return m_CpuStats.UserUsage; }

	virtual quint64 GetInstalledMemory() const		{ QReadLocker Locker(&m_StatsMutex); return m_InstalledMemory; }
	virtual quint64 GetAvailableMemory() const		{ QReadLocker Locker(&m_StatsMutex); return m_AvailableMemory; }
	virtual quint64 GetCommitedMemory() const		{ QReadLocker Locker(&m_StatsMutex); return m_CommitedMemory; }
	virtual quint64 GetCommitedMemoryPeak() const	{ QReadLocker Locker(&m_StatsMutex); return m_CommitedMemoryPeak; }
	virtual quint64 GetMemoryLimit() const			{ QReadLocker Locker(&m_StatsMutex); return m_MemoryLimit; }
	virtual quint64 GetSwapedOutMemory() const		{ QReadLocker Locker(&m_StatsMutex); return m_SwapedOutMemory; }
	virtual quint64 GetTotalSwapMemory() const		{ QReadLocker Locker(&m_StatsMutex); return m_TotalSwapMemory; }
	virtual quint64 GetPagedPool() const			{ QReadLocker Locker(&m_StatsMutex); return m_PagedPool; }
	virtual quint64 GetPersistentPagedPool() const	{ QReadLocker Locker(&m_StatsMutex); return m_PersistentPagedPool; }
	virtual quint64 GetNonPagedPool() const			{ QReadLocker Locker(&m_StatsMutex); return m_NonPagedPool; }
	virtual quint64 GetPhysicalUsed() const			{ QReadLocker Locker(&m_StatsMutex); return m_PhysicalUsed; }
	virtual quint64 GetCacheMemory() const			{ QReadLocker Locker(&m_StatsMutex); return m_CacheMemory; }
	virtual quint64 GetKernelMemory() const			{ QReadLocker Locker(&m_StatsMutex); return m_KernelMemory; }
	virtual quint64 GetDriverMemory() const			{ QReadLocker Locker(&m_StatsMutex); return m_DriverMemory; }
	virtual quint64 GetReservedMemory() const		{ QReadLocker Locker(&m_StatsMutex); return m_ReservedMemory; }

	virtual quint64 GetTotalProcesses() const		{ QReadLocker Locker(&m_StatsMutex); return m_TotalProcesses; }
	virtual quint64 GetTotalThreads() const			{ QReadLocker Locker(&m_StatsMutex); return m_TotalThreads; }
	virtual quint64 GetTotalHandles() const			{ QReadLocker Locker(&m_StatsMutex); return m_TotalHandles; }

	virtual int GetPackageCount() const				{ QReadLocker Locker(&m_StatsMutex); return m_PackageCount; }
	virtual int GetNumaCount() const				{ QReadLocker Locker(&m_StatsMutex); return m_NumaCount; }
	virtual int GetCoreCount() const				{ QReadLocker Locker(&m_StatsMutex); return m_CoreCount; }
	virtual int GetCpuCount() const					{ QReadLocker Locker(&m_StatsMutex); return m_CpuCount; }
	virtual double GetCpuBaseClock() const			{ QReadLocker Locker(&m_StatsMutex); return m_CpuBaseClock; }
	virtual double GetCpuCurrentClock() const		{ QReadLocker Locker(&m_StatsMutex); return m_CpuCurrentClock; }

	virtual SCpuStatsEx GetCpuStats() const			{ QReadLocker Locker(&m_StatsMutex); return m_CpuStats; }
	virtual SCpuStats GetCpuStats(int Index) const	{ QReadLocker Locker(&m_StatsMutex); return m_CpusStats[Index]; }

	virtual QList<SPageFile> GetPageFiles() const	{ QReadLocker Locker(&m_StatsMutex); return m_PageFiles; }

	virtual QString GetCpuModel() const				{ QReadLocker Locker(&m_Mutex); return m_CPU_String; }

	// The logo of the system being watched, as image file bytes; see
	// CModuleInfo::GetFileIcon for why it is not a pixmap.
	virtual QByteArray GetSystemIcon() const		{ QReadLocker Locker(&m_Mutex); return m_SystemIcon; }
	virtual QString GetSystemName() const			{ QReadLocker Locker(&m_Mutex); return m_SystemName; }
	virtual QString GetSystemType() const			{ QReadLocker Locker(&m_Mutex); return m_SystemType; }
	//
	// The version the target reports for itself, in whatever form it keeps it -
	// a kernel release string on one platform, a pair of numbers on another. The
	// pieces are carried separately where they are numbers, so the viewer can
	// put them together; a platform that has only a string fills that instead.
	//
	virtual QString GetSystemVersion() const		{ QReadLocker Locker(&m_Mutex); return m_SystemVersion; }
	virtual QString GetSystemBuild() const			{ QReadLocker Locker(&m_Mutex); return m_SystemBuild; }

	virtual quint32 GetSystemMajorVersion() const	{ QReadLocker Locker(&m_Mutex); return m_SystemMajor; }
	virtual quint32 GetSystemMinorVersion() const	{ QReadLocker Locker(&m_Mutex); return m_SystemMinor; }
	virtual quint32 GetSystemBuildNumber() const	{ QReadLocker Locker(&m_Mutex); return m_SystemBuildNumber; }
	virtual QString GetSystemReleaseId() const		{ QReadLocker Locker(&m_Mutex); return m_SystemReleaseId; }
	virtual quint64 GetUpTime() const = 0;
	virtual QString GetHostName() const				{ QReadLocker Locker(&m_Mutex); return m_HostName; }
	virtual QString GetUserName() const				{ QReadLocker Locker(&m_Mutex); return m_UserName; }
	virtual QString GetSystemDir() const			{ QReadLocker Locker(&m_Mutex); return m_SystemDir; }

	//
	// What a terminal-services session is doing. The numbering is Windows's
	// WTS_CONNECTSTATE_CLASS; a platform without sessions reports none.
	//
	enum ESessionState
	{
		eSessionActive			= 0,
		eSessionConnected		= 1,
		eSessionConnectQuery	= 2,
		eSessionShadow			= 3,
		eSessionDisconnected	= 4,
		eSessionIdle			= 5,
		eSessionListen			= 6,
		eSessionReset			= 7,
		eSessionDown			= 8,
		eSessionInit			= 9,

		//
		// logind describes a session with a smaller vocabulary of its own. Its
		// "active" means what WTS's does, so that value is shared; the other
		// two sit well clear of the WTS range and cannot collide with it.
		//
		eSessionOnline			= 100,	// logged in, but not the session on screen
		eSessionClosing			= 101,

		eSessionUnknown			= -1,
	};

	struct SUser
	{
		QString UserName;

		//
		// What the platform calls this session, as it calls it.
		//
		// Windows numbers its sessions, so this is that number in text. logind
		// does not: its ids are strings - "2" for an ordinary login, "c1" for a
		// greeter - and reading a number out of one is a lossy guess. "c1" and
		// "c2" both come out as zero, which is not merely wrong on screen: it
		// makes two distinct sessions indistinguishable to anything keyed by the
		// number, and the users submenu was keyed by it. See NEXT.md 5.47.
		//
		// Empty from a server too old to send it, in which case SessionId is all
		// there is - which is what it always was.
		//
		QString SessionKey;

		//
		// The numeric form, which is what UserSessionAction takes. Meaningful on
		// Windows; on Linux it is whatever number the id begins with, or zero,
		// and nothing acts on it there - CLinuxAPI does not implement the action.
		//
		quint32 SessionId = 0;

		// See ESessionState.
		int State = eSessionUnknown;

		//
		// Which seat the session is attached to, where the platform has the
		// notion. Empty means it is not attached to one - a remote login.
		//
		QString Seat;
	};

	virtual QList<SUser> GetUsers() const = 0;

	virtual CGpuMonitor* GetGpuMonitor()			{ return m_pGpuMonitor; }
	virtual CNetMonitor* GetNetMonitor()			{ return m_pNetMonitor; }
	virtual CDiskMonitor* GetDiskMonitor()			{ return m_pDiskMonitor; }

	void AddThread(CThreadPtr pThread);
	void ClearThread(quint64 ThreadId);

	virtual bool UpdateOpenFileListAsync();

	virtual void NotifyHardwareChanged();

	virtual QMultiMap<QString, CDnsCacheEntryPtr> GetDnsEntryList() const = 0;

	virtual void LoadPersistentPresets();
	virtual void StorePersistentPresets();

	virtual void SetPersistentPresets(const QList<CPersistentPresetDataPtr>& PersistentPreset);
	virtual QList<CPersistentPresetDataPtr> GetPersistentPresets() const;
	virtual CPersistentPresetPtr FindPersistentPreset(const QString& FileName, const QString& CommandLine = QString());
	virtual bool AddPersistentPreset(const QString& FileName);
	virtual bool RemovePersistentPreset(const QString& FileName);

	virtual void ResetAll();

public slots:
	virtual bool UpdateAll() = 0;
	virtual bool UpdateSysStats() = 0;
	virtual bool UpdateProcessList() = 0;
	virtual bool UpdateSocketList() = 0;
	virtual bool UpdateOpenFileList() = 0;
	virtual bool UpdateServiceList(bool bRefresh = false) = 0;
	virtual bool UpdateDriverList() = 0;

	virtual void ClearPersistence() = 0;

	virtual bool UpdateDnsCache() = 0;
	virtual void FlushDnsCache() = 0;

	virtual void ApplyPersistentPresets();

private slots:
	virtual bool Init() = 0;
	virtual void OnOpenFilesUpdated();
	virtual void OnHardwareChanged() = 0;

signals:
	void ProcessListUpdated(QSet<quint64> Added, QSet<quint64> Changed, QSet<quint64> Removed);
	void SocketListUpdated(QSet<quint64> Added, QSet<quint64> Changed, QSet<quint64> Removed);
	void OpenFileListUpdated(QSet<quint64> Added, QSet<quint64> Changed, QSet<quint64> Removed);
	void ServiceListUpdated(QSet<QString> Added, QSet<QString> Changed, QSet<QString> Removed);
	void DriverListUpdated(QSet<QString> Added, QSet<QString> Changed, QSet<QString> Removed);

	void DnsCacheUpdated();

	//
	// Progress text from long-running background work - symbol downloads and
	// the like - for the status bar.
	//
	void StatusMessage(const QString& Message);

	//
	// ---- what only a remote machine ever emits ----
	//
	// Declared on the base rather than on CRemoteSystem because the cluster
	// connects to them, and the cluster must not need the remote class to do
	// that. A local system never emits any of the three.
	//
	// The connection to a machine went away.
	//
	void ConnectionLost();

	//
	// A dropped connection came back, on the same object. Nothing about the
	// machine's identity in the viewer changes - which is the point of retrying
	// on the same system rather than building a new one.
	//
	void Reconnected();

	//
	// An automatic attempt reached something and refused it. Carries the code
	// rather than a sentence, as everything in the core does.
	//
	// Separate from simply failing to reconnect: a machine that is down should
	// be tried again, and a machine that is somebody else should not be tried
	// again at all until a person has looked at it.
	//
	void ReconnectRefused(quint32 MsgCode);

protected:
	//virtual void				UpdateStats();

	mutable QReadWriteLock		m_ProcessMutex;
	QMap<quint64, CProcessPtr>	m_ProcessByPID;
	QMap<SProcessUID, CProcessPtr>	m_ProcessMap;

	mutable QReadWriteLock		m_SocketMutex;
	QMultiMap<quint64, CSocketPtr>	m_SocketList;

	mutable QReadWriteLock		m_OpenFilesMutex;
	QMap<quint64, CHandlePtr>	m_OpenFilesList;

	mutable QReadWriteLock		m_ServiceMutex;
	QMap<QString, CServicePtr>	m_ServiceList;

	mutable QReadWriteLock		m_DriverMutex;
	QMap<QString, CDriverPtr>	m_DriverList;

	// Guard it with m_ProcessMutex
	QHash<quint64, CThreadRef>	m_ThreadMap;

	mutable QReadWriteLock		m_Mutex;

	CGpuMonitor*				m_pGpuMonitor;
	CNetMonitor*				m_pNetMonitor;
	CDiskMonitor*				m_pDiskMonitor;

	// I/O stats
	mutable QReadWriteLock		m_StatsMutex;
	SSysStats					m_Stats;

	int							m_PackageCount;
	int							m_NumaCount;
	int							m_CoreCount;
	int							m_CpuCount;
	double						m_CpuBaseClock;
	double						m_CpuCurrentClock;

	SCpuStatsEx					m_CpuStats;
	float						m_CpuStatsDPCUsage;

	quint64						m_InstalledMemory;
	quint64						m_AvailableMemory;
	quint64						m_CommitedMemory;
	quint64						m_CommitedMemoryPeak;
	quint64						m_MemoryLimit;
	quint64						m_SwapedOutMemory;
	quint64						m_TotalSwapMemory;
	quint64						m_PagedPool;
	quint64						m_PersistentPagedPool;
	quint64						m_NonPagedPool;
	quint64						m_PhysicalUsed;
	quint64						m_CacheMemory;
	quint64						m_KernelMemory;
	quint64						m_DriverMemory;
	quint64						m_ReservedMemory;

	quint32						m_TotalProcesses;
	quint32						m_TotalThreads;
	quint32						m_TotalHandles;

	QVector<SCpuStats>			m_CpusStats;

	QList<SPageFile>			m_PageFiles;
	
	// guard this once with m_Mutex
	QString						m_CPU_String;
	QByteArray					m_SystemIcon;
	QString						m_SystemName;
	QString						m_SystemType;
	QString						m_SystemVersion;
	QString						m_SystemBuild;

	quint32						m_SystemMajor = 0;
	quint32						m_SystemMinor = 0;
	quint32						m_SystemBuildNumber = 0;
	QString						m_SystemReleaseId;
	QString						m_HostName;
	QString						m_UserName;
	QString						m_SystemDir;

	volatile bool				m_HardwareChangePending;

	static bool					UpdateOpenFileListAsync(CSystemAPI* This);
	QFutureWatcher<bool>*		m_FileListUpdateWatcher;

	QMap<QString, CPersistentPresetPtr>	m_PersistentPresets;
	mutable QReadWriteLock		m_PersistentMutex;
};

typedef QSharedPointer<CSystemAPI> CSystemPtr;

//
// The system in view: the local machine in-process, a local core over a pipe,
// or a remote core over the network. Refcounted like every other object in the
// tree, so it needs no owner above it to stay alive - which is what lets
// theCluster (see Cluster.h) be absent entirely in the ordinary single-machine
// case.
//
// Objects observed on a system point back at it with a raw CSystemAPI* rather
// than a CSystemPtr; see CAbstractInfo::GetSystem() for why.
//
extern TASKCORE_EXPORT CSystemPtr		theSystem;
