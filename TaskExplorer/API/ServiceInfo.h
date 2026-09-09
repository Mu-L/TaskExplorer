#pragma once
#include "SecurityInfo.h"
#include <qobject.h>
#include "AbstractInfo.h"

#include "ModuleInfo.h"

class TASKCORE_EXPORT CServiceInfo: public CAbstractInfoEx
{
	Q_OBJECT

	TRACK_OBJECT(CServiceInfo)
public:
	CServiceInfo(QObject *parent = nullptr);
	virtual ~CServiceInfo();

	virtual QString GetName() const					{ QReadLocker Locker(&m_Mutex); return m_SvcName; }
	virtual QString GetFileName() const				{ QReadLocker Locker(&m_Mutex); return m_FileName; }
	virtual QString GetBinaryPath() const			{ QReadLocker Locker(&m_Mutex); return m_BinaryPath; }
	virtual QString GetDisplayName() const			{ QReadLocker Locker(&m_Mutex); return m_DisplayName; }

	virtual quint64 GetPID() const					{ QReadLocker Locker(&m_Mutex); return m_ProcessId; }


	virtual bool IsStopped() const = 0;
	virtual bool IsRunning(bool bStrict = false) const = 0;
	virtual bool IsPaused() const = 0;
	//
	// Service run state and which control requests it will accept. The values
	// are the Win32 SERVICE_* numbers; systemd states are mapped onto the same
	// scale by the Linux backend, so the view has one vocabulary to reason in.
	//
	enum EServiceState
	{
		eSvcStopped			= 1,
		eSvcStartPending	= 2,
		eSvcStopPending		= 3,
		eSvcRunning			= 4,
		eSvcContinuePending	= 5,
		eSvcPausePending	= 6,
		eSvcPaused			= 7,
	};
	enum EServiceControls
	{
		eSvcAcceptStop			= 0x0001,
		eSvcAcceptPauseContinue	= 0x0002,
	};
	virtual quint32 GetState() const				{ return 0; }
	virtual quint32 GetControlsAccepted() const		{ return 0; }

	//
	// The Windows service vocabulary, by the numbers the platform itself uses -
	// WinService.cpp asserts that they still match. A systemd unit has no such
	// enumeration; it reports free-form state names, so a Linux service answers
	// with GetStateName() below instead.
	//
	enum EServiceType
	{
		eSvcKernelDriver		= 0x001,
		eSvcFileSystemDriver	= 0x002,
		eSvcOwnProcess			= 0x010,
		eSvcShareProcess		= 0x020,
		eSvcUserOwnProcess		= 0x050,
		eSvcUserShareProcess	= 0x060,
		eSvcInteractive			= 0x100,
		eSvcUserServiceInstance	= 0x080,
	};

	enum EServiceStartType
	{
		eSvcBootStart	= 0,
		eSvcSystemStart	= 1,
		eSvcAutoStart	= 2,
		eSvcDemandStart	= 3,
		eSvcDisabled	= 4,
	};

	enum EServiceErrorControl
	{
		eSvcErrorIgnore		= 0,
		eSvcErrorNormal		= 1,
		eSvcErrorSevere		= 2,
		eSvcErrorCritical	= 3,
	};

	//
	// What a target with no such enumeration calls the state - systemd's
	// "active (running)" and the like. Empty on Windows, where GetState() says
	// everything.
	//
	virtual QString GetStateName() const				{ return QString(); }

	virtual quint32 GetType() const						{ return 0; }
	virtual quint32 GetStartType() const				{ return 0; }
	virtual quint32 GetErrorControl() const				{ return 0; }

	virtual CModulePtr GetModuleInfo()			{ QReadLocker Locker(&m_Mutex); return m_pModuleInfo; }

	virtual STATUS Start() = 0;
	virtual STATUS Pause() = 0;
	virtual STATUS Continue() = 0;
	virtual STATUS Stop() = 0;
	virtual STATUS Delete(bool bForce = false) = 0;

	//
	// ---- platform surface ----
	//
	// Everything either platform can report, so the models never need to know
	// which one answered. An implementation without the notion does not
	// override; the default below is the honest answer, and whether a column
	// built on it is worth showing is decided by GetOsType()/HasCapability().
	//
	virtual QString GetGroupeName() const			{ return QString(); }
	virtual QString GetDescription() const			{ return QString(); }
	virtual bool    IsDriver() const				{ return false; }

	//
	// Where a service's configuration and output live. Windows keeps the
	// configuration under a registry key; systemd sends output to the journal.
	// Each backend opens whichever it has, and reports unavailable otherwise.
	//
	//
	// Where the service's configuration lives, for a viewer that wants to show
	// it. A path into the target's registry - which is a fact about the target,
	// so it is reported here; opening an editor on it is not.
	//
	virtual QString GetRegistryKey() const			{ return QString(); }
	virtual STATUS  ViewLog() const					{ return ERR(TE_NotSupported); }
	virtual bool    HasRegistryKey() const			{ return false; }
	virtual bool    HasLog() const					{ return false; }

	// Exit codes reported for a stopped service.
	virtual quint32 GetWin32ExitCode() const			{ return 0; }
	virtual quint32 GetServiceSpecificExitCode() const	{ return 0; }

	//
	// ---- the service properties dialog, as data ----
	//
	// Reading or writing a service's configuration means holding a handle from
	// the service control manager of the machine the service lives on, so it all
	// belongs here rather than in the dialog.
	//
	// The numeric fields keep the platform's own values (SERVICE_*, SC_ACTION_*).
	// There is no portable vocabulary for them, and the dialog presents them
	// through combo boxes it fills from the same source.
	//

	//
	// SetPassword / SetDependencies exist because the platform distinguishes
	// "leave this alone" from "set it to nothing", and a plain field cannot say
	// which is meant. Leaving them false is the safe default: the value is not
	// written at all.
	//
	struct SConfig
	{
		quint32		Type = 0;
		quint32		StartType = 0;
		quint32		ErrorControl = 0;
		QString		BinaryPath;
		QString		LoadOrderGroup;
		QString		StartName;			// the account the service runs as
		QString		Description;
		QString		ServiceDll;			// for a service hosted in a shared process
		bool		DelayedStart = false;

		QStringList	Dependencies;
		bool		SetDependencies = false;

		QString		Password;
		bool		SetPassword = false;
	};
	virtual bool	GetConfig(SConfig& Config) const	{ Q_UNUSED(Config); return false; }
	virtual STATUS	SetConfig(const SConfig& Config)	{ Q_UNUSED(Config); return ERR(TE_NotSupported); }

	//
	// What happens after the service fails, the first, second and every
	// subsequent time. HasNonCrashFlag says whether the target reports the
	// "also act on clean but unexpected exits" flag at all.
	//
	struct SRecoveryAction
	{
		quint32	Type = 0;			// SC_ACTION_*
		quint32	Delay = 0;			// milliseconds
	};
	struct SRecovery
	{
		quint32					ResetPeriod = 0;	// seconds
		QString					RebootMessage;
		QString					CommandLine;
		QList<SRecoveryAction>	Actions;
		quint32					ActionCount = 0;	// as configured, may exceed Actions
		bool					NonCrashFailures = false;
		bool					HasNonCrashFlag = false;
	};
	virtual bool	GetRecovery(SRecovery& Recovery) const	{ Q_UNUSED(Recovery); return false; }
	virtual STATUS	SetRecovery(const SRecovery& Recovery)	{ Q_UNUSED(Recovery); return ERR(TE_NotSupported); }

	//
	// The remaining page. Each Has* says whether the target supports that
	// setting; where it does not, the field is neither shown nor written.
	//
	struct SExtras
	{
		QString		SidString;
		QStringList	Privileges;
		quint32		SidType = 0;
		quint32		LaunchProtected = 0;
		quint32		PreShutdownTimeout = 0;
		bool		HasPrivileges = false;
		bool		HasSidType = false;
		bool		HasLaunchProtected = false;
		bool		HasPreShutdownTimeout = false;
	};
	virtual bool	GetExtras(SExtras& Extras) const	{ Q_UNUSED(Extras); return false; }
	virtual STATUS	SetExtras(const SExtras& Extras)	{ Q_UNUSED(Extras); return ERR(TE_NotSupported); }

	// Services that depend on this one.
	virtual QStringList GetDependents() const			{ return QStringList(); }

	//
	// Whether this service runs inside a process it does not own - a shared
	// host, in other words. Such a service cannot have its own failure actions,
	// because the process it would restart belongs to somebody else.
	//
	// The notion rather than the flag word: Windows says this with
	// SERVICE_RUNS_IN_SYSTEM_PROCESS, systemd with Type=notify inside a shared
	// unit, and neither number means anything to the other.
	//
	virtual bool	RunsInSystemProcess() const			{ return false; }

	//
	// Triggers: conditions under which the system starts or stops the service.
	//
	// A trigger names a type (a device arriving, a network endpoint appearing, an
	// ETW provider firing), a subtype identifying which one, and any number of
	// data items that narrow it further.
	//
	struct STriggerData
	{
		quint32		Type = 0;			// SERVICE_TRIGGER_DATA_TYPE_*
		QString		String;
		QByteArray	Binary;
		quint64		Number = 0;			// a level, or a keyword mask
	};
	struct STrigger
	{
		quint32				Type = 0;	// SERVICE_TRIGGER_TYPE_*
		quint32				Action = 0;	// start or stop
		QString				Subtype;	// GUID, as text
		QList<STriggerData>	Data;
	};
	virtual QList<STrigger> GetTriggers() const			{ return QList<STrigger>(); }

	//
	// bHadTriggers matters: asking to write an empty trigger set to a service
	// that never had one is an error on Windows, so the caller says whether
	// there was anything there to begin with.
	//
	virtual STATUS	SetTriggers(const QList<STrigger>& Triggers, bool bHadTriggers)
														{ Q_UNUSED(Triggers); Q_UNUSED(bHadTriggers); return ERR(TE_NotSupported); }

	//
	// The named subtypes the target knows, so the editor can offer them by name
	// instead of by GUID. Empty Guid means "any".
	//
	struct STriggerSubtype
	{
		quint32	TriggerType = 0;
		QString	Name;
		QString	Guid;
	};
	virtual QList<STriggerSubtype> GetTriggerSubtypes() const	{ return QList<STriggerSubtype>(); }
	// the trigger types the target recognises, by name
	virtual QList<QPair<QString, quint32> > GetTriggerTypes() const
													{ return QList<QPair<QString, quint32> >(); }

	// Custom triggers name an ETW provider; these two turn GUIDs into names.
	virtual QStringList GetEtwPublishers() const		{ return QStringList(); }

	//
	// Label/value tables for the dialog's combo boxes. Platform terms with no
	// portable equivalent, so they come from the target along with everything
	// else it describes.
	//
	//
	// A choice offered in a combo: what it reads as, and what it is worth.
	// Named separately because foreach cannot see past the comma.
	//
	typedef QPair<QString, quint32> SLabeledValue;
	typedef QList<SLabeledValue> SLabeledValues;
	virtual SLabeledValues GetServiceTypes() const		{ return SLabeledValues(); }
	virtual SLabeledValues GetStartTypes() const		{ return SLabeledValues(); }
	virtual SLabeledValues GetErrorControlTypes() const	{ return SLabeledValues(); }
	virtual SLabeledValues GetRecoveryActionTypes() const	{ return SLabeledValues(); }
	virtual SLabeledValues GetSidTypes() const				{ return SLabeledValues(); }
	virtual SLabeledValues GetLaunchProtectionTypes() const	{ return SLabeledValues(); }

	//
	// The service's access control, for the security dialog. Null when the
	// target cannot offer one - which is what a viewer greys the button on.
	//
	virtual CSecurityEditablePtr GetSecurityObject() const	{ return CSecurityEditablePtr(); }
	virtual QString	GetEtwPublisherName(const QString& Guid) const
														{ Q_UNUSED(Guid); return QString(); }
	virtual QString	GetEtwPublisherGuid(const QString& Name) const
														{ Q_UNUSED(Name); return QString(); }

	//
	// How a trigger reads in a list. A decoder like any other - see the note in
	// the sequencing plan about moving these down to the base once the constants
	// are portable.
	//
	virtual void	GetTriggerStrings(const STrigger& Trigger, QString& Description, QString& Action) const
														{ Q_UNUSED(Trigger); Q_UNUSED(Description); Q_UNUSED(Action); }

protected:

	QString							m_SvcName;
	QString							m_FileName;
	QString							m_BinaryPath;
	QString							m_DisplayName;

	quint64							m_ProcessId;

	CModulePtr						m_pModuleInfo;
};

typedef QSharedPointer<CServiceInfo> CServicePtr;
typedef QWeakPointer<CServiceInfo> CServiceRef;