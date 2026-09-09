#pragma once
#include "SecurityInfo.h"
#include "../taskcore_global.h"
#include <qobject.h>
#include "AbstractInfo.h"
#include "TokenInfo.h"
#include "JobInfo.h"
#include "../../MiscHelpers/Common/Status.h"

class TASKCORE_EXPORT CHandleInfo: public CAbstractInfoEx
{
	Q_OBJECT

	TRACK_OBJECT(CHandleInfo)
public:
	CHandleInfo(QObject *parent = nullptr);
	virtual ~CHandleInfo();

	virtual quint64 GetHandleId() const				{ QReadLocker Locker(&m_Mutex); return m_HandleId; }
	virtual quint64 GetProcessId()	const			{ QReadLocker Locker(&m_Mutex); return m_ProcessId; }

	virtual quint32 GetTypeIndex() const = 0;
	virtual QString GetTypeName() const = 0;

	//
	// Some objects have a second, narrower type - a file handle that is really
	// a named pipe, say. It is a name the platform gave, not a word chosen
	// here, so it comes over as it stands; how the two are put together for
	// reading is the viewer's business.
	//
	virtual QString GetSubTypeName() const			{ return QString(); }
	virtual QString GetFileName() const				{ QReadLocker Locker(&m_Mutex); return m_FileName; }
	virtual quint64 GetPosition() const				{ QReadLocker Locker(&m_Mutex); return m_Position; }
	virtual quint64 GetSize()	const				{ QReadLocker Locker(&m_Mutex); return m_Size; }
	virtual quint32 GetGrantedAccess() const = 0;

	//
	// Which rights the granted-access mask actually grants.
	//
	// A mask alone means nothing without knowing the object type - the same bit
	// is PROCESS_TERMINATE on one kind of object and KEY_NOTIFY on another - so
	// the target reads its own tables and reports the rights it found. What
	// each one is called is then the viewer's business, like every other word.
	//
	virtual QList<int> GetGrantedAccessRights() const	{ return QList<int>(); }

	//
	// The same mask reduced to the four generic rights, which is a reading any
	// client can make once the platform has applied the type's mapping.
	//
	enum EGenericAccess
	{
		eGenericRead	= 0x01,
		eGenericWrite	= 0x02,
		eGenericExecute	= 0x04,
		eGenericAll		= 0x08,
	};
	virtual quint32 GetGenericAccess() const		{ return 0; }

	//
	// How a descriptor was opened, on systems that describe that with open(2)
	// flags rather than an access mask. The values are Linux's own.
	//
	enum EOpenFlag
	{
		eOpenAccessMask		= 0x000003,	// O_ACCMODE
		eOpenReadOnly		= 0x000000,	// O_RDONLY
		eOpenWriteOnly		= 0x000001,	// O_WRONLY
		eOpenReadWrite		= 0x000002,	// O_RDWR

		eOpenCloseOnExec	= 0x080000,	// O_CLOEXEC
		eOpenAppend			= 0x000400,	// O_APPEND
		eOpenNonBlock		= 0x000800,	// O_NONBLOCK
		eOpenDSync			= 0x001000,	// O_DSYNC
		eOpenAsync			= 0x002000,	// O_ASYNC
		eOpenDirect			= 0x004000,	// O_DIRECT
		eOpenDirectory		= 0x010000,	// O_DIRECTORY
		eOpenNoAtime		= 0x040000,	// O_NOATIME
		eOpenPath			= 0x200000,	// O_PATH
		eOpenSync			= 0x101000,	// O_SYNC: O_DSYNC | __O_SYNC, hence not a single bit
	};
	virtual quint32 GetOpenFlags() const			{ return 0; }

	virtual QSharedPointer<QObject>	GetProcess() const;
	//virtual QSharedPointer<QObject>	GetProcess() const { QReadLocker Locker(&m_Mutex); return m_pProcess; }
	virtual void SetProcess(QSharedPointer<QObject> pProcess) { QWriteLocker Locker(&m_Mutex); m_pProcess = pProcess; }

	virtual STATUS		Close(bool bForce = false) = 0;

	//
	// ---- platform surface ----
	//
	// Everything either platform can report, so the models never need to know
	// which one answered. An implementation without the notion does not
	// override; the default below is the honest answer, and whether a column
	// built on it is worth showing is decided by GetOsType()/HasCapability().
	//
	//
	// Acting on the kernel object a handle refers to. Which of these make sense
	// depends on the object's type, and the view enables only the applicable
	// ones; a backend with no such objects overrides nothing.
	//
	enum EHandleAction
	{
		eSemaphoreAcquire,
		eSemaphoreRelease,

		eEventSet,
		eEventReset,
		eEventPulse,

		eSetLow,
		eSetHigh,

		eCancelTimer
	};
	virtual STATUS  DoHandleAction(EHandleAction Action)	{ Q_UNUSED(Action); return ERR(TE_NotSupported); }

	virtual STATUS  SetInherited(bool bSet)			{ Q_UNUSED(bSet); return ERR(TE_NotSupported); }
	virtual STATUS  SetProtected(bool bSet)			{ Q_UNUSED(bSet); return ERR(TE_NotSupported); }

	//
	// The object's whole security descriptor in SDDL, which is a value rather
	// than a reading. Empty when it could not be read.
	//
	virtual QString GetSecurityDescriptorSddl() const { return QString(); }

	// Type-specific detail shown on the handle properties page.
	virtual QVariantMap GetHandleInfo() const		{ return QVariantMap(); }

	// The same, for the mode a file handle was opened with.
	virtual QList<int> GetFileAccessModeRights(quint32 Mode) const { Q_UNUSED(Mode); return QList<int>(); }

	//
	// Two more values carried in GetHandleInfo(). What a section is backed by,
	// and how an ALPC port was set up.
	//
	enum ESectionAttribute
	{
		eSecFile	= 0x00800000,	// SEC_FILE
		eSecImage	= 0x01000000,	// SEC_IMAGE
		eSecReserve	= 0x04000000,	// SEC_RESERVE
		eSecCommit	= 0x08000000,	// SEC_COMMIT
	};

	enum EAlpcPortFlag
	{
		eAlpcLpcMode				= 0x0001000,
		eAlpcAllowImpersonation		= 0x0010000,
		eAlpcAllowLpcRequests		= 0x0020000,
		eAlpcWaitablePort			= 0x0040000,
		eAlpcAllowDupObject			= 0x0080000,
		eAlpcSystemProcess			= 0x0100000,
		eAlpcWakePolicy1			= 0x0200000,
		eAlpcWakePolicy2			= 0x0400000,
		eAlpcWakePolicy3			= 0x0800000,
		eAlpcDirectMessage			= 0x1000000,
		eAlpcAllowMultiHandleAttr	= 0x2000000,
	};

	//
	// The object's access control, for the security dialog. Null when the
	// target cannot offer one - which is what a viewer greys the button on.
	//
	virtual CSecurityEditablePtr GetSecurityObject() const	{ return CSecurityEditablePtr(); }

	//
	// The object this handle refers to, when it is one the GUI can show a view
	// for. Null when the handle is of another type, or when the platform has
	// no such object.
	//
	virtual CTokenInfoPtr GetToken() const			{ return CTokenInfoPtr(); }
	virtual CJobInfoPtr   GetJob() const			{ return CJobInfoPtr(); }

	// Opens the referenced section or device for reading, for the memory editor.
	virtual QIODevice*    OpenDevice() const		{ return NULL; }

	//
	// What the handle refers to is reported by GetFileName() - a path for a
	// file, a key for a registry handle. Revealing it in a file manager or a
	// registry editor happens in front of a person, so the viewer does it; see
	// CSystemAPI::IsLocal.
	//

	virtual quint64 GetObjectAddress() const		{ return 0; }
	virtual QString GetOriginalName() const			{ return QString(); }
	//
	// Handle attributes, as the object-manager numbers them.
	//
	enum EHandleAttribute
	{
		eObjProtectClose	= 0x00000001,	// OBJ_PROTECT_CLOSE
		eObjInherit			= 0x00000002,	// OBJ_INHERIT
	};
	virtual quint32 GetAttributes() const			{ return 0; }
	virtual bool    IsInherited() const				{ return false; }
	virtual bool    IsProtected() const				{ return false; }

	// Sharing mode a file handle was opened with.
	enum EFileShare
	{
		eShareRead		= 0x1,
		eShareWrite		= 0x2,
		eShareDelete	= 0x4,
		eShareMask		= 0x7,
	};
	virtual quint32 GetFileFlags() const			{ return 0; }

protected:
	quint64				m_HandleId;
	quint64				m_ProcessId;

	QString				m_FileName;
	quint64				m_Position;
	quint64				m_Size;

	QSharedPointer<QObject>	m_pProcess;
};

typedef QSharedPointer<CHandleInfo> CHandlePtr;
typedef QWeakPointer<CHandleInfo> CHandleRef;