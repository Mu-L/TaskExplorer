#pragma once
#include "SecurityInfo.h"
#include "../taskcore_global.h"
#include <qobject.h>
#include "../../MiscHelpers/Common/Status.h"
#include "AbstractInfo.h"

//
// The security context a task runs under.
//
// On Windows this is an access token; on Linux it is the process credential
// set - uid/gid, capabilities, the LSM label. The two have a thin genuinely
// common core (who, which groups, which session, is it privileged) and a large
// disjoint remainder, so this class is the union of both rather than their
// intersection: everything either platform can report is declared here, and an
// implementation that has no such concept simply does not override it.
//
// The GUI names only this type. Whether it is holding a CWinToken collected
// locally, or a remote one filled from a packet, is not its concern.
//

#undef GetUserName

#define VIRTUALIZATION_NOT_ALLOWED	0x00
#define VIRTUALIZATION_ALLOWED		0x01
#define VIRTUALIZATION_ENABLED		0x02

class TASKCORE_EXPORT CTokenInfo : public CAbstractInfo
{
	Q_OBJECT

public:
	CTokenInfo(QObject *parent = nullptr) : CAbstractInfo(parent) {}
	virtual ~CTokenInfo() {}

	//
	// A group membership. On Windows a SID with its attributes, on Linux a
	// supplementary gid; Sid carries whichever identifier the platform uses.
	//
	struct SGroup
	{
		QByteArray Sid;
		bool Restricted = false;
		QString Name;
		quint32 Attributes = 0;

		//
		// Resolved by whoever collected the group, not by whoever displays it.
		// Turning a SID into text needs the authority database of the machine
		// the process runs on, so a viewer looking at another system cannot do
		// it - and a local viewer should not be doing lookups on the UI thread
		// either.
		//
		QString SidString;		// S-1-5-...
		QString AccountType;	// NT Authority, Local, ...

		// What the authority said the SID names; see ESidType.
		quint8 Use = 0;
	};

	//
	// What kind of thing a SID names. Windows's SID_NAME_USE, which starts at 1
	// and leaves 0 for "nobody said".
	//
	enum ESidType
	{
		eSidNotResolved		= 0,
		eSidUser			= 1,
		eSidGroup			= 2,
		eSidDomain			= 3,
		eSidAlias			= 4,
		eSidWellKnownGroup	= 5,
		eSidDeletedAccount	= 6,
		eSidInvalid			= 7,
		eSidUnknown			= 8,
		eSidComputer		= 9,
		eSidLabel			= 10,
		eSidLogonSession	= 11,
	};

	//
	// A privilege on Windows, a capability on Linux. Both are a named right
	// that is either present, enabled, or absent.
	//
	struct SPrivilege
	{
		QString Name;
		quint32 Attributes = 0;
		quint32 lLuid = 0;
		qint32 hLuid = 0;
		QString Description;
	};

	enum EAction
	{
		eEnable,
		eDisable,
		eReset,
		eRemove
	};

	// ---- identity ----
	virtual QString			GetUserName() const					{ return QString(); }
	virtual QByteArray		GetUserSid(bool bReal = false) const { Q_UNUSED(bReal); return QByteArray(); }
	virtual QString			GetSidString() const				{ return QString(); }
	virtual quint32			GetSessionId() const				{ return 0; }
	virtual QString			GetOwnerName() const				{ return QString(); }
	virtual QByteArray		GetOwnerSid() const					{ return QByteArray(); }
	virtual QString			GetGroupName() const				{ return QString(); }
	virtual QByteArray		GetGroupSid() const					{ return QByteArray(); }

	// ---- privilege level ----
	virtual bool			IsElevated() const					{ return false; }

	enum EElevationType
	{
		eElevationDefault	= 1,	// TokenElevationTypeDefault: UAC is off, or this is not a split token
		eElevationFull		= 2,	// TokenElevationTypeFull
		eElevationLimited	= 3,	// TokenElevationTypeLimited
	};
	virtual int				GetElevationType() const			{ return 0; }

	//
	// Windows integrity level. Linux has no direct counterpart; the closest
	// notion - the LSM confinement - is reported through GetConfinement on the
	// process itself rather than pretended to be an integrity level here.
	//
	//
	// Mandatory integrity levels, as the RID values the platform uses. Spelled
	// out here rather than taken from a Windows header so the token tab can
	// offer the list against a remote Windows target from any client.
	//
	enum EIntegrityLevel
	{
		eIntegrityUntrusted		= 0x0000,
		eIntegrityLow			= 0x1000,
		eIntegrityMedium		= 0x2000,
		eIntegrityMediumPlus	= 0x2100,
		eIntegrityHigh			= 0x3000,
		eIntegritySystem		= 0x4000,
		eIntegrityProtected		= 0x5000,
	};

	virtual quint32			GetIntegrityLevel() const			{ return 0; }
	virtual STATUS			SetIntegrityLevel(quint32 IntegrityLevel) const { Q_UNUSED(IntegrityLevel); return ERR(TE_NotSupported); }

	// ---- groups and privileges ----
	//
	// The attribute masks SGroup and SPrivilege carry. These are fixed Win32 ABI
	// values, spelled out so that a client with no windows.h can read a Windows
	// target's token tab; the Windows backend asserts them against the real
	// SE_* constants, so the two cannot drift.
	//
	enum EPrivilegeAttribute
	{
		ePrivilegeEnabledByDefault	= 0x00000001,	// SE_PRIVILEGE_ENABLED_BY_DEFAULT
		ePrivilegeEnabled			= 0x00000002,	// SE_PRIVILEGE_ENABLED
		ePrivilegeRemoved			= 0x00000004,	// SE_PRIVILEGE_REMOVED
		ePrivilegeUsedForAccess		= 0x80000000,	// SE_PRIVILEGE_USED_FOR_ACCESS
	};

	enum EGroupAttribute
	{
		eGroupMandatory			= 0x00000001,	// SE_GROUP_MANDATORY
		eGroupEnabledByDefault	= 0x00000002,	// SE_GROUP_ENABLED_BY_DEFAULT
		eGroupEnabled			= 0x00000004,	// SE_GROUP_ENABLED
		eGroupOwner				= 0x00000008,	// SE_GROUP_OWNER
		eGroupUseForDenyOnly	= 0x00000010,	// SE_GROUP_USE_FOR_DENY_ONLY
		eGroupIntegrity			= 0x00000020,	// SE_GROUP_INTEGRITY
		eGroupIntegrityEnabled	= 0x00000040,	// SE_GROUP_INTEGRITY_ENABLED
		eGroupResource			= 0x20000000,	// SE_GROUP_RESOURCE
		eGroupLogonId			= 0xC0000000,	// SE_GROUP_LOGON_ID
	};

	//
	// Security-attribute types and flags, shared between the CLAIM_* and TOKEN_*
	// families that spell the same values two ways.
	//
	enum ESecurityAttributeType
	{
		eSecAttrInvalid		= 0x00,
		eSecAttrInt64		= 0x01,
		eSecAttrUInt64		= 0x02,
		eSecAttrString		= 0x03,
		eSecAttrFqbn		= 0x04,
		eSecAttrSid			= 0x05,
		eSecAttrBoolean		= 0x06,
		eSecAttrOctetString	= 0x10,
	};

	enum ESecurityAttributeFlag
	{
		eSecAttrNonInheritable		= 0x0001,
		eSecAttrValueCaseSensitive	= 0x0002,
		eSecAttrUseForDenyOnly		= 0x0004,
		eSecAttrDisabledByDefault	= 0x0008,
		eSecAttrDisabled			= 0x0010,
		eSecAttrMandatory			= 0x0020,
		eSecAttrCompareIgnore		= 0x0040,
	};

	static bool				IsGroupEnabled(quint32 Attributes);
	static bool				IsGroupModified(quint32 Attributes);

	static bool				IsPrivilegeEnabled(quint32 Attributes);
	static bool				IsPrivilegeModified(quint32 Attributes);

	virtual QMap<QByteArray, SGroup>	GetGroups() const		{ return QMap<QByteArray, SGroup>(); }
	virtual QMap<QString, SPrivilege>	GetPrivileges() const	{ return QMap<QString, SPrivilege>(); }

	virtual STATUS			PrivilegeAction(const SPrivilege& Privilege, EAction Action, bool bForce = false)
																{ Q_UNUSED(Privilege); Q_UNUSED(Action); Q_UNUSED(bForce); return ERR(TE_NotSupported); }
	virtual STATUS			GroupAction(const SGroup& Group, EAction Action)
																{ Q_UNUSED(Group); Q_UNUSED(Action); return ERR(TE_NotSupported); }

	// ---- Windows: UAC file and registry virtualization ----
	virtual int				GetVirtualization() const			{ return VIRTUALIZATION_NOT_ALLOWED; }
	virtual bool			IsVirtualizationAllowed() const		{ return (GetVirtualization() & VIRTUALIZATION_ALLOWED) != 0; }
	virtual bool			IsVirtualizationEnabled() const		{ return (GetVirtualization() & VIRTUALIZATION_ENABLED) != 0; }
	virtual STATUS			SetVirtualizationEnabled(bool bSet)	{ Q_UNUSED(bSet); return ERR(TE_NotSupported); }

	// ---- Windows: AppContainer ----
	virtual bool			IsAppContainer() const				{ return false; }
	virtual QString			GetContainerName() const			{ return QString(); }

	//
	// The token's access control, or that of the process default token, which
	// is a separate descriptor on the same object.
	//
	virtual CSecurityEditablePtr GetSecurityObject(bool bDefaultToken = false) const
													{ Q_UNUSED(bDefaultToken); return CSecurityEditablePtr(); }

	virtual QSharedPointer<CTokenInfo> GetLinkedToken()			{ return QSharedPointer<CTokenInfo>(); }

	//
	// The long tail shown on the token tab's advanced page. Windows fills most
	// of it; other platforms fill what they have and leave the rest empty.
	//
	struct SAdvancedInfo
	{
		QString sourceName;
		QString sourceLuid;

		// See ETokenType and EImpersonationLevel.
		quint8 tokenType = 0;
		qint8 tokenImpersonationLevel = -1;

		quint32 tokenLuid = 0;
		quint32 authenticationLuid = 0;
		quint32 tokenModifiedLuid = 0;

		quint64 memoryUsed = 0;
		quint64 memoryAvailable = 0;

		quint32 tokenOriginLogonSession = 0;

		QString tokenNamedObjectPath;
		QString tokenSecurityDescriptor;

		QString tokenTrustLevelSid;
		QString tokenTrustLevelName;

		QString tokenLogonName;
		QString tokenLogonSid;

		QString tokenProfilePath;
		QString tokenProfileRegistry;
	};

	//
	// A token is either the one a process runs under or one it borrowed; a
	// borrowed one carries how far the borrower may go with it.
	//
	enum ETokenType
	{
		eTokenTypeNone			= 0,
		eTokenTypePrimary		= 1,	// TokenPrimary
		eTokenTypeImpersonation	= 2,	// TokenImpersonation
	};

	enum EImpersonationLevel
	{
		eImpersonationNone			= -1,	// a primary token: the question does not arise
		eImpersonationAnonymous		= 0,	// SecurityAnonymous
		eImpersonationIdentification= 1,
		eImpersonationImpersonation	= 2,
		eImpersonationDelegation	= 3,
	};

	virtual SAdvancedInfo	GetAdvancedInfo()					{ return SAdvancedInfo(); }

	// ---- Windows: AppContainer detail ----
	struct SContainerInfo
	{
		QString appContainerName;
		QString appContainerSid;

		// See EAppContainerSidType.
		quint8 appContainerSidType = 0;

		quint32 appContainerNumber = 0;
		bool isLessPrivilegedAppContainer = false;
		QString tokenNamedObjectPath;

		QString parentContainerName;
		QString parentContainerSid;

		QString packageFullName;
		QString packagePath;

		QString appContainerFolderPath;
		QString appContainerRegistryPath;
	};

	//
	// Whether an AppContainer SID names the container itself or one nested in
	// it. Windows's own numbering starts at 0 for the parent kind, so an
	// unreported one needs a value of its own.
	//
	enum EAppContainerSidType
	{
		eAppContainerSidUnknown	= 0,
		eAppContainerSidParent	= 1,	// ParentAppContainerSidType + 1
		eAppContainerSidChild	= 2,	// ChildAppContainerSidType + 1
	};

	virtual SContainerInfo	GetContainerInfo()					{ return SContainerInfo(); }

	struct SCapability
	{
		QString SidString;

		QString FullName;
		QString Capability;

		QString Package;
		QString Guid;
	};

	virtual QMap<QByteArray, SCapability> GetCapabilities()		{ return QMap<QByteArray, SCapability>(); }

	//
	// A security attribute or claim. Windows-specific today; kept general so a
	// Linux backend could surface xattr-based labels through the same tab.
	//
	struct SAttribute
	{
		quint16 Type = 0;
		quint32 Flags = 0;
		QVector<QVariant> Values;
	};

	virtual QMap<QString, SAttribute> GetClaims(bool DeviceClaims) { Q_UNUSED(DeviceClaims); return QMap<QString, SAttribute>(); }
	virtual QMap<QString, SAttribute> GetAttributes()			{ return QMap<QString, SAttribute>(); }

	//
	// Token settings that weaken the sandbox a process runs in. Flagged in the
	// UI because each one is a meaningful downgrade of its isolation.
	//
	enum EDangerousFlags
	{
		eNoWriteUpDisabled,
		eSandboxInertEnabled,
		eUIAccessEnabled,
	};

	virtual QSet<EDangerousFlags> GetDangerousFlags() const		{ return QSet<EDangerousFlags>(); }

public slots:
	virtual bool			UpdateDynamicData()					{ return false; }
	virtual bool			UpdateExtendedData()				{ return false; }
};

typedef QSharedPointer<CTokenInfo> CTokenInfoPtr;
typedef QWeakPointer<CTokenInfo> CTokenInfoRef;
