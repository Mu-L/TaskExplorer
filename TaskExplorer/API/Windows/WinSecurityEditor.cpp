#include "stdafx.h"
#include "ProcessHacker.h"
#include <svcsup.h>
#include "WinSecurityEditor.h"
#include "WinAccessRights.h"
#include "../../../MiscHelpers/Common/Common.h"
#include "WindowsAPI.h"

//
// Reading and writing a security descriptor as values.
//
// This replaces PhEditSecurity, which put Windows' own dialog on the screen
// driven by a live handle. That dialog is a local, modal, COM affair; nothing
// about it can describe a machine on the other end of a socket. What can travel
// is the descriptor, so that is what this produces and consumes.
//
// The descriptor is read into SSecurityInfo and written back from it. Nothing
// in between - not the dialog, not the wire - holds a handle.
//

//
// phlib does the same dispatch internally but does not export the mapping, so
// it is repeated here for the object kinds this application actually edits.
//
enum EWinSecObjectKind
{
	eSecKindDefault = 0,	// NtQuerySecurityObject / NtSetSecurityObject
	eSecKindService,
	eSecKindLsa,
	eSecKindSam,
	eSecKindTokenDefault,
};

static EWinSecObjectKind CWinSecurity__Kind(const QString& Type)
{
	if (Type == "Service" || Type == "SCManager")	return eSecKindService;
	if (Type == "TokenDefault")						return eSecKindTokenDefault;
	if (Type.startsWith("Lsa"))						return eSecKindLsa;
	if (Type.startsWith("Sam"))						return eSecKindSam;
	return eSecKindDefault;
}


//
// ---- SIDs ----
//

static QString CWinSecurity__SidToString(PSID Sid)
{
	if (!Sid || !RtlValidSid(Sid))
		return QString();
	return CastPhString(PhSidToStringSid(Sid));
}

static QString CWinSecurity__SidToName(PSID Sid)
{
	if (!Sid || !RtlValidSid(Sid))
		return QString();
	return CastPhString(PhGetSidFullName(Sid, TRUE, NULL));
}

//
// "S-1-5-32-544" back into a SID.
//
// Written out rather than calling ConvertStringSidToSid, whose header does not
// coexist with phnt in one translation unit. The layout is fixed and the parse
// is exact: anything malformed returns empty rather than a partial SID.
//
static QByteArray CWinSecurity__StringToSid(const QString& Str)
{
	QStringList Parts = Str.split('-');
	if (Parts.size() < 3 || Parts[0].compare("S", Qt::CaseInsensitive) != 0)
		return QByteArray();

	bool bOk = false;
	uint Revision = Parts[1].toUInt(&bOk);
	if (!bOk || Revision != SID_REVISION)
		return QByteArray();

	//
	// The identifier authority is 48 bits and may be written in decimal or, for
	// the large ones, as 0x-prefixed hex.
	//
	quint64 Authority = Parts[2].startsWith("0x", Qt::CaseInsensitive)
		? Parts[2].mid(2).toULongLong(&bOk, 16)
		: Parts[2].toULongLong(&bOk, 10);
	if (!bOk || Authority > Q_UINT64_C(0xFFFFFFFFFFFF))
		return QByteArray();

	QList<quint32> Sub;
	for (int i = 3; i < Parts.size(); i++)
	{
		quint32 Value = Parts[i].toUInt(&bOk);
		if (!bOk)
			return QByteArray();
		Sub.append(Value);
	}
	if (Sub.size() > SID_MAX_SUB_AUTHORITIES)
		return QByteArray();

	QByteArray Buffer((int)RtlLengthRequiredSid((ULONG)Sub.size()), 0);
	PSID Sid = (PSID)Buffer.data();

	((SID*)Sid)->Revision = (UCHAR)Revision;
	((SID*)Sid)->SubAuthorityCount = (UCHAR)Sub.size();

	PSID_IDENTIFIER_AUTHORITY pAuthority = RtlIdentifierAuthoritySid(Sid);
	for (int i = 0; i < 6; i++)		// big endian, most significant byte first
		pAuthority->Value[i] = (UCHAR)((Authority >> (8 * (5 - i))) & 0xFF);

	for (int i = 0; i < Sub.size(); i++)
		*RtlSubAuthoritySid(Sid, i) = Sub[i];

	if (!RtlValidSid(Sid))
		return QByteArray();
	return Buffer;
}

QString LookupSidByName(const QString& Name)
{
	PSID Sid = NULL;
	PH_STRINGREF NameRef;
	std::wstring wName = Name.toStdWString();
	PhInitializeStringRefLongHint(&NameRef, (PWSTR)wName.c_str());

	if (!NT_SUCCESS(PhLookupName(&NameRef, &Sid, NULL, NULL)) || !Sid)
		return QString();

	QString Result = CWinSecurity__SidToString(Sid);
	PhFree(Sid);
	return Result;
}

QString LookupNameBySid(const QString& Sid)
{
	QByteArray Raw = CWinSecurity__StringToSid(Sid);
	if (Raw.isEmpty())
		return QString();
	return CWinSecurity__SidToName((PSID)Raw.data());
}


//
// ---- descriptor -> values ----
//

static void CWinSecurity__ReadAcl(PACL Acl, QList<SAce>& List, bool bAudit, int& Skipped)
{
	if (!Acl)
		return;

	for (ULONG i = 0; i < Acl->AceCount; i++)
	{
		PVOID pAce = NULL;
		if (!NT_SUCCESS(RtlGetAce(Acl, i, &pAce)) || !pAce)
			continue;

		PACE_HEADER pHeader = (PACE_HEADER)pAce;

		SAce Ace;
		PSID pSid = NULL;

		switch (pHeader->AceType)
		{
		case ACCESS_ALLOWED_ACE_TYPE:
			if (bAudit) continue;
			Ace.Type = SAce::eAllow;
			Ace.Mask = ((PACCESS_ALLOWED_ACE)pAce)->Mask;
			pSid = (PSID)&((PACCESS_ALLOWED_ACE)pAce)->SidStart;
			break;

		case ACCESS_DENIED_ACE_TYPE:
			if (bAudit) continue;
			Ace.Type = SAce::eDeny;
			Ace.Mask = ((PACCESS_DENIED_ACE)pAce)->Mask;
			pSid = (PSID)&((PACCESS_DENIED_ACE)pAce)->SidStart;
			break;

		case SYSTEM_AUDIT_ACE_TYPE:
			if (!bAudit) continue;
			Ace.Type = SAce::eAudit;
			Ace.Mask = ((PSYSTEM_AUDIT_ACE)pAce)->Mask;
			pSid = (PSID)&((PSYSTEM_AUDIT_ACE)pAce)->SidStart;
			break;

		default:
			//
			// Object ACEs and the conditional/callback kinds are not modelled.
			// Counting them is what stops the descriptor being written back
			// with them missing - see SSecurityInfo::SkippedAces.
			//
			Skipped++;
			continue;
		}

		Ace.Flags = pHeader->AceFlags;
		Ace.Sid = CWinSecurity__SidToString(pSid);
		Ace.Name = CWinSecurity__SidToName(pSid);
		if (Ace.Name.isEmpty())
			Ace.Name = Ace.Sid;

		List.append(Ace);
	}
}

static void CWinSecurity__ReadDescriptor(PSECURITY_DESCRIPTOR pSd, SSecurityInfo& Info, bool bWithAudit)
{
	PSID pOwner = NULL, pGroup = NULL;
	BOOLEAN bDefaulted = FALSE;

	if (NT_SUCCESS(RtlGetOwnerSecurityDescriptor(pSd, &pOwner, &bDefaulted)) && pOwner)
	{
		Info.OwnerSid = CWinSecurity__SidToString(pOwner);
		Info.OwnerName = CWinSecurity__SidToName(pOwner);
	}

	if (NT_SUCCESS(RtlGetGroupSecurityDescriptor(pSd, &pGroup, &bDefaulted)) && pGroup)
	{
		Info.GroupSid = CWinSecurity__SidToString(pGroup);
		Info.GroupName = CWinSecurity__SidToName(pGroup);
	}

	SECURITY_DESCRIPTOR_CONTROL Control = 0;
	ULONG Revision = 0;
	RtlGetControlSecurityDescriptor(pSd, &Control, &Revision);

	PACL pDacl = NULL;
	BOOLEAN bDaclPresent = FALSE;
	if (NT_SUCCESS(RtlGetDaclSecurityDescriptor(pSd, &bDaclPresent, &pDacl, &bDefaulted)))
	{
		Info.bDaclPresent = !!bDaclPresent;
		Info.bDaclProtected = (Control & SE_DACL_PROTECTED) != 0;
		CWinSecurity__ReadAcl(pDacl, Info.Dacl, false, Info.SkippedAces);
	}

	if (bWithAudit)
	{
		PACL pSacl = NULL;
		BOOLEAN bSaclPresent = FALSE;
		if (NT_SUCCESS(RtlGetSaclSecurityDescriptor(pSd, &bSaclPresent, &pSacl, &bDefaulted)))
		{
			Info.bSaclPresent = !!bSaclPresent;
			Info.bSaclProtected = (Control & SE_SACL_PROTECTED) != 0;
			CWinSecurity__ReadAcl(pSacl, Info.Sacl, true, Info.SkippedAuditAces);
		}
	}
}


//
// ---- values -> descriptor ----
//
// An absolute descriptor pointing at buffers the caller owns, so everything is
// kept alive in the vectors passed in until the set call has returned.
//

static PACL CWinSecurity__BuildAcl(const QList<SAce>& List, QList<QByteArray>& Sids, QByteArray& AclBuffer)
{
	//
	// Size first: the ACL header plus, per entry, the ACE header and the SID
	// minus the placeholder SidStart already counted in the ACE structure.
	//
	ULONG Size = sizeof(ACL);
	QList<QByteArray> Raw;
	foreach(const SAce& Ace, List)
	{
		QByteArray Sid = CWinSecurity__StringToSid(Ace.Sid);
		if (Sid.isEmpty())
			return NULL;			// refuse rather than silently drop an entry
		Raw.append(Sid);
		Size += sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + (ULONG)Sid.size();
	}

	AclBuffer.resize((int)Size);
	AclBuffer.fill(0);
	PACL pAcl = (PACL)AclBuffer.data();

	if (!NT_SUCCESS(RtlCreateAcl(pAcl, Size, ACL_REVISION)))
		return NULL;

	//
	// Deny entries go in first. Windows evaluates a DACL in order and stops at
	// the first match, so a deny placed after an allow for the same principal
	// would never be reached - the native editor canonicalises the same way.
	//
	for (int Pass = 0; Pass < 2; Pass++)
	{
		for (int i = 0; i < List.size(); i++)
		{
			const SAce& Ace = List[i];
			bool bDeny = (Ace.Type == SAce::eDeny);
			if ((Pass == 0) != bDeny)
				continue;

			PSID pSid = (PSID)Raw[i].data();
			NTSTATUS status;

			if (Ace.Type == SAce::eAudit)
			{
				status = RtlAddAuditAccessAceEx(pAcl, ACL_REVISION, (UCHAR)Ace.Flags, Ace.Mask, pSid,
					(Ace.Flags & SAce::eAuditSuccess) ? TRUE : FALSE,
					(Ace.Flags & SAce::eAuditFailure) ? TRUE : FALSE);
			}
			else if (bDeny)
				status = RtlAddAccessDeniedAceEx(pAcl, ACL_REVISION, (UCHAR)Ace.Flags, Ace.Mask, pSid);
			else
				status = RtlAddAccessAllowedAceEx(pAcl, ACL_REVISION, (UCHAR)Ace.Flags, Ace.Mask, pSid);

			if (!NT_SUCCESS(status))
				return NULL;
		}
	}

	Sids = Raw;			// keep the SID buffers alive for the caller
	return pAcl;
}


//
// phlib's PhSamQuerySecurityObject is a stub - its body is commented out and it
// returns STATUS_NOT_SUPPORTED - so SAM accounts have never shown a descriptor.
// samlib is already linked for the account enumeration, so the call is simply
// made here instead.
//
// The descriptor comes back in SAM's allocator and has to be copied into the
// one the caller will free.
//
static NTSTATUS CWinSecurity__SamGetSecurity(HANDLE Handle, SECURITY_INFORMATION What, PSECURITY_DESCRIPTOR* SecurityDescriptor)
{
	PSECURITY_DESCRIPTOR pSamSd = NULL;
	NTSTATUS status = SamQuerySecurityObject(Handle, What, &pSamSd);
	if (!NT_SUCCESS(status))
		return status;

	if (!pSamSd)
		return STATUS_UNSUCCESSFUL;

	*SecurityDescriptor = PhAllocateCopy(pSamSd, PhLengthSecurityDescriptor(pSamSd));
	SamFreeMemory(pSamSd);
	return STATUS_SUCCESS;
}


//
// What went wrong, in terms that mean something here.
//
// Most statuses are best rendered by the system, but a couple describe the
// plumbing rather than the problem: a caller told to "make sure the filter
// manager is loaded as a driver" has no way to guess that the real answer is
// that this application's own kernel driver is not running.
//
static STATUS CWinSecurity__Status(NTSTATUS Status)
{
	if (Status == STATUS_FLT_NOT_INITIALIZED)
		return ERR(TE_KsiNotRunningForObject, Status);

	return ERR(TE_Generic, QVariantList() << CastPhString(PhGetStatusMessage(Status, 0)), Status);
}


//
// ---- the object ----
//

CWinSecurityObject::CWinSecurityObject(const QString& Name, const QString& Type, POpenObject Opener, quint64 Context, quint64 ObjectId)
	: m_Name(Name), m_Type(Type), m_Opener(Opener), m_Value(Context), m_bByValue(true)
{
	m_ObjectId = ObjectId;
}

CWinSecurityObject::CWinSecurityObject(const QString& Name, const QString& Type, POpenObject Opener, const QByteArray& Context)
	: m_Name(Name), m_Type(Type), m_Opener(Opener), m_Context(Context), m_Value(0), m_bByValue(false)
{
	m_ObjectId = 0;
}

void* CWinSecurityObject::Context() const
{
	if (m_bByValue)
		return (void*)(ULONG_PTR)m_Value;
	return m_Context.isEmpty() ? NULL : (void*)m_Context.constData();
}

QList<SAccessRight> CWinSecurityObject::GetAccessRights() const
{
	return WinAccess__GetAccessRights(m_Type);
}

STATUS CWinSecurityObject::GetSecurity(SSecurityInfo& Info, bool bWithAudit) const
{
	if (!m_Opener)
		return ERR(TE_ObjectExposeSecurity);

	SECURITY_INFORMATION What = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
	if (bWithAudit)
		What |= SACL_SECURITY_INFORMATION;

	HANDLE Handle = NULL;
	NTSTATUS status = m_Opener((void**)&Handle, PhGetAccessForGetSecurity(What), Context());

	//
	// Auditing needs SeSecurityPrivilege, which the caller often does not hold.
	// Losing it should not cost the owner and DACL, so the open is retried
	// without it rather than failing outright.
	//
	if (!NT_SUCCESS(status) && bWithAudit)
	{
		bWithAudit = false;
		What &= ~SACL_SECURITY_INFORMATION;
		status = m_Opener((void**)&Handle, PhGetAccessForGetSecurity(What), Context());
	}

	if (!NT_SUCCESS(status))
		return CWinSecurity__Status(status);

	PSECURITY_DESCRIPTOR pSd = NULL;
	switch (CWinSecurity__Kind(m_Type))
	{
	case eSecKindService:		status = PhGetServiceObjectSecurity((SC_HANDLE)Handle, What, &pSd); break;
	case eSecKindLsa:			status = PhLsaQuerySecurityObject(Handle, What, &pSd); break;
	case eSecKindSam:			status = CWinSecurity__SamGetSecurity(Handle, What, &pSd); break;
	case eSecKindTokenDefault:	status = PhGetSeObjectSecurityTokenDefault(Handle, What, &pSd); break;
	default:					status = PhGetObjectSecurity(Handle, What, &pSd); break;
	}

	NtClose(Handle);

	if (!NT_SUCCESS(status) || !pSd)
		return CWinSecurity__Status(status);

	CWinSecurity__ReadDescriptor(pSd, Info, bWithAudit);
	PhFree(pSd);
	return OK;
}

STATUS CWinSecurityObject::SetSecurity(const SSecurityInfo& Info, bool bWithAudit)
{
	if (!m_Opener)
		return ERR(TE_ObjectExposeSecurity);

	//
	// Reading a SAM account's descriptor is done here because phlib's helper is
	// a stub; writing one is not, so this refuses rather than pretending. It is
	// a deliberate gap, not a Windows restriction - SamSetSecurityObject exists.
	//
	if (CWinSecurity__Kind(m_Type) == eSecKindSam)
		return ERR(TE_ChangingSecuritySam);

	SECURITY_INFORMATION What = 0;

	SECURITY_DESCRIPTOR Sd;
	if (!NT_SUCCESS(RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION)))
		return ERR(TE_BuildSecurityDesc);

	//
	// The access list, unless it held entries this model does not describe -
	// rebuilding it from an incomplete picture would drop them, which is a
	// security change nobody asked for. An owner change is still allowed in
	// that case, because it does not touch the list.
	//
	QList<QByteArray> DaclSids;
	QByteArray DaclBuffer;
	if (Info.SkippedAces == 0)
	{
		//
		// Inherited entries are dropped rather than written. They belong to the
		// parent; writing them back would turn each one into an explicit copy
		// that no longer tracks the parent, which is how a DACL quietly ossifies.
		//
		QList<SAce> Explicit;
		foreach(const SAce& Ace, Info.Dacl)
		{
			if (!Ace.IsInherited())
				Explicit.append(Ace);
		}

		PACL pDacl = CWinSecurity__BuildAcl(Explicit, DaclSids, DaclBuffer);
		if (!pDacl)
			return ERR(TE_AccountNotResolved);

		if (!NT_SUCCESS(RtlSetDaclSecurityDescriptor(&Sd, TRUE, pDacl, FALSE)))
			return ERR(TE_BuildSecurityDesc);

		What |= DACL_SECURITY_INFORMATION;
	}
	else if (!Info.bSetOwner)
	{
		return ERR(TE_ObjectAccessControl, QVariantList() << Info.SkippedAces);
	}

	//
	// The owner, only when asked for.
	//
	QByteArray OwnerSid;
	if (Info.bSetOwner)
	{
		OwnerSid = CWinSecurity__StringToSid(Info.OwnerSid);
		if (OwnerSid.isEmpty())
			return ERR(TE_NewOwnerResolved);

		if (!NT_SUCCESS(RtlSetOwnerSecurityDescriptor(&Sd, (PSID)OwnerSid.data(), FALSE)))
			return ERR(TE_BuildSecurityDesc);

		What |= OWNER_SECURITY_INFORMATION;
	}

	QList<QByteArray> SaclSids;
	QByteArray SaclBuffer;
	if (bWithAudit && Info.bSaclPresent)
	{
		if (Info.SkippedAuditAces > 0)
		{
			return ERR(TE_ObjectAuditEntries, QVariantList() << Info.SkippedAuditAces);
		}

		PACL pSacl = CWinSecurity__BuildAcl(Info.Sacl, SaclSids, SaclBuffer);
		if (pSacl && NT_SUCCESS(RtlSetSaclSecurityDescriptor(&Sd, TRUE, pSacl, FALSE)))
			What |= SACL_SECURITY_INFORMATION;
	}

	if (What == 0)
		return OK;			// nothing was asked for

	HANDLE Handle = NULL;
	NTSTATUS status = m_Opener((void**)&Handle, PhGetAccessForSetSecurity(What), Context());
	if (!NT_SUCCESS(status))
		return CWinSecurity__Status(status);

	switch (CWinSecurity__Kind(m_Type))
	{
	case eSecKindService:		status = PhSetServiceObjectSecurity((SC_HANDLE)Handle, What, &Sd); break;
	case eSecKindLsa:			status = LsaSetSecurityObject(Handle, What, &Sd); break;
	case eSecKindTokenDefault:	status = PhSetSeObjectSecurityTokenDefault(Handle, What, &Sd); break;
	default:					status = PhSetObjectSecurity(Handle, What, &Sd); break;
	}

	NtClose(Handle);

	if (!NT_SUCCESS(status))
		return CWinSecurity__Status(status);
	return OK;
}


//
// The same two lookups, reached through the system object so a view never has
// to name the Windows backend.
//
QString CWindowsAPI::LookupSidByName(const QString& Name) const
{
	return ::LookupSidByName(Name);
}

QString CWindowsAPI::LookupNameBySid(const QString& Sid) const
{
	return ::LookupNameBySid(Sid);
}
