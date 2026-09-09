/*
 * Task Explorer -
 *   the LSA / SAM enumeration behind the security explorer.
 *
 * This used to live in GUI/SecurityExplorer.cpp, which meant the dialog could
 * only ever describe the machine the GUI was running on. Everything here is a
 * property of a target system, so it belongs on CWindowsAPI; what is left in
 * the view is Qt.
 *
 * PhEditSecurity is the exception and stays a local operation: it opens the
 * platform's own modal editor against a live handle, which is not something a
 * remote system can do on the viewer's screen.
 */

#include "stdafx.h"
#include "WindowsAPI.h"
#include "ProcessHacker.h"
#include "WinSecurityEditor.h"

// the LSA/SAM types come from phnt via ProcessHacker.h; pulling in the SDK's
// <ntsecapi.h> as well would redefine every one of them
#include <wincred.h>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Samlib.lib")
#pragma comment(lib, "Secur32.lib")

//
// Accounts the local security authority knows about.
//
QList<CSystemAPI::SPrincipal> CWindowsAPI::EnumLsaAccounts() const
{
	QList<SPrincipal> List;

	LSA_HANDLE policyHandle;
	if (!NT_SUCCESS(PhOpenLsaPolicy(&policyHandle, POLICY_VIEW_LOCAL_INFORMATION, NULL)))
		return List;

	LSA_ENUMERATION_HANDLE enumerationHandle = 0;
	PLSA_ENUMERATION_INFORMATION accounts;
	ULONG numberOfAccounts;
	while (NT_SUCCESS(LsaEnumerateAccounts(policyHandle, &enumerationHandle, (PVOID*)&accounts, 0x100, &numberOfAccounts)))
	{
		for (ULONG i = 0; i < numberOfAccounts; i++)
		{
			SPrincipal Principal;
			Principal.Sid = QByteArray((char*)accounts[i].Sid, RtlLengthSid(accounts[i].Sid));

			PPH_STRING name = PhGetSidFullName(accounts[i].Sid, TRUE, NULL);
			if (name) Principal.Name = CastPhString(name);

			PPH_STRING sid = PhSidToStringSid(accounts[i].Sid);
			if (sid) Principal.SidString = CastPhString(sid);

			List.append(Principal);
		}

		LsaFreeMemory(accounts);
	}

	LsaClose(policyHandle);
	return List;
}

//
// Logon sessions currently on the machine.
//
QList<CSystemAPI::SPrincipal> CWindowsAPI::EnumLogonSessions() const
{
	QList<SPrincipal> List;

	ULONG logonSessionCount = 0;
	PLUID logonSessionList = NULL;
	if (!NT_SUCCESS(LsaEnumerateLogonSessions(&logonSessionCount, &logonSessionList)))
		return List;

	for (ULONG i = 0; i < logonSessionCount; i++)
	{
		PSECURITY_LOGON_SESSION_DATA logonSessionData;
		if (!NT_SUCCESS(LsaGetLogonSessionData(&logonSessionList[i], &logonSessionData)))
			continue;

		//
		// A session whose SID does not validate is still worth listing - it has
		// a logon id - but it has no principal to name.
		//
		SPrincipal Principal;
		Principal.LogonId = logonSessionData->LogonId.LowPart;

		if (RtlValidSid(logonSessionData->Sid))
		{
			Principal.Sid = QByteArray((char*)logonSessionData->Sid, RtlLengthSid(logonSessionData->Sid));

			PPH_STRING name = PhGetSidFullName(logonSessionData->Sid, TRUE, NULL);
			if (name) Principal.Name = CastPhString(name);

			PPH_STRING sid = PhSidToStringSid(logonSessionData->Sid);
			if (sid) Principal.SidString = CastPhString(sid);
		}

		List.append(Principal);

		LsaFreeReturnBuffer(logonSessionData);
	}

	LsaFreeReturnBuffer(logonSessionList);
	return List;
}

//
// Opening the account domain is the same five steps for users and for groups.
//
static NTSTATUS CWindowsAPI__OpenAccountDomain(
	_Out_ PLSA_HANDLE PolicyHandle,
	_Out_ SAM_HANDLE* ServerHandle,
	_Out_ SAM_HANDLE* DomainHandle,
	_Out_ PPOLICY_ACCOUNT_DOMAIN_INFO* DomainInfo)
{
	*PolicyHandle = NULL;
	*ServerHandle = NULL;
	*DomainHandle = NULL;
	*DomainInfo = NULL;

	NTSTATUS status = PhOpenLsaPolicy(PolicyHandle, POLICY_VIEW_LOCAL_INFORMATION, NULL);
	if (!NT_SUCCESS(status))
		return status;

	status = LsaQueryInformationPolicy(*PolicyHandle, PolicyAccountDomainInformation, (PVOID*)DomainInfo);
	if (!NT_SUCCESS(status))
		return status;

	status = SamConnect(NULL, ServerHandle, SAM_SERVER_CONNECT | SAM_SERVER_LOOKUP_DOMAIN, NULL);
	if (!NT_SUCCESS(status))
		return status;

	return SamOpenDomain(*ServerHandle, DOMAIN_LIST_ACCOUNTS | DOMAIN_LOOKUP, (*DomainInfo)->DomainSid, DomainHandle);
}

static void CWindowsAPI__CloseAccountDomain(
	LSA_HANDLE PolicyHandle, SAM_HANDLE ServerHandle, SAM_HANDLE DomainHandle, PPOLICY_ACCOUNT_DOMAIN_INFO DomainInfo)
{
	if (DomainHandle) SamCloseHandle(DomainHandle);
	if (ServerHandle) SamCloseHandle(ServerHandle);
	if (DomainInfo) LsaFreeMemory(DomainInfo);
	if (PolicyHandle) LsaClose(PolicyHandle);
}

QList<CSystemAPI::SPrincipal> CWindowsAPI::EnumSamUsers() const
{
	QList<SPrincipal> List;

	LSA_HANDLE policyHandle;
	SAM_HANDLE serverHandle, domainHandle;
	PPOLICY_ACCOUNT_DOMAIN_INFO policyDomainInfo;

	if (NT_SUCCESS(CWindowsAPI__OpenAccountDomain(&policyHandle, &serverHandle, &domainHandle, &policyDomainInfo)))
	{
		SAM_ENUMERATE_HANDLE enumContext = 0;
		ULONG enumBufferLength = 0;
		PSAM_RID_ENUMERATION enumBuffer = NULL;

		if (NT_SUCCESS(SamEnumerateUsersInDomain(domainHandle, &enumContext, 0, (PVOID*)&enumBuffer, -1, &enumBufferLength)))
		{
			for (ULONG i = 0; i < enumBufferLength; i++)
			{
				//
				// A name and a SID is all this list shows. USER_ALL_ACCESS used
				// to be asked for here, which is denied without elevation - so
				// the list came back empty in a normal session even though the
				// domain enumerated fine.
				//
				SAM_HANDLE userHandle;
				if (!NT_SUCCESS(SamOpenUser(domainHandle, USER_READ_GENERAL, enumBuffer[i].RelativeId, &userHandle)))
					continue;

				//
				// The UserAllInformation query that used to sit here was never
				// read - the name comes from the SID below - and the handle
				// leaked whenever it failed.
				//
				PSID userSid = NULL;
				if (NT_SUCCESS(SamRidToSid(userHandle, enumBuffer[i].RelativeId, &userSid)))
				{
					SPrincipal Principal;
					Principal.RelativeId = enumBuffer[i].RelativeId;
					Principal.Sid = QByteArray((char*)userSid, RtlLengthSid(userSid));

					PPH_STRING name = PhGetSidFullName(userSid, TRUE, NULL);
					if (name) Principal.Name = CastPhString(name);

					PPH_STRING sid = PhSidToStringSid(userSid);
					if (sid) Principal.SidString = CastPhString(sid);

					List.append(Principal);
				}

				SamCloseHandle(userHandle);
			}

			SamFreeMemory(enumBuffer);
		}
	}

	CWindowsAPI__CloseAccountDomain(policyHandle, serverHandle, domainHandle, policyDomainInfo);
	return List;
}

QList<CSystemAPI::SPrincipal> CWindowsAPI::EnumSamGroups() const
{
	QList<SPrincipal> List;

	LSA_HANDLE policyHandle;
	SAM_HANDLE serverHandle, domainHandle;
	PPOLICY_ACCOUNT_DOMAIN_INFO policyDomainInfo;

	if (NT_SUCCESS(CWindowsAPI__OpenAccountDomain(&policyHandle, &serverHandle, &domainHandle, &policyDomainInfo)))
	{
		SAM_ENUMERATE_HANDLE enumContext = 0;
		ULONG enumBufferLength = 0;
		PSAM_RID_ENUMERATION enumBuffer = NULL;

		if (NT_SUCCESS(SamEnumerateGroupsInDomain(domainHandle, &enumContext, (PVOID*)&enumBuffer, -1, &enumBufferLength)))
		{
			for (ULONG i = 0; i < enumBufferLength; i++)
			{
				SAM_HANDLE groupHandle;
				if (!NT_SUCCESS(SamOpenGroup(domainHandle, GROUP_READ_INFORMATION, enumBuffer[i].RelativeId, (PVOID*)&groupHandle)))
					continue;

				PGROUP_GENERAL_INFORMATION groupInfo = NULL;
				if (NT_SUCCESS(SamQueryInformationGroup(groupHandle, GroupGeneralInformation, (PVOID*)&groupInfo)))
				{
					SPrincipal Principal;
					Principal.RelativeId = enumBuffer[i].RelativeId;

					PSID groupSid = NULL;
					if (NT_SUCCESS(SamRidToSid(groupHandle, enumBuffer[i].RelativeId, &groupSid)))
					{
						Principal.Sid = QByteArray((char*)groupSid, RtlLengthSid(groupSid));

						PPH_STRING sid = PhSidToStringSid(groupSid);
						if (sid) Principal.SidString = CastPhString(sid);
					}

					Principal.Name = QString::fromWCharArray(groupInfo->Name.Buffer, groupInfo->Name.Length / sizeof(wchar_t));
					Principal.Comment = QString::fromWCharArray(groupInfo->AdminComment.Buffer, groupInfo->AdminComment.Length / sizeof(wchar_t));

					List.append(Principal);

					SamFreeMemory(groupInfo);
				}

				SamCloseHandle(groupHandle);
			}

			SamFreeMemory(enumBuffer);
		}
	}

	CWindowsAPI__CloseAccountDomain(policyHandle, serverHandle, domainHandle, policyDomainInfo);
	return List;
}

QList<CSystemAPI::SCredential> CWindowsAPI::EnumCredentials() const
{
	QList<SCredential> List;

	ULONG count = 0;
	PCREDENTIAL* credential = NULL;
	if (!CredEnumerate(NULL, CRED_ENUMERATE_ALL_CREDENTIALS, &count, &credential))
		return List;

	for (ULONG i = 0; i < count; i++)
	{
		SCredential Credential;
		Credential.Target = QString::fromWCharArray(credential[i]->TargetName);
		Credential.User = QString::fromWCharArray(credential[i]->UserName);
		Credential.Comment = QString::fromWCharArray(credential[i]->Comment);

		LARGE_INTEGER FileTime;
		FileTime.HighPart = credential[i]->LastWritten.dwHighDateTime;
		FileTime.LowPart = credential[i]->LastWritten.dwLowDateTime;
		Credential.LastWritten = FILETIME2time(FileTime.QuadPart);

		List.append(Credential);
	}

	CredFree(credential);
	return List;
}

//
// Privilege definitions, with the display name the system shows for each.
//
QList<CSystemAPI::SPrivilege> CWindowsAPI::EnumPrivileges() const
{
	QList<SPrivilege> List;

	LSA_HANDLE policyHandle;
	if (!NT_SUCCESS(PhOpenLsaPolicy(&policyHandle, POLICY_VIEW_LOCAL_INFORMATION, NULL)))
		return List;

	LSA_ENUMERATION_HANDLE enumContext = 0;
	PPOLICY_PRIVILEGE_DEFINITION buffer;
	ULONG count;

	for (;;)
	{
		NTSTATUS status = LsaEnumeratePrivileges(policyHandle, &enumContext, (PVOID*)&buffer, 0x100, &count);
		if (!NT_SUCCESS(status))
			break;

		for (ULONG i = 0; i < count; i++)
		{
			SPrivilege Privilege;
			Privilege.Name = QString::fromWCharArray(buffer[i].Name.Buffer, buffer[i].Name.Length / sizeof(wchar_t));

			PH_STRINGREF nameSr;
			nameSr.Buffer = buffer[i].Name.Buffer;
			nameSr.Length = buffer[i].Name.Length;

			//
			// NTSTATUS, not a boolean: the original tested it as one, so the
			// display name was only ever taken on failure - which also meant
			// reading a pointer the call had not written.
			//
			PPH_STRING displayName = NULL;
			if (NT_SUCCESS(PhLookupPrivilegeDisplayName(&nameSr, &displayName)) && displayName)
				Privilege.DisplayName = CastPhString(displayName);

			List.append(Privilege);
		}

		LsaFreeMemory(buffer);
	}

	LsaClose(policyHandle);
	return List;
}

//
// The security editor callbacks. Each one re-opens what it needs from the
// context the caller handed in, because the editor may run long after the call.
//
static NTSTATUS NTAPI CWindowsAPI__OpenLsaPolicy(_Out_ PHANDLE Handle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ PVOID Context)
{
	return PhOpenLsaPolicy(Handle, DesiredAccess, NULL);
}

static NTSTATUS NTAPI CWindowsAPI__OpenLsaAccount(_Out_ PHANDLE Handle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ PVOID Context)
{
	LSA_HANDLE policyHandle;
	NTSTATUS status = PhOpenLsaPolicy(&policyHandle, POLICY_LOOKUP_NAMES, NULL);
	if (NT_SUCCESS(status))
	{
		status = LsaOpenAccount(policyHandle, Context, DesiredAccess, Handle);
		LsaClose(policyHandle);
	}
	return status;
}

//
// The low half of the context is the RID, the high half says user or group.
//
static NTSTATUS NTAPI CWindowsAPI__OpenSamAccount(_Out_ PHANDLE Handle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ PVOID Context)
{
	const quint64 Selector = *((quint64*)Context);

	LSA_HANDLE policyHandle;
	SAM_HANDLE serverHandle, domainHandle;
	PPOLICY_ACCOUNT_DOMAIN_INFO policyDomainInfo;

	NTSTATUS status = CWindowsAPI__OpenAccountDomain(&policyHandle, &serverHandle, &domainHandle, &policyDomainInfo);
	if (NT_SUCCESS(status))
	{
		if ((Selector >> 32) == 0)
			status = SamOpenUser(domainHandle, DesiredAccess, Selector & 0xFFFFFFFF, Handle);
		else
			status = SamOpenGroup(domainHandle, DesiredAccess, Selector & 0xFFFFFFFF, Handle);
	}

	CWindowsAPI__CloseAccountDomain(policyHandle, serverHandle, domainHandle, policyDomainInfo);
	return status;
}

// the service manager opener lives with the rest of the service code
NTSTATUS NTAPI CWindowsAPI__OpenServiceControlManagerFwd(_Out_ PHANDLE Handle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ PVOID Context);

//
// The system's own securable objects. Each is an opener plus a context, the
// same shape as a process or a service; the context is copied into the object
// rather than parked in a static, which is what the old code had to do because
// the native dialog outlived this call.
//
CSecurityEditablePtr CWindowsAPI::GetSecurityObject(ESecurityObject Type, const QString& Name,
													const QByteArray& Sid, quint32 RelativeId) const
{
	switch (Type)
	{
	case eSecServiceManager:
		return CSecurityEditablePtr(new CWinSecurityObject(
			QString(), "SCManager",
			(CWinSecurityObject::POpenObject)CWindowsAPI__OpenServiceControlManagerFwd, (quint64)0));

	case eSecLsaPolicy:
		return CSecurityEditablePtr(new CWinSecurityObject(
			QString(), "LsaPolicy",
			(CWinSecurityObject::POpenObject)CWindowsAPI__OpenLsaPolicy, (quint64)0));

	case eSecLsaAccount:
	{
		if (Sid.isEmpty())
			return CSecurityEditablePtr();
		return CSecurityEditablePtr(new CWinSecurityObject(
			Name, "LsaAccount",
			(CWinSecurityObject::POpenObject)CWindowsAPI__OpenLsaAccount, Sid));
	}

	case eSecSamUser:
	case eSecSamGroup:
	{
		//
		// The low half of the context is the RID, the high half says which of
		// the two it is - the same encoding the opener already expected.
		//
		quint64 Selector = RelativeId | ((quint64)(Type == eSecSamGroup ? 1 : 0) << 32);
		return CSecurityEditablePtr(new CWinSecurityObject(
			Name, Type == eSecSamGroup ? "SamGroup" : "SamUser",
			(CWinSecurityObject::POpenObject)CWindowsAPI__OpenSamAccount,
			QByteArray((const char*)&Selector, sizeof(Selector))));
	}
	}

	return CSecurityEditablePtr();
}

//
// The COM running object table. Moved out of CRunObjView, which walked the
// monikers itself; the numbers - names, here - belong on this side.
//
QStringList CWindowsAPI::EnumRunningObjects() const
{
	QStringList Names;

	IRunningObjectTable* iRunningObjectTable = NULL;
	IEnumMoniker* iEnumMoniker = NULL;
	IMoniker* iMoniker = NULL;
	IBindCtx* iBindCtx = NULL;
	IMalloc* iMalloc = NULL;
	ULONG count = 0;

	if (!SUCCEEDED(CoGetMalloc(1, &iMalloc)))
		return Names;

	if (SUCCEEDED(GetRunningObjectTable(0, &iRunningObjectTable)))
	{
		if (SUCCEEDED(IRunningObjectTable_EnumRunning(iRunningObjectTable, &iEnumMoniker)))
		{
			while (IEnumMoniker_Next(iEnumMoniker, 1, &iMoniker, &count) == S_OK)
			{
				if (SUCCEEDED(CreateBindCtx(0, &iBindCtx)))
				{
					OLECHAR* displayName = NULL;

					if (SUCCEEDED(IMoniker_GetDisplayName(iMoniker, iBindCtx, NULL, &displayName)))
					{
						Names.append(QString::fromWCharArray(displayName));
						IMalloc_Free(iMalloc, displayName);
					}

					IBindCtx_Release(iBindCtx);
				}

				IEnumMoniker_Release(iMoniker);
			}

			IEnumMoniker_Release(iEnumMoniker);
		}

		IRunningObjectTable_Release(iRunningObjectTable);
	}

	IMalloc_Release(iMalloc);
	return Names;
}
