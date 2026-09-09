/*
 * Task Explorer -
 *   qt wrapper and support functions based on hndlprv.c
 *
 * Copyright (C) 2010-2015 wj32
 * Copyright (C) 2017 dmex
 * Copyright (C) 2019-2022 David Xanatos
 *
 * This file is part of Task Explorer and contains System Informer code.
 * 
 */

#include "stdafx.h"
#include "WinHandle.h"
#include "WinAccessRights.h"
#include "WinMemIO.h"
#include "WinJob.h"
#include "WinToken.h"
#include "ProcessHacker.h"
#include "WinSecurityEditor.h"
#include "WindowsAPI.h"
#include "ProcessHacker/appsup.h"   // PhShellExecuteUserString, PhShellOpenKey2
#include "../../../MiscHelpers/Common/Settings.h"

//
// The values CHandleInfo names are the object manager's own; a typo has to
// break the build rather than quietly read a handle wrong.
//
static_assert(CHandleInfo::eObjProtectClose == OBJ_PROTECT_CLOSE, "obj protect close");
static_assert(CHandleInfo::eObjInherit      == OBJ_INHERIT,       "obj inherit");

static_assert(CHandleInfo::eShareRead   == PH_HANDLE_FILE_SHARED_READ,   "share read");
static_assert(CHandleInfo::eShareWrite  == PH_HANDLE_FILE_SHARED_WRITE,  "share write");
static_assert(CHandleInfo::eShareDelete == PH_HANDLE_FILE_SHARED_DELETE, "share delete");
static_assert(CHandleInfo::eShareMask   == PH_HANDLE_FILE_SHARED_MASK,   "share mask");

static_assert(CHandleInfo::eSecFile    == SEC_FILE,    "sec file");
static_assert(CHandleInfo::eSecImage   == SEC_IMAGE,   "sec image");
static_assert(CHandleInfo::eSecReserve == SEC_RESERVE, "sec reserve");
static_assert(CHandleInfo::eSecCommit  == SEC_COMMIT,  "sec commit");

static_assert(CHandleInfo::eAlpcLpcMode              == ALPC_PORFLG_LPC_MODE,                    "alpc lpc mode");
static_assert(CHandleInfo::eAlpcAllowImpersonation   == ALPC_PORFLG_ALLOW_IMPERSONATION,         "alpc allow impersonation");
static_assert(CHandleInfo::eAlpcAllowLpcRequests     == ALPC_PORFLG_ALLOW_LPC_REQUESTS,          "alpc allow lpc requests");
static_assert(CHandleInfo::eAlpcWaitablePort         == ALPC_PORFLG_WAITABLE_PORT,               "alpc waitable port");
static_assert(CHandleInfo::eAlpcAllowDupObject       == ALPC_PORFLG_ALLOW_DUP_OBJECT,            "alpc allow dup object");
static_assert(CHandleInfo::eAlpcSystemProcess        == ALPC_PORFLG_SYSTEM_PROCESS,              "alpc system process");
static_assert(CHandleInfo::eAlpcWakePolicy1          == ALPC_PORFLG_WAKE_POLICY1,                "alpc wake policy 1");
static_assert(CHandleInfo::eAlpcWakePolicy2          == ALPC_PORFLG_WAKE_POLICY2,                "alpc wake policy 2");
static_assert(CHandleInfo::eAlpcWakePolicy3          == ALPC_PORFLG_WAKE_POLICY3,                "alpc wake policy 3");
static_assert(CHandleInfo::eAlpcDirectMessage        == ALPC_PORFLG_DIRECT_MESSAGE,              "alpc direct message");
static_assert(CHandleInfo::eAlpcAllowMultiHandleAttr == ALPC_PORFLG_ALLOW_MULTIHANDLE_ATTRIBUTE, "alpc allow multi-handle attributes");


CWinHandle::CWinHandle(QObject *parent) 
	: CHandleInfo(parent) 
{
	m_Object = -1;
	m_Attributes = 0;
	m_GrantedAccess = 0;
	m_TypeIndex = 0;
	m_FileFlags = 0;
}

CWinHandle::~CWinHandle()
{
}

quint64 CWinHandle::MakeID(quint64 HandleValue, quint64 UniqueProcessId)
{
	quint64 HandleID = HandleValue;
	HandleID ^= (UniqueProcessId << 32);
	HandleID ^= (UniqueProcessId >> 32);
	return HandleID;
}

bool CWinHandle::InitStaticData(struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* handle, quint64 TimeStamp)
{
	QWriteLocker Locker(&m_Mutex);

	m_ProcessId = (quint64)handle->UniqueProcessId;
	m_HandleId = (quint64)handle->HandleValue;
	m_Object = (quint64)handle->Object;
	m_Attributes = handle->HandleAttributes;
	m_GrantedAccess = handle->GrantedAccess;
	m_TypeIndex = handle->ObjectTypeIndex;

	m_CreateTimeStamp = TimeStamp;
	m_RemoveTimeStamp = 0; // handles can be reused

	return true;
}

bool CWinHandle::InitExtData(struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* handle, quint64 ProcessHandle, bool bFull)
{
	QWriteLocker Locker(&m_Mutex);

	PPH_STRING TypeName;
    PPH_STRING ObjectName; // Original Name
    PPH_STRING BestObjectName; // File Name

	if (!NT_SUCCESS(PhGetHandleInformationEx((HANDLE)ProcessHandle, (HANDLE)handle->HandleValue, handle->ObjectTypeIndex, 0, NULL, NULL, &TypeName, &ObjectName, &BestObjectName, NULL)))
		return false;

	if (bFull)
	{
		// HACK: Some security products block NtQueryObject with ObjectTypeInformation and return an invalid type
		// so we need to lookup the TypeName using the TypeIndex. We should improve PhGetHandleInformationEx for this case
		// but for now we'll preserve backwards compat by doing the lookup here. (dmex)
		if (PhIsNullOrEmptyString(TypeName))
		{
			PPH_STRING typeName;

			if (typeName = PhGetObjectTypeIndexName(m_TypeIndex))
			{
				PhMoveReference(&TypeName, typeName);
			}
		}

		if (TypeName && PhEqualString2(TypeName, L"File", TRUE) && KphCommsIsConnected())
		{
			KPH_FILE_OBJECT_INFORMATION objectInfo;

			if (NT_SUCCESS(KphQueryInformationObject((HANDLE)ProcessHandle, (HANDLE)handle->HandleValue, KphObjectFileObjectInformation, &objectInfo, sizeof(KPH_FILE_OBJECT_INFORMATION), NULL)))
			{
				if (objectInfo.SharedRead)
					m_FileFlags |= PH_HANDLE_FILE_SHARED_READ;
				if (objectInfo.SharedWrite)
					m_FileFlags |= PH_HANDLE_FILE_SHARED_WRITE;
				if (objectInfo.SharedDelete)
					m_FileFlags |= PH_HANDLE_FILE_SHARED_DELETE;
			}
		}
	}

	m_TypeName = CastPhString(TypeName);
    m_OriginalName = CastPhString(ObjectName);
    m_FileName = CastPhString(BestObjectName);

	return true;
}

QFutureWatcher<bool>* CWinHandle::InitExtDataAsync(struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* handle, quint64 ProcessHandle)
{
	QFutureWatcher<bool>* pWatcher = new QFutureWatcher<bool>(this);
	pWatcher->setFuture(QtConcurrent::run([this, handle, ProcessHandle]() {
		return CWinHandle::InitExtDataAsync(this, handle, ProcessHandle);
	}));
	return pWatcher;
}

bool CWinHandle::InitExtDataAsync(CWinHandle* This, struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* handle, quint64 ProcessHandle)
{
	return This->InitExtData(handle, ProcessHandle, false);
}

bool CWinHandle__UpdateFileData(HANDLE ProcessHandle, HANDLE HandleId, QString& SubTypeName, quint64& FileSize, quint64& FilePosition, quint32* FileMode = NULL, int* FileType = NULL)
{
	NTSTATUS status;
	IO_STATUS_BLOCK isb;

	HANDLE fileHandle = NULL;

	FILE_FS_DEVICE_INFORMATION fileDeviceInfo;
	if (!KphCommsIsConnected() || !NT_SUCCESS(status = KphQueryVolumeInformationFile(ProcessHandle, HandleId, FileFsDeviceInformation, &fileDeviceInfo, sizeof(FILE_FS_DEVICE_INFORMATION), &isb)))
	{
		if (!NT_SUCCESS(status = NtDuplicateObject(ProcessHandle, HandleId, NtCurrentProcess(), &fileHandle, MAXIMUM_ALLOWED, 0, 0)))
			return false;
	
		status = NtQueryVolumeInformationFile(fileHandle, &isb, &fileDeviceInfo, sizeof(FILE_FS_DEVICE_INFORMATION), FileFsDeviceInformation);
	}

    BOOLEAN isFileOrDirectory = FALSE;
    BOOLEAN isConsoleHandle = FALSE;
	BOOLEAN isPipeHandle = FALSE;
    BOOLEAN isNetworkHandle = FALSE;

	if (NT_SUCCESS(status))
	{
		switch (fileDeviceInfo.DeviceType)
		{
		case FILE_DEVICE_NAMED_PIPE:
			isPipeHandle = TRUE;
			SubTypeName = "Pipe";
			break;
		case FILE_DEVICE_NETWORK:
			isNetworkHandle = TRUE;
			SubTypeName = "Network";
			break;
		case FILE_DEVICE_CD_ROM:
		case FILE_DEVICE_CD_ROM_FILE_SYSTEM:
		case FILE_DEVICE_CONTROLLER:
		case FILE_DEVICE_DATALINK:
		case FILE_DEVICE_DFS:
		case FILE_DEVICE_DISK:
		case FILE_DEVICE_DISK_FILE_SYSTEM:
		case FILE_DEVICE_VIRTUAL_DISK:
			isFileOrDirectory = TRUE;
			SubTypeName = "File or directory";
			break;
		case FILE_DEVICE_CONSOLE:
			isConsoleHandle = TRUE;
			SubTypeName = "Console";
			break;
		default:
			SubTypeName = "Other";
			break;
		}
	}

	if (FileMode)
	{
		// Note: These devices deadlock without a timeout (dmex)
        // 1) Named pipes
        // 2) \Device\ConDrv\CurrentIn
        // 3) \Device\VolMgrControl

		FILE_MODE_INFORMATION fileModeInfo;
		ULONG ReturnLength = 0;
		if (NT_SUCCESS(status = ((fileHandle != NULL)
			? PhCallNtQueryFileInformationWithTimeout(fileHandle, FileModeInformation, &fileModeInfo, sizeof(FILE_MODE_INFORMATION), &ReturnLength)
			: PhCallKphQueryFileInformationWithTimeout(ProcessHandle, HandleId, FileModeInformation, &fileModeInfo, sizeof(FILE_MODE_INFORMATION), &ReturnLength)
			)))
		{
			*FileMode = fileModeInfo.Mode;
		}
	}

	// NOTE: NtQueryInformationFile can hang on windows 7 at \Device\VolMgrControl (DX)
    if (isFileOrDirectory)
	// if(!isConsoleHandle)
    {
		FILE_STANDARD_INFORMATION fileStandardInfo;
		ULONG ReturnLength = 0;
        //if (NT_SUCCESS(NtQueryInformationFile(fileHandle, &isb, &fileStandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation)))
		if (NT_SUCCESS(status = ((fileHandle != NULL)
			? PhCallNtQueryFileInformationWithTimeout(fileHandle, FileStandardInformation, &fileStandardInfo, sizeof(FILE_STANDARD_INFORMATION), &ReturnLength)
			: PhCallKphQueryFileInformationWithTimeout(ProcessHandle, HandleId, FileStandardInformation, &fileStandardInfo, sizeof(FILE_STANDARD_INFORMATION), &ReturnLength)
			)))
        {
			if (FileType) *FileType = fileStandardInfo.Directory ? 2 : 1;

			SubTypeName = fileStandardInfo.Directory ? "Directory" : "File";

			FileSize = fileStandardInfo.EndOfFile.QuadPart;
        }

		FILE_POSITION_INFORMATION filePositionInfo;
		ReturnLength = 0;
		//if (NT_SUCCESS(NtQueryInformationFile(fileHandle, &isb, &filePositionInfo, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation)))
		if (NT_SUCCESS(status = ((fileHandle != NULL)
			? PhCallNtQueryFileInformationWithTimeout(fileHandle, FilePositionInformation, &filePositionInfo, sizeof(FILE_POSITION_INFORMATION), &ReturnLength)
			: PhCallKphQueryFileInformationWithTimeout(ProcessHandle, HandleId, FilePositionInformation, &filePositionInfo, sizeof(FILE_POSITION_INFORMATION), &ReturnLength)
			)))
		{
			FilePosition = filePositionInfo.CurrentByteOffset.QuadPart;
		}
    }
	
	if(fileHandle) 
		NtClose(fileHandle);
	
	return true;
}

bool CWinHandle::UpdateDynamicData(struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* handle, quint64 ProcessHandle)
{
	QWriteLocker Locker(&m_Mutex);

	BOOLEAN modified = FALSE;

	if (m_Attributes != handle->HandleAttributes)
	{
		m_Attributes = handle->HandleAttributes;
		modified = TRUE;
	}

	if (m_TypeName == "File")
    {
		QString SubTypeName;
		quint64 FileSize = 0;
		quint64 FilePosition = 0;

		CWinHandle__UpdateFileData((HANDLE)ProcessHandle, (HANDLE)m_HandleId, SubTypeName, FileSize, FilePosition);

		if (m_SubTypeName != SubTypeName)
		{
			m_SubTypeName = SubTypeName;
			modified = TRUE;
		}
		if (m_Size != FileSize)
		{
			m_Size = FileSize;
			modified = TRUE;
		}
		if (m_Position != FilePosition)
		{
			m_Position = FilePosition;
			modified = TRUE;
		}
    }
	else if(m_TypeName == "Section")
	{
		HANDLE sectionHandle;
		NTSTATUS status = NtDuplicateObject((HANDLE)ProcessHandle, (HANDLE)m_HandleId, NtCurrentProcess(), &sectionHandle, SECTION_QUERY | SECTION_MAP_READ, 0, 0 );
		if (!NT_SUCCESS(status))
			status = NtDuplicateObject((HANDLE)ProcessHandle, (HANDLE)m_HandleId, NtCurrentProcess(), &sectionHandle, SECTION_QUERY, 0, 0);

		if (NT_SUCCESS(status))
		{
			quint64 SectionSize = 0;

			SECTION_BASIC_INFORMATION sectionInfo;
			if (NT_SUCCESS(PhGetSectionBasicInformation(sectionHandle, &sectionInfo)))
			{
				SectionSize = sectionInfo.MaximumSize.QuadPart;
			}

			if (m_Size != SectionSize)
			{
				m_Size = SectionSize;
				modified = TRUE;
			}

			NtClose(sectionHandle);
		}
	}


	return modified;
}

/**
 * Enumerates all handles in a process.
 *
 * \param ProcessId The ID of the process.
 * \param ProcessHandle A handle to the process.
 * \param Handles A variable which receives a pointer to a buffer containing
 * information about the handles.
 * \param FilterNeeded A variable which receives a boolean indicating
 * whether the handle information needs to be filtered by process ID.
 */
NTSTATUS PhEnumHandlesGeneric(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ProcessHandle,
	_Out_ PSYSTEM_HANDLE_INFORMATION_EX *Handles,
	_Out_ PBOOLEAN FilterNeeded
)
{
	NTSTATUS status;

	// There are three ways of enumerating handles:
	// * On Windows 8 and later, NtQueryInformationProcess with ProcessHandleInformation is the most efficient method.
	// * On Windows XP and later, NtQuerySystemInformation with SystemExtendedHandleInformation.
	// * Otherwise, NtQuerySystemInformation with SystemHandleInformation can be used.

	if (KphCommsIsConnected())
	{
		PKPH_PROCESS_HANDLE_INFORMATION handles;
		PSYSTEM_HANDLE_INFORMATION_EX convertedHandles;
		ULONG i;

		// Enumerate handles using KProcessHacker. Unlike with NtQuerySystemInformation,
		// this only enumerates handles for a single process and saves a lot of processing.

		if (!NT_SUCCESS(status = KsiEnumerateProcessHandles(ProcessHandle, &handles)))
			goto FAILED;

		convertedHandles = (PSYSTEM_HANDLE_INFORMATION_EX)PhAllocate(
			FIELD_OFFSET(SYSTEM_HANDLE_INFORMATION_EX, Handles) +
			sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) * handles->HandleCount
		);

		convertedHandles->NumberOfHandles = handles->HandleCount;

		for (i = 0; i < handles->HandleCount; i++)
		{
			convertedHandles->Handles[i].Object = handles->Handles[i].Object;
			convertedHandles->Handles[i].UniqueProcessId = (HANDLE)ProcessId;
			convertedHandles->Handles[i].HandleValue = (HANDLE)handles->Handles[i].Handle;
			convertedHandles->Handles[i].GrantedAccess = (ULONG)handles->Handles[i].GrantedAccess;
			convertedHandles->Handles[i].CreatorBackTraceIndex = 0;
			convertedHandles->Handles[i].ObjectTypeIndex = handles->Handles[i].ObjectTypeIndex;
			convertedHandles->Handles[i].HandleAttributes = handles->Handles[i].HandleAttributes;
		}

		PhFree(handles);

		*Handles = convertedHandles;
		*FilterNeeded = FALSE;
	}
	else if (WindowsVersion >= WINDOWS_8 && theConf->GetBool("Options/EnableHandleSnapshot", true))
	{
		PPROCESS_HANDLE_SNAPSHOT_INFORMATION handles;
		PSYSTEM_HANDLE_INFORMATION_EX convertedHandles;
		ULONG i;

		if (!NT_SUCCESS(status = PhEnumProcessHandles(ProcessHandle, &handles)))
			goto FAILED;

		convertedHandles = (PSYSTEM_HANDLE_INFORMATION_EX)PhAllocate(
			FIELD_OFFSET(SYSTEM_HANDLE_INFORMATION_EX, Handles) +
			sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) * handles->NumberOfHandles
		);

		convertedHandles->NumberOfHandles = handles->NumberOfHandles;

		for (i = 0; i < handles->NumberOfHandles; i++)
		{
			convertedHandles->Handles[i].Object = 0;
			convertedHandles->Handles[i].UniqueProcessId = (HANDLE)ProcessId;
			convertedHandles->Handles[i].HandleValue = (HANDLE)handles->Handles[i].HandleValue;
			convertedHandles->Handles[i].GrantedAccess = handles->Handles[i].GrantedAccess;
			convertedHandles->Handles[i].CreatorBackTraceIndex = 0;
			convertedHandles->Handles[i].ObjectTypeIndex = (USHORT)handles->Handles[i].ObjectTypeIndex;
			convertedHandles->Handles[i].HandleAttributes = handles->Handles[i].HandleAttributes;
		}

		PhFreePage(handles);

		*Handles = convertedHandles;
		*FilterNeeded = FALSE;
	}
	else
	{
		PSYSTEM_HANDLE_INFORMATION_EX handles;
	FAILED:
		if (!NT_SUCCESS(status = PhEnumHandlesEx(&handles)))
			return status;

		*Handles = handles;
		*FilterNeeded = TRUE;
	}

	return status;
}
STATUS CWinHandle::SetAttribute(quint32 Attribute, bool bSet)
{
	QWriteLocker Locker(&m_Mutex);

    if (!KphCommsIsConnected())
		return ERR(TE_KProcessHackerUnavail);

	if(bSet)
		m_Attributes |= Attribute;
	else
		m_Attributes ^= Attribute;

	NTSTATUS status;
    HANDLE processHandle;
    if (NT_SUCCESS(status = PhOpenProcess(&processHandle, PROCESS_QUERY_LIMITED_INFORMATION, (HANDLE)m_ProcessId)))
    {
        OBJECT_HANDLE_FLAG_INFORMATION handleFlagInfo;

        handleFlagInfo.Inherit = !!(m_Attributes & OBJ_INHERIT);
        handleFlagInfo.ProtectFromClose = !!(m_Attributes & OBJ_PROTECT_CLOSE);

        status = KphSetInformationObject(processHandle, (HANDLE)m_HandleId, KphObjectHandleFlagInformation, &handleFlagInfo, sizeof(OBJECT_HANDLE_FLAG_INFORMATION));

        NtClose(processHandle);
    }

    if (!NT_SUCCESS(status))
    {
		return ERR(TE_SetHandleAttribute);
    }

    return OK;
}

bool CWinHandle::IsProtected() const
{
	return (GetAttributes() & OBJ_PROTECT_CLOSE) != 0;
}

STATUS CWinHandle::SetProtected(bool bSet) 
{
	return SetAttribute(OBJ_PROTECT_CLOSE, bSet);
}

bool CWinHandle::IsInherited() const
{
	return (GetAttributes() & OBJ_INHERIT) != 0;
}

STATUS CWinHandle::SetInherited(bool bSet)
{
	return SetAttribute(OBJ_INHERIT, bSet);
}
QList<int> CWinHandle::GetGrantedAccessRights() const
{
	QReadLocker Locker(&m_Mutex);
	return WinAccess__GetGrantedRights(m_GrantedAccess, m_TypeName);
}

QList<int> CWinHandle::GetFileAccessModeRights(quint32 Mode) const
{
	return WinAccess__GetFileModeRights(Mode);
}

//
// The granted-access mask through the type's generic mapping. Applying the
// mapping needs the object type, so it is done here; which four words come out
// of the four bits is the viewer's business.
//
quint32 CWinHandle::GetGenericAccess() const
{
	QReadLocker Locker(&m_Mutex);

	GENERIC_MAPPING genericMapping;
	PPH_STRING TypeName = CastQString(m_TypeName);

	quint32 Access = 0;
	if (TypeName && NT_SUCCESS(PhGetObjectTypeMask(&TypeName->sr, &genericMapping)))
	{
		if (FlagOn(m_GrantedAccess, genericMapping.GenericRead))		Access |= eGenericRead;
		if (FlagOn(m_GrantedAccess, genericMapping.GenericWrite))		Access |= eGenericWrite;
		if (FlagOn(m_GrantedAccess, genericMapping.GenericExecute))		Access |= eGenericExecute;
		if (FlagOn(m_GrantedAccess, genericMapping.GenericAll))			Access |= eGenericAll;
	}

	if (TypeName)
		PhDereferenceObject(TypeName);

	return Access;
}

QString CWinHandle::GetSecurityDescriptorSddl() const
{
	QReadLocker Locker(&m_Mutex);

	NTSTATUS status;
	PSECURITY_DESCRIPTOR securityDescriptor;
	PPH_STRING securityDescriptorString;

	status = PhGetObjectSecurity(
		(HANDLE)m_HandleId,
		OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
		DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION |
		ATTRIBUTE_SECURITY_INFORMATION | SCOPE_SECURITY_INFORMATION,
		&securityDescriptor
	);

	if (NT_SUCCESS(status))
	{
		status = PhGetSecurityDescriptorAsString(
			securityDescriptor,
			OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
			DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION |
			ATTRIBUTE_SECURITY_INFORMATION | SCOPE_SECURITY_INFORMATION,
			&securityDescriptorString
		);

		PhFree(securityDescriptor);
	}

	//
	// An empty descriptor is the honest answer for "could not be read"; the
	// viewer says so rather than showing a status code in a text field.
	//
	return NT_SUCCESS(status) ? CastPhString(securityDescriptorString) : QString();
}


//
// Turning a handle into the object it refers to. The factories live on the
// Windows classes because opening the object needs a handle duplicate from
// the owning process; the view only ever sees the abstract result.
//
//
// Decodes an ALPC port's flag word.
//
// Lives here rather than in the handle view because the flag constants are
// Windows kernel definitions; the view only receives the resulting list.
//
CTokenInfoPtr CWinHandle::GetToken() const
{
	return CTokenInfoPtr(CWinToken::TokenFromHandle(GetSystem(), GetProcessId(), GetHandleId()));
}

CJobInfoPtr CWinHandle::GetJob() const
{
	return CJobInfoPtr(CWinJob::JobFromHandle(GetSystem(), GetProcessId(), GetHandleId()));
}

QIODevice* CWinHandle::OpenDevice() const
{
	return CWinMemIO::FromHandle(GetProcessId(), GetHandleId());
}

VOID PhLoadSymbolProviderOptions(_Inout_ PPH_SYMBOL_PROVIDER SymbolProvider);

BOOLEAN NTAPI EnumGenericModulesCallback(_In_ PPH_MODULE_INFO Module, _In_opt_ PVOID Context)
{
	if (Module->Type == PH_MODULE_TYPE_MODULE || Module->Type == PH_MODULE_TYPE_WOW64_MODULE) {
		PPH_STRING Name = PhCreateString(Module->FileName->Buffer);
		PhLoadModuleSymbolProvider((PPH_SYMBOL_PROVIDER)Context, Name, (PVOID)Module->BaseAddress, Module->Size);
		PhDereferenceObject(Name);
	}
    return TRUE;
}


QVariantMap CWinHandle::GetHandleInfo() const
{
	QReadLocker Locker(&m_Mutex); 

	QVariantMap HandleInfo;

    HANDLE processHandle;
	if (!NT_SUCCESS(PhOpenProcess(&processHandle, PROCESS_DUP_HANDLE, (HANDLE)m_ProcessId)))
		return HandleInfo;
	
	OBJECT_BASIC_INFORMATION basicInfo;
	if (NT_SUCCESS(PhGetHandleInformation(processHandle, (HANDLE)m_HandleId, ULONG_MAX, &basicInfo, NULL, NULL, NULL)))
	{
		HandleInfo["References"] = (quint64)basicInfo.PointerCount;
		HandleInfo["Handles"] = (quint64)basicInfo.HandleCount;

		HandleInfo["Paged"] = (quint64)basicInfo.PagedPoolCharge;
		HandleInfo["VirtualSize"] = (quint64)basicInfo.NonPagedPoolCharge;
	}


	if(m_TypeName == "ALPC Port")
	{
        //
        // TODO this path doesn't use all the ALPC info returned yet
        // see: KPH_ALPC_BASIC_INFORMATION.State
        //
        KPH_ALPC_BASIC_INFORMATION kphAlpcInfo;
        if (KphCommsIsConnected() && NT_SUCCESS(KphAlpcQueryInformation(processHandle, (HANDLE)m_HandleId, KphAlpcBasicInformation, &kphAlpcInfo, sizeof(kphAlpcInfo), NULL)))
        {
			HandleInfo["Flags"] = (quint32)kphAlpcInfo.Flags;
			HandleInfo["SeqNumber"] = (quint64)kphAlpcInfo.SequenceNo;
			HandleInfo["Context"] = (quint64)kphAlpcInfo.PortContext;

			PKPH_ALPC_COMMUNICATION_NAMES_INFORMATION connectionNames;
			if (!NT_SUCCESS(KphAlpcQueryCommunicationsNamesInfo(processHandle, (HANDLE)m_HandleId, &connectionNames)))
			{
				connectionNames = NULL;
			}

			KPH_ALPC_COMMUNICATION_INFORMATION connectionInfo;
			if (NT_SUCCESS(KphAlpcQueryInformation(processHandle, (HANDLE)m_HandleId, KphAlpcCommunicationInformation, &connectionInfo, sizeof(connectionInfo), NULL)))
			{
				if (connectionInfo.ConnectionPort.OwnerProcessId)
				{
					HandleInfo["ConnectionPID"] = (quint64)connectionInfo.ConnectionPort.OwnerProcessId;

					if (connectionNames && connectionNames->ConnectionPort.Length > 0)
						HandleInfo["ConnectionPort"] = QString::fromWCharArray(connectionNames->ConnectionPort.Buffer, connectionNames->ConnectionPort.Length / sizeof(WCHAR));
				}

				if (connectionInfo.ServerCommunicationPort.OwnerProcessId)
				{
					HandleInfo["ServerComPID"] = (quint64)connectionInfo.ServerCommunicationPort.OwnerProcessId;

					if (connectionNames && connectionNames->ServerCommunicationPort.Length > 0)
						HandleInfo["ServerComPort"] = QString::fromWCharArray(connectionNames->ServerCommunicationPort.Buffer, connectionNames->ServerCommunicationPort.Length / sizeof(WCHAR));
				}

				if (connectionInfo.ClientCommunicationPort.OwnerProcessId)
				{
					HandleInfo["ClientComPID"] = (quint64)connectionInfo.ClientCommunicationPort.OwnerProcessId;

					if (connectionNames && connectionNames->ClientCommunicationPort.Length > 0)
						HandleInfo["ClientComPort"] = QString::fromWCharArray(connectionNames->ClientCommunicationPort.Buffer, connectionNames->ClientCommunicationPort.Length / sizeof(WCHAR));
				}

				if (connectionNames)
					PhFree(connectionNames);
			}
        }
		else
		{
			HANDLE alpcPortHandle;
			if (NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)m_HandleId, NtCurrentProcess(), &alpcPortHandle, READ_CONTROL, 0, 0)))
			{
				ALPC_BASIC_INFORMATION alpcInfo;
				if (NT_SUCCESS(NtAlpcQueryInformation(alpcPortHandle, AlpcBasicInformation, &alpcInfo, sizeof(ALPC_BASIC_INFORMATION), NULL)))
				{
					HandleInfo["Flags"] = (quint32)alpcInfo.Flags;
					HandleInfo["SeqNumber"] = (quint64)alpcInfo.SequenceNo;
					HandleInfo["Context"] = (quint64)alpcInfo.PortContext;
				}

				//if (WindowsVersion >= WINDOWS_10_19H2)
				//{
				//	ALPC_SERVER_SESSION_INFORMATION serverInfo;
				//
				//	if (NT_SUCCESS(NtAlpcQueryInformation(alpcPortHandle, AlpcServerSessionInformation, &serverInfo, sizeof(ALPC_SERVER_SESSION_INFORMATION), NULL)))
				//	{
				//		HandleInfo["SessionId"] = (quint64)serverInfo.SessionId;
				//		HandleInfo["ProcessId"] = (quint64)serverInfo.ProcessId;
				//	}
				//}

				NtClose(alpcPortHandle);
			}
		}
	}
	else if(m_TypeName == "File")
	{
		QString SubTypeName;
		quint64 FileSize = 0;
		quint64 FilePosition = 0;
		quint32 FileMode = 0;
		int FileType = 0;

		CWinHandle__UpdateFileData(processHandle, (HANDLE)m_HandleId, SubTypeName, FileSize, FilePosition, &FileMode, &FileType);
		
		HandleInfo["Mode"] = FileMode;

		if (FileType != 0)
		{
			HandleInfo["IsDir"] = FileType == 2;
			HandleInfo["Size"] = FileSize;
			HandleInfo["Position"] = FilePosition;
		}

		HANDLE fileObjectDriver;
		if (KphCommsIsConnected() && NT_SUCCESS(KphQueryInformationObject(processHandle, (HANDLE)m_HandleId, KphObjectFileObjectDriver, &fileObjectDriver, sizeof(HANDLE), NULL)))
		{
			PPH_STRING string;

			if (NT_SUCCESS(PhGetDriverName(fileObjectDriver, &string)))
				HandleInfo["DrvDevice"] = CastPhString(string);

			if (NT_SUCCESS(PhGetDriverImageFileName(fileObjectDriver, &string)))
				HandleInfo["DrvImage"] = CastPhString(string);

			NtClose(fileObjectDriver);
		}
	}
	else if(m_TypeName == "Section")
	{
		HANDLE sectionHandle;
		NTSTATUS status = NtDuplicateObject(processHandle, (HANDLE)m_HandleId, NtCurrentProcess(), &sectionHandle, SECTION_QUERY | SECTION_MAP_READ, 0, 0 );
		if (!NT_SUCCESS(status))
			status = NtDuplicateObject(processHandle, (HANDLE)m_HandleId, NtCurrentProcess(), &sectionHandle, SECTION_QUERY, 0, 0);

		if (NT_SUCCESS(status))
		{
			SECTION_BASIC_INFORMATION sectionInfo;
            
			if (NT_SUCCESS(PhGetSectionBasicInformation(sectionHandle, &sectionInfo)))
			{
				HandleInfo["Attribs"] = (quint32)sectionInfo.AllocationAttributes;
				HandleInfo["Size"] = (quint64)sectionInfo.MaximumSize.QuadPart;
			}

			PPH_STRING fileName = NULL;
			if (NT_SUCCESS(PhGetSectionFileName(sectionHandle, &fileName)))
			{
				PPH_STRING newFileName;

				if (newFileName = PhResolveDevicePrefix(&fileName->sr)) 
				{
					PhDereferenceObject(fileName);
					fileName = newFileName;
				}
			}

			HandleInfo["File"] = CastPhString(fileName);

			NtClose(sectionHandle);
		}
	}
	else if(m_TypeName == "Mutant")
	{
		HANDLE mutantHandle;
		if (NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)m_HandleId, NtCurrentProcess(), &mutantHandle, SEMAPHORE_QUERY_STATE, 0, 0)))
		{
			MUTANT_BASIC_INFORMATION mutantInfo;
			MUTANT_OWNER_INFORMATION ownerInfo;

			if (NT_SUCCESS(PhGetMutantBasicInformation(mutantHandle, &mutantInfo)))
			{
				HandleInfo["Count"] = (qint32)mutantInfo.CurrentCount;
				HandleInfo["Abandoned"] = mutantInfo.AbandonedState;
			}

			if (NT_SUCCESS(PhGetMutantOwnerInformation(mutantHandle, &ownerInfo)))
			{
				HandleInfo["OwnerPID"] = (quint64)ownerInfo.ClientId.UniqueProcess;
				HandleInfo["OwnerTID"] = (quint64)ownerInfo.ClientId.UniqueThread;
			}

			NtClose(mutantHandle);
		}
	}
	else if(m_TypeName == "Process")
	{
		HANDLE dupHandle;
		if (NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)m_HandleId, NtCurrentProcess(), &dupHandle, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0)))
		{
			/*PPH_STRING fileName;
			if (NT_SUCCESS(PhGetProcessImageFileName(dupHandle, &fileName)))
			{
					= CastPhString(fileName);
			}*/

			NTSTATUS exitStatus = STATUS_PENDING;
			PROCESS_BASIC_INFORMATION procInfo;
			if (NT_SUCCESS(PhGetProcessBasicInformation(dupHandle, &procInfo)))
			{
				HandleInfo["PID"] = (quint64)procInfo.UniqueProcessId;

				HandleInfo["ExitStatus"] = (qint32)procInfo.ExitStatus;
			}

			KERNEL_USER_TIMES times;
			if (NT_SUCCESS(PhGetProcessTimes(dupHandle, &times)))
			{
				HandleInfo["Created"] = FILETIME2time(times.CreateTime.QuadPart);
				if (exitStatus != STATUS_PENDING)
					HandleInfo["Exited"] = FILETIME2time(times.ExitTime.QuadPart);
			}

			NtClose(dupHandle);
		}
	}
	else if(m_TypeName == "Thread")
	{
		HANDLE dupHandle;
		if (NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)m_HandleId, NtCurrentProcess(), &dupHandle, THREAD_QUERY_LIMITED_INFORMATION, 0, 0)))
		{
			/*PPH_STRING name;
			if (NT_SUCCESS(PhGetThreadName(dupHandle, &name)))
			{
				= CastPhString(name);
			}*/

			NTSTATUS exitStatus = STATUS_PENDING;
			THREAD_BASIC_INFORMATION threadInfo;
			if (NT_SUCCESS(PhGetThreadBasicInformation(dupHandle, &threadInfo)))
			{
				HandleInfo["PID"] = (quint64)threadInfo.ClientId.UniqueProcess;
				HandleInfo["TID"] = (quint64)threadInfo.ClientId.UniqueThread;

				HandleInfo["ExitStatus"] = (qint32)threadInfo.ExitStatus;

				//if (NT_SUCCESS(PhOpenProcess(
				//    &processHandle,
				//    PROCESS_QUERY_LIMITED_INFORMATION,
				//    threadInfo.ClientId.UniqueProcess
				//    )))
				//{
				//    if (NT_SUCCESS(PhGetProcessModuleFileName(processHandle, &fileName)))
				//    {
				//        PhMoveReference(&fileName, PhGetFileName(fileName));
				//        PhSetListViewSubItem(Context->ListViewHandle, Context->ListViewRowCache[PH_HANDLE_GENERAL_INDEX_PROCESSTHREADNAME], 1, PhGetStringOrEmpty(fileName));
				//        PhDereferenceObject(fileName);
				//    }
				//
				//    NtClose(processHandle);
				//}
			}

			KERNEL_USER_TIMES times;
			if (NT_SUCCESS(PhGetThreadTimes(dupHandle, &times)))
			{
				HandleInfo["Created"] = FILETIME2time(times.CreateTime.QuadPart);
				if (exitStatus != STATUS_PENDING)
					HandleInfo["Exited"] = FILETIME2time(times.ExitTime.QuadPart);
			}

			NtClose(dupHandle);
		}
	}
	else if(m_TypeName == "Timer")
	{
		HANDLE timerHandle;
		if (NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)m_HandleId, NtCurrentProcess(), &timerHandle, TIMER_QUERY_STATE, 0, 0)))
		{
			TIMER_BASIC_INFORMATION basicInfo;
			if (NT_SUCCESS(PhGetTimerBasicInformation(timerHandle, &basicInfo)))
			{
				HandleInfo["Remaining"] = basicInfo.RemainingTime.QuadPart;
				HandleInfo["Signaled"] = basicInfo.TimerState;
			}

			NtClose(timerHandle);
		}
	}
	/*else if(m_TypeName == "TpWorkerFactory") // ToDo
	{
		HANDLE workerFactoryHandle;
		if (NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)m_HandleId, NtCurrentProcess(), &workerFactoryHandle, WORKER_FACTORY_QUERY_INFORMATION, 0, 0)))
		{
			WORKER_FACTORY_BASIC_INFORMATION basicInfo;
            if (NT_SUCCESS(NtQueryInformationWorkerFactory(workerFactoryHandle, WorkerFactoryBasicInformation, &basicInfo, sizeof(WORKER_FACTORY_BASIC_INFORMATION), NULL)))
            {
                PPH_SYMBOL_PROVIDER symbolProvider;
                PPH_STRING symbol = NULL;

                symbolProvider = PhCreateSymbolProvider(basicInfo.ProcessId);
                PhLoadSymbolProviderOptions(symbolProvider);

                if (symbolProvider->IsRealHandle)
                {
                    PhEnumGenericModules(basicInfo.ProcessId, symbolProvider->ProcessHandle, 0, EnumGenericModulesCallback, symbolProvider);

                    symbol = PhGetSymbolFromAddress(symbolProvider, (ULONG64)basicInfo.StartRoutine, NULL, NULL, NULL, NULL);
                }

                PhDereferenceObject(symbolProvider);

                if (symbol)
                {
                    //PhaFormatString(L"Worker Thread Start: %s", symbol->Buffer)->Buffer
                    PhDereferenceObject(symbol);
                }
                else
                {
                    //PhaFormatString(L"Worker Thread Start: 0x%Ix", basicInfo.StartRoutine)->Buffer;
                }
                //PhaFormatString(L"Worker Thread Context: 0x%Ix", basicInfo.StartParameter)->Buffer);
            }

			NtClose(workerFactoryHandle);
		}
	}*/

	NtClose(processHandle);

	return HandleInfo;
}

STATUS CWinHandle::Close(bool bForce)
{
	QWriteLocker Locker(&m_Mutex); 

	NTSTATUS status;
    HANDLE processHandle;
	if (NT_SUCCESS(status = PhOpenProcess(&processHandle, PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, (HANDLE)m_ProcessId)))
    {
#ifndef SAFE_MODE // in safe mode always check and fail
		if (!bForce)
#endif
		{
			BOOLEAN critical = FALSE;
			BOOLEAN strict = FALSE;

			if (WindowsVersion >= WINDOWS_10)
			{
				BOOLEAN breakOnTermination;
				if (NT_SUCCESS(PhGetProcessBreakOnTermination(processHandle, &breakOnTermination)))
				{
					if (breakOnTermination)
					{
						critical = TRUE;
					}
				}

				PROCESS_MITIGATION_POLICY_INFORMATION policyInfo;
				policyInfo.Policy = ProcessStrictHandleCheckPolicy;
				policyInfo.StrictHandleCheckPolicy.Flags = 0;
				if (NT_SUCCESS(NtQueryInformationProcess(processHandle, ProcessMitigationPolicy, &policyInfo, sizeof(PROCESS_MITIGATION_POLICY_INFORMATION), NULL)))
				{
					if (policyInfo.StrictHandleCheckPolicy.Flags != 0)
					{
						strict = TRUE;
					}
				}
			}

			if (critical && strict)
			{
				NtClose(processHandle);
				return ERR(TE_ConfirmCloseCriticalHandle, ERROR_CONFIRM);
			}
		}

        status = NtDuplicateObject(processHandle, (HANDLE)m_HandleId, NULL, NULL, 0, 0, DUPLICATE_CLOSE_SOURCE);

		NtClose(processHandle);

        if (!NT_SUCCESS(status))
        {
			return ERR(TE_CloseHandle, status);
        }
    }
    else
    {
        return ERR(TE_OpenProc2, status);
    }

	return OK;
}

static NTSTATUS PhpDuplicateHandleFromProcess(_Out_ PHANDLE Handle, _In_ ACCESS_MASK DesiredAccess, HANDLE ProcessId, HANDLE HandleId)
{
    NTSTATUS status;
    HANDLE processHandle;

    if (!NT_SUCCESS(status = PhOpenProcess(&processHandle, PROCESS_DUP_HANDLE, ProcessId )))
        return status;

    status = NtDuplicateObject(processHandle, HandleId, NtCurrentProcess(), Handle, DesiredAccess, 0, 0 );

    NtClose(processHandle);

    return status;
}

STATUS CWinHandle::DoHandleAction(EHandleAction Action)
{
	QWriteLocker Locker(&m_Mutex); 

	ACCESS_MASK DesiredAccess;
	switch (Action)
	{
		case eSemaphoreAcquire:	DesiredAccess = SYNCHRONIZE; break;
		case eSemaphoreRelease: DesiredAccess = SEMAPHORE_MODIFY_STATE; break;

		case eSetLow:
		case eSetHigh:			DesiredAccess = EVENT_PAIR_ALL_ACCESS; break;

		case eCancelTimer:		DesiredAccess = TIMER_MODIFY_STATE; break;

		default: /*eEvent...*/  DesiredAccess = EVENT_MODIFY_STATE; break;
	}

    NTSTATUS status;

	HANDLE processHandle;
	if (!NT_SUCCESS(status = PhOpenProcess(&processHandle, PROCESS_DUP_HANDLE, (HANDLE)m_ProcessId )))
        return ERR(TE_OpenProcHandle, status);

	HANDLE dupDandle;
	status = NtDuplicateObject(processHandle, (HANDLE)m_HandleId, NtCurrentProcess(), &dupDandle, DesiredAccess, 0, 0 );

    NtClose(processHandle);

	if (!NT_SUCCESS(status))
		return ERR(TE_OpenDuplicateHandle, status);


    switch (Action)
    {
    case eSemaphoreAcquire:
        {
            LARGE_INTEGER timeout;

            timeout.QuadPart = 0;
            NtWaitForSingleObject(dupDandle, FALSE, &timeout);
        }
        break;
    case eSemaphoreRelease:
        NtReleaseSemaphore(dupDandle, 1, NULL);
        break;

    case eEventSet:
        NtSetEvent(dupDandle, NULL);
        break;
    case eEventReset:
        NtResetEvent(dupDandle, NULL);
        break;
    case eEventPulse:
        NtPulseEvent(dupDandle, NULL);
        break;

	case eSetLow:
		NtSetLowEventPair(dupDandle);
        break;
	case eSetHigh:
        NtSetHighEventPair(dupDandle);
        break;

	case eCancelTimer:
		NtCancelTimer(dupDandle, NULL);
		break;
    }

    NtClose(dupDandle);

	return OK;
}

//
// Which handle, in which process. Plain layout so the context can travel as a
// byte copy owned by the security object.
//
struct SHandleRef
{
	HANDLE	ProcessId;
	HANDLE	HandleId;
};

NTSTATUS NTAPI CWinHandle__DuplicateHandle(_Out_ PHANDLE Handle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ PVOID Context)
{
	SHandleRef* pRef = (SHandleRef*)Context;
	return PhpDuplicateHandleFromProcess(Handle, DesiredAccess, pRef->ProcessId, pRef->HandleId);
}

NTSTATUS NTAPI CWinHandle__cbPermissionsClosed(_In_ HANDLE Handle, _In_ BOOLEAN Release, _In_opt_ PVOID Context)
{
	if (Release) {
		QPair<HANDLE, HANDLE>* pPair = (QPair<HANDLE, HANDLE>*)Context;
		delete pPair;
	}

	return STATUS_SUCCESS;
}

CSecurityEditablePtr CWinHandle::GetSecurityObject() const
{
	QReadLocker Locker(&m_Mutex);
	SHandleRef Context;
	Context.ProcessId = (HANDLE)m_ProcessId;
	Context.HandleId = (HANDLE)m_HandleId;
	QString Name = m_FileName;
	Locker.unlock();

	return CSecurityEditablePtr(new CWinSecurityObject(
		Name, "Handle",
		(CWinSecurityObject::POpenObject)CWinHandle__DuplicateHandle,
		QByteArray((const char*)&Context, sizeof(Context))));
}
