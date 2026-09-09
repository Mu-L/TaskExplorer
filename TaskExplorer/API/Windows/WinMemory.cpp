#include "stdafx.h"
#include "WinMemory.h"
#include "WindowsAPI.h"
#include "WinMemIO.h"

#include "ProcessHacker.h"
#include "ProcessHacker/memprv.h"

CWinMemory::CWinMemory(QObject *parent) 
	: CMemoryInfo(parent) 
{
	memset(&u, 0, sizeof(u));
}

CWinMemory::~CWinMemory()
{
	
}

void CWinMemory::InitBasicInfo(struct _MEMORY_BASIC_INFORMATION* basicInfo, void* ProcessId)
{
	m_ProcessId = (quint64)ProcessId;

	m_BaseAddress = (quint64)basicInfo->BaseAddress;
	m_AllocationBase = (quint64)basicInfo->AllocationBase;
	m_AllocationProtect = basicInfo->AllocationProtect;
	m_RegionSize = basicInfo->RegionSize;
	m_State = basicInfo->State;
	m_Protect = basicInfo->Protect;
	m_Type = basicInfo->Type;
}

quint32 CWinMemory::GetPageSize() const
{
	return PAGE_SIZE;
}

bool CWinMemory::IsExecutable() const
{
	return (GetProtection() & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

bool CWinMemory::IsBitmapRegion() const
{
	QReadLocker Locker(&m_Mutex);
	return m_RegionType == CfgBitmapRegion || m_RegionType == CfgBitmap32Region;
}

bool CWinMemory::IsFree() const
{
	return (GetState() & MEM_FREE) != 0;
}

bool CWinMemory::IsMapped() const
{
	return (GetType() & (MEM_MAPPED | MEM_IMAGE)) != 0;
}

bool CWinMemory::IsPrivate() const
{
	return (GetType() & MEM_PRIVATE) != 0; 
}


quint8 CWinMemory::GetSigningLevel() const 
{ 
    QReadLocker Locker(&m_Mutex);
    return u.MappedFile.SigningLevel; 
}

STATUS CWinMemory::SetProtect(quint32 Protect)
{
	NTSTATUS status;
	HANDLE processHandle;

	if (NT_SUCCESS(status = PhOpenProcess(&processHandle, PROCESS_VM_OPERATION, (HANDLE)GetProcessId())))
	{
		QWriteLocker Locker(&m_Mutex);

		PVOID baseAddress;
		SIZE_T regionSize;
		ULONG oldProtect;

		baseAddress = (PVOID)m_BaseAddress;
		regionSize = m_RegionSize;

		status = NtProtectVirtualMemory(
			processHandle,
			&baseAddress,
			&regionSize,
			(ULONG)Protect,
			&oldProtect
			);

		if (NT_SUCCESS(status))
			m_Protect = Protect;
	}

	if (!NT_SUCCESS(status))
		return ERR(TE_ChangeMemoryProtection, status);
	return OK;
}

STATUS CWinMemory::DumpMemory(QIODevice* pFile)
{
	if (!IsAllocationBase() && (GetState() & MEM_COMMIT) == 0)
		return ERR(TE_NotDumpableMemory, -1);

	QReadLocker Locker(&m_Mutex);

	NTSTATUS status;
	HANDLE processHandle;
	if (!NT_SUCCESS(status = PhOpenProcess(&processHandle, PROCESS_VM_READ, (HANDLE)m_ProcessId)))
		return ERR(TE_OpenProc2, status);

	PVOID buffer = PhAllocatePage(PAGE_SIZE, NULL);

	for (size_t offset = 0; offset < m_RegionSize; offset += PAGE_SIZE)
	{
		if (NT_SUCCESS(NtReadVirtualMemory(processHandle, PTR_ADD_OFFSET((PVOID)m_BaseAddress, offset), buffer, PAGE_SIZE, NULL)))
		{
			pFile->write((char*)buffer, PAGE_SIZE);
		}
	}

	PhFreePage(buffer);

	NtClose(processHandle);

	return OK;
}

STATUS CWinMemory::FreeMemory(bool Free)
{
	NTSTATUS status;
    HANDLE processHandle;

	if (NT_SUCCESS(status = PhOpenProcess(&processHandle, PROCESS_VM_OPERATION, (HANDLE)GetProcessId())))
    {
        PVOID baseAddress;
        SIZE_T regionSize;

        baseAddress = (PVOID)GetBaseAddress();

        if (!IsMapped())
        {
            // The size needs to be 0 if we're freeing.
            if (Free)
                regionSize = 0;
            else
                regionSize = GetRegionSize();

            status = NtFreeVirtualMemory(
                processHandle,
                &baseAddress,
                &regionSize,
                Free ? MEM_RELEASE : MEM_DECOMMIT
                );
        }
        else
        {
            status = NtUnmapViewOfSection(processHandle, baseAddress);
        }

        NtClose(processHandle);
    }

    if (!NT_SUCCESS(status))
    {
        //
        // Which operation was refused is the useful part; the platform's own
        // wording for the status travels with it as an argument.
        //
        const ETaskMsgCode Code = IsMapped() ? TE_UnmapSectionViewFailed
                                : Free       ? TE_FreeMemoryFailed
                                             : TE_DecommitMemoryFailed;

        return ERR(Code, QVariantList() << FormatNativeStatus(status), status);
    }
	return OK;
}

QIODevice* CWinMemory::MkDevice()
{
	if (!IsAllocationBase() && (GetState() & MEM_COMMIT) == 0)
		return NULL;

	return new CWinMemIO(GetBaseAddress(), GetRegionSize(), GetProcessId());
}



//
// The payload that belongs with a region, reported as values so the viewer can
// word it - see GUI/TaskStrings.cpp.
//
QString CWinMemory::GetRegionText() const
{
	QReadLocker Locker(&m_Mutex);
	return u_Custom_Text;
}

quint64 CWinMemory::GetRegionThreadId() const
{
	QReadLocker Locker(&m_Mutex);
	switch (m_RegionType)
	{
	case TebRegion:
	case Teb32Region:		return (quint64)u.Teb.ThreadId;
	case StackRegion:
	case Stack32Region:		return (quint64)u.Stack.ThreadId;
	}
	return 0;
}

quint32 CWinMemory::GetRegionIndex() const
{
	QReadLocker Locker(&m_Mutex);
	switch (m_RegionType)
	{
	case HeapRegion:
	case Heap32Region:
		return (quint32)u.Heap.Index + 1;
	case HeapSegmentRegion:
	case HeapSegment32Region:
		if (u_HeapSegment_HeapItem)
			return (quint32)u_HeapSegment_HeapItem->u.Heap.Index + 1;
		break;
	}
	return 0;
}

quint32 CWinMemory::GetRegionTypeExFlags() const
{
	QReadLocker Locker(&m_Mutex);

	if (!m_RegionTypeEx)
		return 0;

	quint32 Flags = 0;
	if (m_Private)					Flags |= eRegionPrivate;
	if (m_MappedDataFile)			Flags |= eRegionMappedDataFile;
	if (m_MappedImage)				Flags |= eRegionMappedImage;
	if (m_MappedPageFile)			Flags |= eRegionMappedPageFile;
	if (m_MappedPhysical)			Flags |= eRegionMappedPhysical;
	if (m_DirectMapped)				Flags |= eRegionDirectMapped;
	if (m_SoftwareEnclave)			Flags |= eRegionSoftwareEnclave;
	if (m_PageSize64K)				Flags |= eRegionPageSize64K;
	if (m_PlaceholderReservation)	Flags |= eRegionPlaceholder;
	if (m_MappedAwe)				Flags |= eRegionMappedAwe;
	if (m_MappedWriteWatch)			Flags |= eRegionMappedWriteWatch;
	if (m_PageSizeLarge)			Flags |= eRegionPageSizeLarge;
	if (m_PageSizeHuge)				Flags |= eRegionPageSizeHuge;
	return Flags;
}

static_assert(CMemoryInfo::ePageNoAccess          == PAGE_NOACCESS,           "page protection drifted");
static_assert(CMemoryInfo::ePageReadOnly          == PAGE_READONLY,           "page protection drifted");
static_assert(CMemoryInfo::ePageReadWrite         == PAGE_READWRITE,          "page protection drifted");
static_assert(CMemoryInfo::ePageWriteCopy         == PAGE_WRITECOPY,          "page protection drifted");
static_assert(CMemoryInfo::ePageExecute           == PAGE_EXECUTE,            "page protection drifted");
static_assert(CMemoryInfo::ePageExecuteRead       == PAGE_EXECUTE_READ,       "page protection drifted");
static_assert(CMemoryInfo::ePageExecuteReadWrite  == PAGE_EXECUTE_READWRITE,  "page protection drifted");
static_assert(CMemoryInfo::ePageExecuteWriteCopy  == PAGE_EXECUTE_WRITECOPY,  "page protection drifted");
static_assert(CMemoryInfo::ePageGuard             == PAGE_GUARD,              "page protection drifted");
static_assert(CMemoryInfo::ePageNoCache           == PAGE_NOCACHE,            "page protection drifted");
static_assert(CMemoryInfo::ePageWriteCombine      == PAGE_WRITECOMBINE,       "page protection drifted");

static_assert(CMemoryInfo::eMemCommit  == MEM_COMMIT,  "memory state drifted");
static_assert(CMemoryInfo::eMemReserve == MEM_RESERVE, "memory state drifted");
static_assert(CMemoryInfo::eMemFree    == MEM_FREE,    "memory state drifted");
static_assert(CMemoryInfo::eMemPrivate == MEM_PRIVATE, "memory type drifted");
static_assert(CMemoryInfo::eMemMapped  == MEM_MAPPED,  "memory type drifted");
static_assert(CMemoryInfo::eMemImage   == MEM_IMAGE,   "memory type drifted");

static_assert(CMemoryInfo::eSignUnchecked    == SE_SIGNING_LEVEL_UNCHECKED,    "signing level drifted");
static_assert(CMemoryInfo::eSignUnsigned     == SE_SIGNING_LEVEL_UNSIGNED,     "signing level drifted");
static_assert(CMemoryInfo::eSignAuthenticode == SE_SIGNING_LEVEL_AUTHENTICODE, "signing level drifted");
static_assert(CMemoryInfo::eSignStore        == SE_SIGNING_LEVEL_STORE,        "signing level drifted");
static_assert(CMemoryInfo::eSignMicrosoft    == SE_SIGNING_LEVEL_MICROSOFT,    "signing level drifted");
static_assert(CMemoryInfo::eSignWindows      == SE_SIGNING_LEVEL_WINDOWS,      "signing level drifted");
static_assert(CMemoryInfo::eSignWindowsTcb   == SE_SIGNING_LEVEL_WINDOWS_TCB,  "signing level drifted");

static_assert(CMemoryInfo::eRegionCustom            == CustomRegion,               "region type drifted");
static_assert(CMemoryInfo::eRegionMappedFile        == MappedFileRegion,           "region type drifted");
static_assert(CMemoryInfo::eRegionPeb               == PebRegion,                  "region type drifted");
static_assert(CMemoryInfo::eRegionTeb               == TebRegion,                  "region type drifted");
static_assert(CMemoryInfo::eRegionStack             == StackRegion,                "region type drifted");
static_assert(CMemoryInfo::eRegionHeap              == HeapRegion,                 "region type drifted");
static_assert(CMemoryInfo::eRegionHeapSegment       == HeapSegmentRegion,          "region type drifted");
static_assert(CMemoryInfo::eRegionApiSetMap         == ApiSetMapRegion,            "region type drifted");
static_assert(CMemoryInfo::eRegionTelemetryCoverage == TelemetryCoverageRegion,    "region type drifted");
