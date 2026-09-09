#pragma once
#include <qobject.h>
#include "AbstractInfo.h"
#include "../../MiscHelpers/Common/Status.h"

class TASKCORE_EXPORT CMemoryInfo: public CAbstractInfoEx
{
	Q_OBJECT

	TRACK_OBJECT(CMemoryInfo)
public:
	CMemoryInfo(QObject *parent = nullptr);
	virtual ~CMemoryInfo();

	virtual quint64 GetProcessId() const			{ QReadLocker Locker(&m_Mutex); return m_ProcessId; }

	virtual quint64 GetBaseAddress() const			{ QReadLocker Locker(&m_Mutex); return m_BaseAddress; }
	virtual quint64 GetAllocationBase() const		{ QReadLocker Locker(&m_Mutex); return m_AllocationBaseItem.isNull() ? 0 : m_AllocationBaseItem.staticCast<CMemoryInfo>()->GetBaseAddress(); }
	virtual bool IsAllocationBase() const;
	//
	// Page protection, region state and kind, by the platform's own numbers -
	// asserted in WinMemory.cpp. Linux describes a mapping quite differently and
	// answers with its own reading; see GUI/TaskStrings.cpp.
	//
	enum EPageProtection
	{
		ePageNoAccess			= 0x001,
		ePageReadOnly			= 0x002,
		ePageReadWrite			= 0x004,
		ePageWriteCopy			= 0x008,
		ePageExecute			= 0x010,
		ePageExecuteRead		= 0x020,
		ePageExecuteReadWrite	= 0x040,
		ePageExecuteWriteCopy	= 0x080,
		ePageGuard				= 0x100,
		ePageNoCache			= 0x200,
		ePageWriteCombine		= 0x400,
	};

	enum EMemoryState
	{
		eMemCommit	= 0x00001000,
		eMemReserve	= 0x00002000,
		eMemFree	= 0x00010000,
	};

	enum EMemoryType
	{
		eMemPrivate	= 0x00020000,
		eMemMapped	= 0x00040000,
		eMemImage	= 0x01000000,
	};

	//
	// How far the image behind a mapping was verified. The numbering is the
	// kernel's; several of the values are vendor slots with no fixed meaning,
	// which is why they collapse to one reading.
	//
	//
	// What a region is being used for. The order is memprv.h's, asserted in
	// WinMemory.cpp; the payload that goes with some of them - a thread, a heap
	// index, a file name - is reported separately below.
	//
	enum EMemoryRegion
	{
		eRegionUnknown = 0,
		eRegionCustom,
		eRegionUnusable,
		eRegionMappedFile,
		eRegionUserSharedData,
		eRegionPeb,
		eRegionPeb32,
		eRegionTeb,
		eRegionTeb32,
		eRegionStack,
		eRegionStack32,
		eRegionHeap,
		eRegionHeap32,
		eRegionHeapSegment,
		eRegionHeapSegment32,
		eRegionCfgBitmap,
		eRegionCfgBitmap32,
		eRegionApiSetMap,
		eRegionHypervisorSharedData,
		eRegionReadOnlySharedMemory,
		eRegionCodePageData,
		eRegionGdiSharedHandleTable,
		eRegionShimData,
		eRegionActivationContextData,
		eRegionWerRegistrationData,
		eRegionSiloSharedData,
		eRegionTelemetryCoverage,
	};

	//
	// The text that goes with a custom or mapped-file region, and the thread or
	// heap a region belongs to. Zero and empty where they do not apply.
	//
	virtual QString GetRegionText() const			{ return QString(); }
	virtual quint64 GetRegionThreadId() const		{ return 0; }
	virtual quint32 GetRegionIndex() const			{ return 0; }

	//
	// The extended region attributes, which the platform reports as a set of
	// bits of its own; these are this application's numbering of them.
	//
	enum ERegionTypeEx
	{
		eRegionPrivate			= 0x0001,
		eRegionMappedDataFile	= 0x0002,
		eRegionMappedImage		= 0x0004,
		eRegionMappedPageFile	= 0x0008,
		eRegionMappedPhysical	= 0x0010,
		eRegionDirectMapped		= 0x0020,
		eRegionSoftwareEnclave	= 0x0040,
		eRegionPageSize64K		= 0x0080,
		eRegionPlaceholder		= 0x0100,
		eRegionMappedAwe		= 0x0200,
		eRegionMappedWriteWatch	= 0x0400,
		eRegionPageSizeLarge	= 0x0800,
		eRegionPageSizeHuge		= 0x1000,
	};
	virtual quint32 GetRegionTypeExFlags() const	{ return 0; }

	enum ESigningLevel
	{
		eSignUnchecked		= 0x0,
		eSignUnsigned		= 0x1,
		eSignEnterprise		= 0x2,
		eSignDeveloper		= 0x3,
		eSignAuthenticode	= 0x4,
		eSignCustom2		= 0x5,
		eSignStore			= 0x6,
		eSignAntimalware	= 0x7,
		eSignMicrosoft		= 0x8,
		eSignCustom4		= 0x9,
		eSignCustom5		= 0xA,
		eSignDynamicCodegen	= 0xB,
		eSignWindows		= 0xC,
		eSignCustom7		= 0xD,
		eSignWindowsTcb		= 0xE,
		eSignCustom6		= 0xF,
	};
	virtual quint64 GetRegionSize() const			{ QReadLocker Locker(&m_Mutex); return m_RegionSize; }
	virtual quint32 GetState() const				{ QReadLocker Locker(&m_Mutex); return m_State; }
	virtual bool IsFree() const = 0;
	virtual quint32 GetProtection() const			{ QReadLocker Locker(&m_Mutex); return m_Protect; }
	virtual quint32 GetAllocProtection() const		{ QReadLocker Locker(&m_Mutex); return m_AllocationProtect; }
	virtual bool IsExecutable() const = 0;
	virtual quint32 GetType() const					{ QReadLocker Locker(&m_Mutex); return m_Type; }
	virtual bool IsMapped() const = 0;
	virtual bool IsPrivate() const = 0;

	virtual quint64 GetCommittedSize() const		{ QReadLocker Locker(&m_Mutex); return m_CommittedSize; }
	virtual quint64 GetPrivateSize() const			{ QReadLocker Locker(&m_Mutex); return m_PrivateSize; }

	virtual int GetRegionType() const				{ QReadLocker Locker(&m_Mutex); return m_RegionType; }


	virtual quint64 GetTotalWorkingSet() const		{ QReadLocker Locker(&m_Mutex); return m_TotalWorkingSet; }
	virtual quint64 GetPrivateWorkingSet() const	{ QReadLocker Locker(&m_Mutex); return m_PrivateWorkingSet; }
	virtual quint64 GetSharedWorkingSet() const		{ QReadLocker Locker(&m_Mutex); return m_SharedWorkingSet; }
	virtual quint64 GetShareableWorkingSet() const	{ QReadLocker Locker(&m_Mutex); return m_ShareableWorkingSet; }
	virtual quint64 GetLockedWorkingSet() const		{ QReadLocker Locker(&m_Mutex); return m_LockedWorkingSet; }

	virtual quint64 GetSharedOriginalPages() const	{ QReadLocker Locker(&m_Mutex); return m_SharedOriginalPages; }
	virtual quint64 GetPriority() const				{ QReadLocker Locker(&m_Mutex); return m_Priority; }
	
	virtual STATUS SetProtect(quint32 Protect) = 0;
	virtual STATUS DumpMemory(QIODevice* pFile) = 0;
	virtual STATUS FreeMemory(bool Free) = 0;

	virtual QIODevice* MkDevice() = 0;

	//
	// ---- platform surface ----
	//
	// Everything either platform can report, so the models never need to know
	// which one answered. An implementation without the notion does not
	// override; the default below is the honest answer, and whether a column
	// built on it is worth showing is decided by GetOsType()/HasCapability().
	//
	// The size of a page on the target, which need not match this machine's.
	virtual quint32 GetPageSize() const				{ return 4096; }
	virtual bool    IsBitmapRegion() const			{ return false; }

	// Code-integrity signing level of the mapped image.
	virtual quint8  GetSigningLevel() const			{ return 0; }

protected:
	quint64				m_ProcessId;

	quint64				m_BaseAddress;
	quint64				m_AllocationBase;
    quint32				m_AllocationProtect;
	quint64 			m_RegionSize; // SIZE_T
    quint32 			m_State;
    quint32 			m_Protect;
    quint32 			m_Type;

	// todo: move to winmemory?
	quint64				m_CommittedSize;
	quint64				m_PrivateSize;

	quint64				m_TotalWorkingSet;
    quint64				m_PrivateWorkingSet;
    quint64				m_SharedWorkingSet;
    quint64				m_ShareableWorkingSet;
    quint64				m_LockedWorkingSet;

	quint64				m_SharedOriginalPages;
	quint64				m_Priority;

	int					m_RegionType; // PH_MEMORY_REGION_TYPE

	QSharedPointer<QObject>	m_AllocationBaseItem;
};

typedef QSharedPointer<CMemoryInfo> CMemoryPtr;
typedef QWeakPointer<CMemoryInfo> CMemoryRef;
