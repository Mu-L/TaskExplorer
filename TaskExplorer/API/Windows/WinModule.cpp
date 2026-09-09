#include "stdafx.h"
#include "WinModule.h"
#include "ProcessHacker.h"
#include "WindowsAPI.h"
#include "../../../MiscHelpers/Common/Settings.h"

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
#include <QtWin>
#endif

//
// QImage, for the encoder below. The only QtGui in the collector, and the
// reason TaskCore links Qt6::Gui on Windows and not on Linux.
//
#include <QImage>
#include <QBuffer>

//
// An icon handle turned into the bytes of a PNG.
//
// This runs on a worker thread, and what it produces is stored and later sent
// to whoever is looking - so it has to be data, not a QPixmap. A QPixmap needs
// a QGuiApplication, belongs to the thread that made it, and cannot be
// serialised; QImage has none of those problems and knows how to encode itself.
//
static QByteArray CWinModule__EncodeIcon(HICON Icon)
{
	const QImage Image = QImage::fromHICON(Icon);
	if (Image.isNull())
		return QByteArray();

	QByteArray Bytes;
	QBuffer Buffer(&Bytes);
	Buffer.open(QIODevice::WriteOnly);
	if (!Image.save(&Buffer, "PNG"))
		return QByteArray();

	return Bytes;
}

CWinModule::CWinModule(quint64 ProcessId, bool IsSubsystemProcess, QObject *parent) 
	: CModuleInfo(parent) 
{
	m_ProcessId = ProcessId;
	m_IsSubsystemProcess = IsSubsystemProcess;
	m_EntryPoint = NULL;
    m_Flags = 0;
    m_Type = 0;
	m_LoadTime = 0;
    m_LoadReason = 0;
    m_LoadCount = 0;

	m_EnclaveType = 0;
	m_EnclaveBaseAddress = 0;
	m_EnclaveSize = 0;

	m_StateFlags = 0;

	m_ImageMachine = 0;
	m_ImageCHPEVersion = 0;
	m_ImageTimeDateStamp = 0;
	m_ImageCharacteristics = 0;
	m_ImageDllCharacteristics = 0;
	m_ImageDllCharacteristicsEx = 0;
	m_ImageFlags = 0;
	m_GuardFlags = 0;

	m_ImageCoherencyStatus = 0;
	m_ImageCoherency = -1.0F;

	m_VerifyResult = VrUnknown;

	m_IsPacked = false;
	m_ImportFunctions = 0;
	m_ImportModules = 0;
}

CWinModule::~CWinModule()
{
}

extern "C" NTSTATUS NTAPI PhModuleItemReadVirtualMemoryCallback(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_Out_writes_bytes_(BufferSize) PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead,
	_In_opt_ PVOID Context
)
{
	_PH_MODULE_INFO* moduleItem = (_PH_MODULE_INFO*)Context;
	NTSTATUS status;

	if (moduleItem)
	{
		SIZE_T numberOfBytesRead = 0;

		if (moduleItem->Type == PH_MODULE_TYPE_KERNEL_MODULE)
			status = KphReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, &numberOfBytesRead);
		else
			status = PhReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, &numberOfBytesRead);

		if (NumberOfBytesRead)
			*NumberOfBytesRead = numberOfBytesRead;
	}
	else
	{
		status = STATUS_INVALID_PARAMETER_6;
	}

	return status;
}

bool CWinModule::InitStaticData(struct _PH_MODULE_INFO* moduleItem, quint64 ProcessHandle)
{
	QWriteLocker Locker(&m_Mutex);

	m_IsLoaded = true;
	m_FileNameNt = CastPhString(moduleItem->FileName, false);
	m_FileName = CastPhString(PhGetFileName(moduleItem->FileName));
	m_ModuleName = CastPhString(moduleItem->Name, false);

	m_BaseAddress = (quint64)moduleItem->BaseAddress;
	m_EntryPoint = (quint64)moduleItem->EntryPoint;
	m_Size = moduleItem->Size;
	m_Flags = moduleItem->Flags;
	m_Type = moduleItem->Type;
	m_LoadReason = moduleItem->LoadReason;
	m_LoadCount = moduleItem->LoadCount;
	m_LoadTime = FILETIME2time(moduleItem->LoadTime.QuadPart);
	m_ParentBaseAddress = (quint64)moduleItem->ParentBaseAddress;
	m_EnclaveType = moduleItem->EnclaveType;
	m_EnclaveBaseAddress = (quint64)moduleItem->EnclaveBaseAddress;
	m_EnclaveSize = moduleItem->EnclaveSize;

	if (m_IsSubsystemProcess)
    {
        // HACK: Update the module type. (TO-DO: Move into PhEnumGenericModules) (dmex)
        m_Type = -1;
    }
    else
    {
        // Fix up the load count. If this is not an ordinary DLL or kernel module, set the load count to 0.
        if (m_Type != PH_MODULE_TYPE_MODULE &&
            m_Type != PH_MODULE_TYPE_WOW64_MODULE &&
            m_Type != PH_MODULE_TYPE_KERNEL_MODULE)
        {
            m_LoadCount = 0;
        }
    }

	if (
		m_Type == PH_MODULE_TYPE_MODULE ||
		m_Type == PH_MODULE_TYPE_WOW64_MODULE ||
		m_Type == PH_MODULE_TYPE_MAPPED_IMAGE ||
		m_Type == PH_MODULE_TYPE_ENCLAVE_MODULE ||
		(m_Type == PH_MODULE_TYPE_KERNEL_MODULE &&
		(KsiLevel() == KphLevelMax)))
    {
        PH_REMOTE_MAPPED_IMAGE remoteMappedImage;

		PhInitializeRemoteMappedImage(
			&remoteMappedImage,
			PhModuleItemReadVirtualMemoryCallback,
			moduleItem
		);

        // Note:
        // On Windows 7 the LDRP_IMAGE_NOT_AT_BASE flag doesn't appear to be used
        // anymore. Instead we'll check ImageBase in the image headers. We read this in
        // from the process' memory because:
        //
        // 1. It (should be) faster than opening the file and mapping it in, and
        // 2. It contains the correct original image base relocated by ASLR, if present.

        //m_Flags &= ~LDRP_IMAGE_NOT_AT_BASE;

        if (NT_SUCCESS(PhLoadRemoteMappedImage(&remoteMappedImage, (HANDLE)ProcessHandle, &m_BaseAddress, m_Size)))
        {
			PIMAGE_DATA_DIRECTORY dataDirectory;
			PVOID imageBase = 0;
			ULONG entryPoint = 0;
			ULONG debugEntryLength;
			PVOID debugEntry;

            m_ImageTimeDateStamp = remoteMappedImage.NtHeaders->FileHeader.TimeDateStamp;
            m_ImageCharacteristics = remoteMappedImage.NtHeaders->FileHeader.Characteristics;

            if (remoteMappedImage.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            {
                PIMAGE_OPTIONAL_HEADER32 optionalHeader = (PIMAGE_OPTIONAL_HEADER32)&remoteMappedImage.NtHeaders->OptionalHeader;

                imageBase = (PVOID)optionalHeader->ImageBase;
                entryPoint = optionalHeader->AddressOfEntryPoint;
				m_ImageDllCharacteristics = optionalHeader->DllCharacteristics;
				m_ImageMachine = remoteMappedImage.NtHeaders32->FileHeader.Machine;
				m_ImageTimeDateStamp = remoteMappedImage.NtHeaders32->FileHeader.TimeDateStamp;
				m_ImageCharacteristics = remoteMappedImage.NtHeaders32->FileHeader.Characteristics;
            }
            else if (remoteMappedImage.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                PIMAGE_OPTIONAL_HEADER64 optionalHeader = (PIMAGE_OPTIONAL_HEADER64)&remoteMappedImage.NtHeaders->OptionalHeader;

                imageBase = (PVOID)optionalHeader->ImageBase;
                entryPoint = optionalHeader->AddressOfEntryPoint;
				m_ImageDllCharacteristics = optionalHeader->DllCharacteristics;
				m_ImageMachine = remoteMappedImage.NtHeaders64->FileHeader.Machine;
				m_ImageTimeDateStamp = remoteMappedImage.NtHeaders64->FileHeader.TimeDateStamp;
				m_ImageCharacteristics = remoteMappedImage.NtHeaders64->FileHeader.Characteristics;
            }

			if (m_BaseAddress != (quint64)imageBase)
				m_ImageNotAtBase = TRUE;

            if (entryPoint != 0)
                m_EntryPoint = (quint64)PTR_ADD_OFFSET(m_BaseAddress, entryPoint);

			if (NT_SUCCESS(PhGetRemoteMappedImageDataEntry(
				&remoteMappedImage,
				IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
				&dataDirectory
			)))
			{
				SetFlag(m_ImageFlags, LDRP_COR_IMAGE);
			}

			if (NT_SUCCESS(PhGetRemoteMappedImageDebugEntryByType(
				&remoteMappedImage,
				IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS,
				&debugEntryLength,
				&debugEntry
			)))
			{
				ULONG characteristics = ULONG_MAX;

				if (debugEntryLength == sizeof(ULONG))
					characteristics = *(PULONG)debugEntry;

				if (characteristics != ULONG_MAX)
					m_ImageDllCharacteristicsEx = characteristics;

				PhFree(debugEntry);
			}

			if (!NT_SUCCESS(PhGetRemoteMappedImageGuardFlags(
				&remoteMappedImage,
				(PULONG)&m_GuardFlags
			)))
			{
				m_GuardFlags = 0;
			}

            PhUnloadRemoteMappedImage(&remoteMappedImage);
        }
		else
		{
			PH_MAPPED_IMAGE mappedImage;

			// Query the file since we're unable to query memory. (dmex)


			PH_STRINGREF fileName;
			fileName.Buffer = (wchar_t*)m_FileNameNt.utf16();
			fileName.Length = m_FileNameNt.length() * sizeof(wchar_t);

			if (NT_SUCCESS(PhLoadMappedImageEx(&fileName, NULL, &mappedImage)))
			{
				ULONG entryPoint = 0;
				USHORT characteristics = 0;
				PIMAGE_DATA_DIRECTORY dataDirectory;
				PH_MAPPED_IMAGE_CFG cfgConfig = { NULL };

				m_ImageMachine = mappedImage.NtHeaders->FileHeader.Machine;
				m_ImageCHPEVersion = PhGetMappedImageCHPEVersion(&mappedImage);

				if (mappedImage.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
				{
					PIMAGE_OPTIONAL_HEADER32 optionalHeader = (PIMAGE_OPTIONAL_HEADER32)&mappedImage.NtHeaders32->OptionalHeader;

					entryPoint = optionalHeader->AddressOfEntryPoint;
					characteristics = optionalHeader->DllCharacteristics;
				}
				else if (mappedImage.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
				{
					PIMAGE_OPTIONAL_HEADER64 optionalHeader = (PIMAGE_OPTIONAL_HEADER64)&mappedImage.NtHeaders64->OptionalHeader;

					entryPoint = optionalHeader->AddressOfEntryPoint;
					characteristics = optionalHeader->DllCharacteristics;
				}

				if (entryPoint != 0)
					m_EntryPoint = (quint64)PTR_ADD_OFFSET(m_BaseAddress, entryPoint);

				if (characteristics != 0)
					m_ImageDllCharacteristics = characteristics;

				if (NT_SUCCESS(PhGetMappedImageDataDirectory(
					&mappedImage,
					IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
					&dataDirectory
				)))
				{
					SetFlag(m_ImageFlags, LDRP_COR_IMAGE);
				}

				if (NT_SUCCESS(PhGetMappedImageCfg(&cfgConfig, &mappedImage)))
				{
					m_GuardFlags = cfgConfig.GuardFlags;
				}

				PhUnloadMappedImage(&mappedImage);
			}
		}
    }

	if (m_Type == PH_MODULE_TYPE_MODULE ||
		m_Type == PH_MODULE_TYPE_WOW64_MODULE ||
		m_Type == PH_MODULE_TYPE_MAPPED_IMAGE ||
		m_Type == PH_MODULE_TYPE_KERNEL_MODULE)
	{
		if (m_Type == PH_MODULE_TYPE_KERNEL_MODULE && (KsiLevel() < KphLevelMax))
		{
			// The driver wasn't available or we failed verification preventing
			// us from checking driver coherency. Pass a special value so we
			// don't highlight incorrect entries by default. (dmex)
		}
		else if (!m_FileNameNt.isEmpty())
		{
			PPH_STRING Name = PhCreateString((wchar_t*)m_FileNameNt.utf16());
			m_ImageCoherencyStatus = PhGetProcessModuleImageCoherency(
				Name,
				(HANDLE)ProcessHandle,
				(PVOID)m_BaseAddress,
				m_Size,
				m_Type == PH_MODULE_TYPE_KERNEL_MODULE,
				PhImageCoherencyQuick, // todo add option to change level
				&m_ImageCoherency
			);
			PhDereferenceObject(Name);
		}
	}

	if (!m_FileNameNt.isEmpty())
	{
		PPH_STRING Name = PhCreateString((wchar_t*)m_FileNameNt.utf16());
		m_ImageKnownDll = PhIsKnownDllFileName(Name);
		PhDereferenceObject(Name);
	}

	InitFileInfo();

	return true;
}

bool CWinModule::InitStaticData(const QString& FileName)
{
	QWriteLocker Locker(&m_Mutex);

	m_IsLoaded = true;
	m_FileName = FileName;
	m_FileNameNt = "\\??\\" + FileName; // fixme
	
	InitFileInfo();

	return true;
}

void CWinModule::InitFileInfo()
{
	FILE_NETWORK_OPEN_INFORMATION networkOpenInfo;
	if (NT_SUCCESS(PhQueryFullAttributesFileWin32((PWSTR)m_FileName.toStdWString().c_str(), &networkOpenInfo)))
	{
		m_ModificationTime = FILETIME2time(networkOpenInfo.LastWriteTime.QuadPart);
		m_FileSize = networkOpenInfo.EndOfFile.QuadPart;
	}
}

bool CWinModule::ResolveRefServices()
{
	QWriteLocker Locker(&m_Mutex);

	static PQUERY_TAG_INFORMATION I_QueryTagInformation = NULL;
    static PH_INITONCE initOnce = PH_INITONCE_INIT;
    if (PhBeginInitOnce(&initOnce))
    {
        I_QueryTagInformation = (PQUERY_TAG_INFORMATION)PhGetModuleProcAddress(L"advapi32.dll", "I_QueryTagInformation");
        PhEndInitOnce(&initOnce);
    }

	if (!I_QueryTagInformation)
		return false;
	
	std::wstring ModuleName = m_ModuleName.toStdWString();

	TAG_INFO_NAMES_REFERENCING_MODULE namesReferencingModule;
	memset(&namesReferencingModule, 0, sizeof(TAG_INFO_NAMES_REFERENCING_MODULE));
	namesReferencingModule.InParams.ProcessId = m_ProcessId;
	namesReferencingModule.InParams.ModuleName = (wchar_t*)ModuleName.c_str();

	ULONG win32Result = I_QueryTagInformation(NULL, eTagInfoLevelNamesReferencingModule, &namesReferencingModule);

	if (win32Result == ERROR_NO_MORE_ITEMS)
		win32Result = ERROR_SUCCESS;

	if (win32Result != ERROR_SUCCESS)
		return false;

	if (!namesReferencingModule.OutParams.Names)
		return false;

	m_Services.clear();

	PCWSTR serviceName = namesReferencingModule.OutParams.Names;
	while (TRUE)
	{
		ULONG nameLength = (ULONG)PhCountStringZ(serviceName);
		if (nameLength == 0)
			break;

		m_Services.append(QString::fromWCharArray(serviceName, nameLength));

		serviceName += nameLength + 1;
	}

	LocalFree((HLOCAL)namesReferencingModule.OutParams.Names);
	
	return true;
}

bool CWinModule::InitStaticData(const QVariantMap& Module)
{
	QWriteLocker Locker(&m_Mutex);

	m_IsLoaded = false;
	//Module["Sequence"].toInt();
	m_ModuleName = Module["ImageName"].toString();
	m_BaseAddress = Module["BaseAddress"].toULongLong();
	m_Size = Module["Size"].toULongLong();
	m_LoadTime = Module["TimeStamp"].toULongLong();
	//Module["Checksum"].toByteArray();

	return true;
}

void CWinModule::ClearControlFlowGuardEnabled()
{
	QReadLocker Locker(&m_Mutex);
	m_ImageDllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_GUARD_CF;
}

void CWinModule::SetCetEnabled()
{
	QReadLocker Locker(&m_Mutex);
	m_ImageDllCharacteristicsEx |= IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT;
}

void CWinModule::ClearCetEnabled()
{
	QReadLocker Locker(&m_Mutex);
	m_ImageDllCharacteristicsEx &= ~IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT;
}

bool CWinModule::UpdateDynamicData(struct _PH_MODULE_INFO* module)
{
	QReadLocker Locker(&m_Mutex);

	BOOLEAN modified = FALSE;

	/*
        if (m_JustProcessed)
            modified = TRUE;

        m_JustProcessed = FALSE;

        if (m_LoadCount != module->LoadCount)
        {
            m_LoadCount = module->LoadCount;
            modified = TRUE;
        }
	*/
	return modified;
}

void CWinModule::InitAsyncData(const QString& PackageFullName)
{
	QReadLocker Locker(&m_Mutex);

	QVariantMap Params;
	Params["FileName"] = m_FileName;
	Params["FileNameNt"] = m_FileNameNt;
	Params["PackageFullName"] = PackageFullName;
	Params["IsSubsystemProcess"] = m_IsSubsystemProcess;

	// Note: this instance of CWinModule may be deleted before the async proces finishes,
	// so to make things simple and avoid emmory leaks we pass all params and results as a QVariantMap
	// its not the most eficient way but its simple and reliable.

	QFutureWatcher<QVariantMap>* pWatcher = new QFutureWatcher<QVariantMap>(this); // Note: the job will be canceled if the file will be deleted :D
	connect(pWatcher, SIGNAL(resultReadyAt(int)), this, SLOT(OnInitAsyncData(int)));
	connect(pWatcher, SIGNAL(finished()), pWatcher, SLOT(deleteLater()));
	pWatcher->setFuture(QtConcurrent::run([this, Params]() {
		return this->InitAsyncData(Params);
	}));
}

// Note: PhInitializeModuleVersionInfoCached does not look thread safe, so we have to guard it.
QMutex g_ModuleVersionInfoCachedMutex;

QVariantMap CWinModule::InitAsyncData(QVariantMap Params)
{
	QVariantMap Result;

	PPH_STRING FileNameWin32 = CastQString(Params["FileName"].toString());
	PPH_STRING FileName = CastQString(Params["FileNameNt"].toString());
	PPH_STRING PackageFullName = CastQString(Params["PackageFullName"].toString());
	BOOLEAN IsSubsystemProcess = Params["IsSubsystemProcess"].toBool();

	PH_IMAGE_VERSION_INFO VersionInfo = { NULL, NULL, NULL, NULL };

	// PhpProcessQueryStage1 Begin
	NTSTATUS status;

	if (!IsSubsystemProcess)
	{
		HICON SmallIcon;
		HICON LargeIcon;
		if (!PhExtractIcon(FileNameWin32->Buffer, &LargeIcon, &SmallIcon))
		{
			LargeIcon = NULL;
			SmallIcon = NULL;
		}

		if (SmallIcon)
		{
			Result["SmallIcon"] = CWinModule__EncodeIcon(SmallIcon);
			DestroyIcon(SmallIcon);
		}

		if (LargeIcon)
		{
			Result["LargeIcon"] = CWinModule__EncodeIcon(LargeIcon);
			DestroyIcon(LargeIcon);
		}

		// Version info.
		QMutexLocker Lock(&g_ModuleVersionInfoCachedMutex);
		PhInitializeImageVersionInfoCached(&VersionInfo, FileName, FALSE, theConf->GetBool("Options/EnableVersionSupport", true));
	}
	// PhpProcessQueryStage1 End

	// PhpProcessQueryStage2 Begin
	if (!IsSubsystemProcess)
	{
		NTSTATUS status;

		VERIFY_RESULT VerifyResult = VERIFY_RESULT(0); //VrUnknown
		PPH_STRING VerifySignerName = NULL;
		if(theConf->GetBool("Options/VerifySignatures", true))
			VerifyResult = PhVerifyFileCached(FileName, PackageFullName, &VerifySignerName, TRUE, FALSE);

		BOOLEAN IsPacked = FALSE;
		ulong ImportFunctions;
		ulong ImportModules;
		status = PhIsExecutablePacked(FileName, &IsPacked, &ImportModules, &ImportFunctions);

		// If we got an Module-related error, the Module is packed.
		if (status == STATUS_INVALID_IMAGE_NOT_MZ || status == STATUS_INVALID_IMAGE_FORMAT || status == STATUS_ACCESS_VIOLATION)
		{
			IsPacked = TRUE;
			ImportModules = ULONG_MAX;
			ImportFunctions = ULONG_MAX;
		}

		Result["VerifyResult"] = (int)VerifyResult;
		Result["VerifySignerName"] = CastPhString(VerifySignerName);
		Result["IsPacked"] = IsPacked;
		Result["ImportFunctions"] = (quint32)ImportFunctions;
		Result["ImportModules"] = (quint32)ImportModules;
	}

	if (/*PhEnableLinuxSubsystemSupport &&*/ IsSubsystemProcess)
	{
		QMutexLocker Lock(&g_ModuleVersionInfoCachedMutex);
		PhInitializeImageVersionInfoCached(&VersionInfo, FileName, TRUE, theConf->GetBool("Options/EnableVersionSupport", true));
	}
	// PhpProcessQueryStage2 End

	QVariantMap Infos;
	Infos["CompanyName"] = CastPhString(VersionInfo.CompanyName);
	Infos["Description"] = CastPhString(VersionInfo.FileDescription);
	Infos["FileVersion"] = CastPhString(VersionInfo.FileVersion);
	Infos["ProductName"] = CastPhString(VersionInfo.ProductName);

	Result["Infos"] = Infos;

	PhDereferenceObject(FileName);
	PhDereferenceObject(FileNameWin32);
	PhDereferenceObject(PackageFullName);

	return Result;
}

void CWinModule::OnInitAsyncData(int Index)
{
	QFutureWatcher<QVariantMap>* pWatcher = (QFutureWatcher<QVariantMap>*)sender();
	if (!pWatcher)
		return;

	QVariantMap Result = pWatcher->resultAt(Index);

	QWriteLocker Locker(&m_Mutex);

	m_SmallIcon = Result["SmallIcon"].toByteArray();
	m_LargeIcon = Result["LargeIcon"].toByteArray();

	m_FileDetails.clear();
	QVariantMap Infos = Result["Infos"].toMap();
	foreach(const QString& Key, Infos.keys())
		m_FileDetails[Key] = Infos[Key].toString();

	m_VerifyResult = (EVerifyResult)Result["VerifyResult"].toInt();
	m_VerifySignerName = Result["VerifySignerName"].toString();

	m_IsPacked = Result["IsPacked"].toBool();
	m_ImportFunctions = Result["ImportFunctions"].toUInt();
	m_ImportModules = Result["ImportModules"].toUInt();

	emit AsyncDataDone(Result["IsPacked"].toBool(), Result["ImportFunctions"].toUInt(), Result["ImportModules"].toUInt());
}

quint32 CWinModule::GetMitigationFlags() const
{
	QReadLocker Locker(&m_Mutex);

	quint32 Flags = 0;
	if (m_ImageDllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
		Flags |= eImageAslr;
	if (m_ImageDllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
		Flags |= eImageCfg;
	if (m_ImageDllCharacteristicsEx & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT)
		Flags |= eImageCet;
	return Flags;
}

STATUS CWinModule::Unload(bool bForce)
{
	HANDLE ProcessId = (HANDLE)m_ProcessId;

	NTSTATUS status;
    HANDLE processHandle;

    switch (m_Type)
    {
    case PH_MODULE_TYPE_MODULE:
    case PH_MODULE_TYPE_WOW64_MODULE:
		//if(!bForce)
		//	return ERR(TE_ConfirmUnloadModule, ERROR_CONFIRM);

        if (NT_SUCCESS(status = PhOpenProcess(&processHandle, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, ProcessId)))
        {
            status = PhUnloadDllProcess(processHandle, (PVOID)m_BaseAddress, 5000);

            NtClose(processHandle);
        }

        if (status == STATUS_DLL_NOT_FOUND)
        {
            return ERR(TE_FindModuleUnload);
        }

        if (!NT_SUCCESS(status))
        {
            return ERR(TE_UnloadModule);
        }

        break;

    case PH_MODULE_TYPE_KERNEL_MODULE:
		if(!bForce)
			return ERR(TE_ConfirmUnloadDriver, ERROR_CONFIRM);

		{
			std::wstring Name = m_ModuleName.toStdWString();
			PH_STRINGREF phName = PH_STRINGREF_INIT(Name.c_str());
			std::wstring FileName = m_FileName.toStdWString();
			PH_STRINGREF phFileName = PH_STRINGREF_INIT(FileName.c_str());
			status = PhUnloadDriver((PVOID)m_BaseAddress, &phName, &phFileName);
		}

        if (!NT_SUCCESS(status))
        {
			return ERR(TE_UnloadDriver, status);
        }

        break;

    case PH_MODULE_TYPE_MAPPED_FILE:
    case PH_MODULE_TYPE_MAPPED_IMAGE:
		//if(!bForce)
		//	return ERR(TE_ConfirmUnmapSection, ERROR_CONFIRM);

        if (NT_SUCCESS(status = PhOpenProcess(&processHandle, PROCESS_VM_OPERATION, ProcessId)))
        {
            status = NtUnmapViewOfSection(processHandle, (PVOID)m_BaseAddress);
            NtClose(processHandle);
        }

        if (!NT_SUCCESS(status))
        {
			return ERR(TE_UnmapSectionView, QVariantList() << m_BaseAddress);
        }

        break;

    default:
        return ERR(TE_UnknownModuleType);
    }

    return OK;
}

void CWinModule::SetModifiedPage(quint64 VirtualAddress)	
{ 
	QWriteLocker Locker(&m_Mutex); 
	SModPage& Page = m_ModifiedPages[VirtualAddress];
	if (!Page.VirtualAddress) {
		Page.VirtualAddress = VirtualAddress;
		qobject_cast<CWindowsAPI*>(m_pSystem)->GetSymbolProvider()->GetSymbolFromAddress(m_ProcessId, VirtualAddress, this, SLOT(OnSymbolFromAddress(quint64, quint64, int, const QString&, const QString&, const QString&)));
	}
}

void CWinModule::OnSymbolFromAddress(quint64 ProcessId, quint64 Address, int ResolveLevel, const QString& StartAddressString, const QString& FileName, const QString& SymbolName)
{
	QWriteLocker Locker(&m_Mutex);
	SModPage& Page = m_ModifiedPages[Address];
	if (!Page.VirtualAddress)
		Page.VirtualAddress = Address;
	Page.Name = StartAddressString;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
// CWinMainModule 

CWinMainModule::CWinMainModule(QObject *parent) 
	: CWinModule(-1, false, parent) 
{
	m_ImageSubsystem = 0;
	m_PebBaseAddress = 0;
	m_PebBaseAddress32 = 0;
}

bool CWinMainModule::InitStaticData(quint64 ProcessId, quint64 ProcessHandle, const QString& FileName, const QString& FileNameNt, bool IsSubsystemProcess, bool IsWow64)
{
	QWriteLocker Locker(&m_Mutex);

	m_IsLoaded = true;
	m_ProcessId = ProcessId;
	m_FileName = FileName;
	m_FileNameNt = FileNameNt;
	m_IsSubsystemProcess = IsSubsystemProcess;

	// subsystem
	if (m_IsSubsystemProcess)
    {
        m_ImageSubsystem = IMAGE_SUBSYSTEM_POSIX_CUI;
    }
    else if(ProcessHandle)
    {
		PROCESS_BASIC_INFORMATION basicInfo;
		if (NT_SUCCESS(PhGetProcessBasicInformation((HANDLE)ProcessHandle, &basicInfo)) && basicInfo.PebBaseAddress != 0)
		{
			m_PebBaseAddress = (quint64)basicInfo.PebBaseAddress;
			if (IsWow64)
			{
				PVOID peb32;
				PhGetProcessPeb32((HANDLE)ProcessHandle, &peb32);
				m_PebBaseAddress32 = (quint64)peb32;
			}

			PVOID imageBaseAddress;
			PH_REMOTE_MAPPED_IMAGE mappedImage;

			_PH_MODULE_INFO moduleItem;
			moduleItem.Type = m_Type;

			PhInitializeRemoteMappedImage(
				&mappedImage,
				PhModuleItemReadVirtualMemoryCallback,
				&moduleItem
			);

			if (NT_SUCCESS(NtReadVirtualMemory((HANDLE)ProcessHandle, PTR_ADD_OFFSET(basicInfo.PebBaseAddress, FIELD_OFFSET(PEB, ImageBaseAddress)), &imageBaseAddress, sizeof(PVOID), NULL)))
			{
				if (NT_SUCCESS(PhLoadRemoteMappedImage(&mappedImage, (HANDLE)ProcessHandle, imageBaseAddress, -1)))
				{
					PVOID imageBase = 0;
					ULONG entryPoint = 0;

					if (mappedImage.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
					{
						PIMAGE_OPTIONAL_HEADER32 optionalHeader = (PIMAGE_OPTIONAL_HEADER32)&mappedImage.NtHeaders->OptionalHeader;

						imageBase = (PVOID)optionalHeader->ImageBase;
						entryPoint = optionalHeader->AddressOfEntryPoint;
						m_ImageSubsystem = optionalHeader->Subsystem;
						m_ImageDllCharacteristics = optionalHeader->DllCharacteristics;
						m_ImageMachine = mappedImage.NtHeaders32->FileHeader.Machine;
						m_ImageTimeDateStamp = mappedImage.NtHeaders32->FileHeader.TimeDateStamp;
						m_ImageCharacteristics = mappedImage.NtHeaders32->FileHeader.Characteristics;
					}
					else if (mappedImage.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
					{
						PIMAGE_OPTIONAL_HEADER64 optionalHeader = (PIMAGE_OPTIONAL_HEADER64)&mappedImage.NtHeaders->OptionalHeader;

						imageBase = (PVOID)optionalHeader->ImageBase;
						entryPoint = optionalHeader->AddressOfEntryPoint;
						m_ImageSubsystem = optionalHeader->Subsystem;
						m_ImageDllCharacteristics = optionalHeader->DllCharacteristics;
						m_ImageMachine = mappedImage.NtHeaders64->FileHeader.Machine;
						m_ImageTimeDateStamp = mappedImage.NtHeaders64->FileHeader.TimeDateStamp;
						m_ImageCharacteristics = mappedImage.NtHeaders64->FileHeader.Characteristics;
					}

					if (m_BaseAddress != (quint64)imageBase)
						m_ImageNotAtBase = TRUE;

					if (entryPoint != 0)
						m_EntryPoint = (quint64)PTR_ADD_OFFSET(m_BaseAddress, entryPoint);

					PhUnloadRemoteMappedImage(&mappedImage);
				}
			}
		}

		PPH_STRING Name = PhCreateString((wchar_t*)m_FileNameNt.utf16());
		m_ImageCoherencyStatus = PhGetProcessImageCoherency(
			Name,
			(HANDLE)ProcessId,
			PhImageCoherencyQuick, // todo add option to change level
			&m_ImageCoherency
		);
		PhDereferenceObject(Name);
    }

	InitFileInfo();

	return true;
}

quint64 CWinMainModule::GetPebBaseAddress(bool bWow64) const
{
	QReadLocker Locker(&m_Mutex); 
	return bWow64 ? m_PebBaseAddress32 : m_PebBaseAddress;
}

//
// The load reason is only meaningful from Windows 8 onwards; before that the
// field is not filled in, so the target says so rather than letting a viewer
// read a stale zero as "static dependency".
//
qint32 CWinModule::GetLoadReason() const
{
	QReadLocker Locker(&m_Mutex);

	if (m_Type == PH_MODULE_TYPE_KERNEL_MODULE)
		return eLoadDynamic;

	if (m_Type != PH_MODULE_TYPE_MODULE && m_Type != PH_MODULE_TYPE_WOW64_MODULE)
		return eLoadReasonNotAvailable;

	if (WindowsVersion < WINDOWS_8)
		return eLoadReasonNotAvailable;

	return (qint32)m_LoadReason;
}

//
// The wire carries the platform's own numbering for all of this, so a drift
// has to break the build rather than a word on someone's screen.
//
static_assert(CModuleInfo::eModuleDll         == PH_MODULE_TYPE_MODULE,         "module type drifted");
static_assert(CModuleInfo::eModuleMappedFile  == PH_MODULE_TYPE_MAPPED_FILE,    "module type drifted");
static_assert(CModuleInfo::eModuleWow64Dll    == PH_MODULE_TYPE_WOW64_MODULE,   "module type drifted");
static_assert(CModuleInfo::eModuleKernel      == PH_MODULE_TYPE_KERNEL_MODULE,  "module type drifted");
static_assert(CModuleInfo::eModuleMappedImage == PH_MODULE_TYPE_MAPPED_IMAGE,   "module type drifted");
static_assert(CModuleInfo::eModuleEnclave     == PH_MODULE_TYPE_ENCLAVE_MODULE, "module type drifted");

static_assert(CModuleInfo::eLoadStaticDependency        == LoadReasonStaticDependency,        "load reason drifted");
static_assert(CModuleInfo::eLoadDelayloadDependency     == LoadReasonDelayloadDependency,     "load reason drifted");
static_assert(CModuleInfo::eLoadDynamic                 == LoadReasonDynamicLoad,             "load reason drifted");
static_assert(CModuleInfo::eLoadEnclaveDependency       == LoadReasonEnclaveDependency,       "load reason drifted");

static_assert(CModuleInfo::eMachineI386  == IMAGE_FILE_MACHINE_I386,  "image machine drifted");
static_assert(CModuleInfo::eMachineArmNt == IMAGE_FILE_MACHINE_ARMNT, "image machine drifted");
static_assert(CModuleInfo::eMachineAmd64 == IMAGE_FILE_MACHINE_AMD64, "image machine drifted");
static_assert(CModuleInfo::eMachineArm64 == IMAGE_FILE_MACHINE_ARM64, "image machine drifted");

static_assert(CModuleInfo::eEnclaveSgx  == ENCLAVE_TYPE_SGX,  "enclave type drifted");
static_assert(CModuleInfo::eEnclaveSgx2 == ENCLAVE_TYPE_SGX2, "enclave type drifted");
static_assert(CModuleInfo::eEnclaveVbs  == ENCLAVE_TYPE_VBS,  "enclave type drifted");
