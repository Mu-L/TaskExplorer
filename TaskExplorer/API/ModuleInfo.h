#pragma once
#include "../taskcore_global.h"
#include <qobject.h>
#include "AbstractInfo.h"
#include "../../MiscHelpers/Common/Status.h"


class TASKCORE_EXPORT CModuleInfo: public CAbstractInfo
{
	Q_OBJECT

	TRACK_OBJECT(CModuleInfo)
public:
	CModuleInfo(QObject *parent = nullptr);
	virtual ~CModuleInfo();

	virtual QString GetFileName() const						{ QReadLocker Locker(&m_Mutex); return m_FileName; }

	virtual quint64 GetFileSize() const						{ QReadLocker Locker(&m_Mutex); return m_FileSize; }
	virtual quint64 GetModificationTime() const				{ QReadLocker Locker(&m_Mutex); return m_ModificationTime; }

	virtual QString GetName() const							{ QReadLocker Locker(&m_Mutex); return m_ModuleName; }

	virtual quint64 GetBaseAddress() const 					{ QReadLocker Locker(&m_Mutex); return m_BaseAddress; }
	virtual quint64 GetSize() const 						{ QReadLocker Locker(&m_Mutex); return m_Size; }
	virtual quint64 GetParentBaseAddress() const 			{ QReadLocker Locker(&m_Mutex); return m_ParentBaseAddress; }
	virtual void SetParentBaseAddress(quint64 Address)		{ QWriteLocker Locker(&m_Mutex); m_ParentBaseAddress = Address; }

	virtual void SetFirst(bool bSet = true)					{ QWriteLocker Locker(&m_Mutex); m_IsFirst = bSet; }
	virtual bool IsFirst() const							{ QReadLocker Locker(&m_Mutex); return m_IsFirst; }

	virtual void SetLoaded(bool bSet)						{ QWriteLocker Locker(&m_Mutex); m_IsLoaded = bSet; }
	virtual bool IsLoaded() const							{ QReadLocker Locker(&m_Mutex); return m_IsLoaded; }

	virtual void SetFileInfos(const QMap<QString, QString>&	FileDetails) { QWriteLocker Locker(&m_Mutex); m_FileDetails = FileDetails; }
	virtual QString GetFileInfo(const QString& Name) const	{ QReadLocker Locker(&m_Mutex); return m_FileDetails[Name]; }

	//
	// The icon a binary carries, as the bytes of an image file - PNG, as it
	// happens, though whoever draws it should let the image reader work that
	// out rather than assume.
	//
	// Bytes rather than a QPixmap for two reasons. A QPixmap cannot be made
	// without a QGuiApplication, which a collector running as a daemon will
	// not have; and it cannot be sent anywhere, which is the whole point of
	// collecting on one machine and looking on another.
	//
	virtual void SetFileIcon(const QByteArray& SmallIcon, const QByteArray& LargeIcon = QByteArray())
															{ QWriteLocker Locker(&m_Mutex); m_SmallIcon = SmallIcon;  m_LargeIcon = LargeIcon; }
	virtual QByteArray GetFileIcon(bool bLarge = false) const	{ QReadLocker Locker(&m_Mutex); return (bLarge && !m_LargeIcon.isEmpty()) ? m_LargeIcon : m_SmallIcon; }

	virtual QSharedPointer<QObject>	GetProcess() const		{ QReadLocker Locker(&m_Mutex); return m_pProcess; }

	//
	// ---- platform surface ----
	//
	// Signature verification and image coherency exist on Windows today; a
	// Linux backend could report the same notions from an ELF signature or a
	// package manager's integrity check. Declared here so the modules view and
	// the process list can ask without knowing which system answered.
	//
	//
	// Outcome of checking the image's signature. Windows fills this from
	// WinVerifyTrust; a Linux backend could map a package manager's verdict
	// onto the same scale.
	//
	enum EVerifyResult
	{
		VrUnknown = 0,
		VrNoSignature,
		VrTrusted,
		VrExpired,
		VrRevoked,
		VrDistrust,
		VrSecuritySettings,
		VrBadSignature
	};
	virtual EVerifyResult GetVerifyResult() const	{ return VrUnknown; }

	// Heuristic packer detection, and the import counts it is derived from.
	virtual bool    IsPacked() const				{ return false; }
	virtual quint32 GetImportFunctions() const		{ return 0; }
	virtual quint32 GetImportModules() const		{ return 0; }

	virtual QString GetVerifySignerName() const		{ return QString(); }

	// How much of the on-disk image still matches what is mapped in memory.
	// Negative means "not measured".
	virtual float   GetImageCoherency() const		{ return -1.0f; }

	// The link timestamp from the image header.
	virtual quint64 GetTimeStamp() const			{ return 0; }

	//
	// A page of the mapped image whose contents no longer match the file on
	// disk - the basis of the "modified pages" tree. Detecting them needs a
	// comparison against the image, which only the collecting side can do.
	//
	struct SModPage
	{
		quint64		VirtualAddress = 0;
		QString		Name;
	};
	virtual void SetModifiedPage(quint64 VirtualAddress)	{ Q_UNUSED(VirtualAddress); }
	virtual QMap<quint64, SModPage> GetModifiedPages() const { return QMap<quint64, SModPage>(); }
	virtual void ClearModifiedPages()						{}

	// Reveal the module's file in the system's file manager.

	virtual QString GetFileNameNt() const			{ return QString(); }
	//
	// What kind of module this is, why it was loaded, and what it was built
	// for - by the numbers the platform uses, checked in WinModule.cpp.
	//
	enum EModuleType
	{
		eModuleUnknown		= 0,
		eModuleDll			= 1,
		eModuleMappedFile	= 2,
		eModuleWow64Dll		= 3,
		eModuleKernel		= 4,
		eModuleMappedImage	= 5,
		eModuleEnclave		= 6,
	};

	enum EModuleLoadReason
	{
		eLoadReasonNotAvailable				= -1,
		eLoadStaticDependency				= 0,
		eLoadStaticForwarderDependency		= 1,
		eLoadDynamicForwarderDependency		= 2,
		eLoadDelayloadDependency			= 3,
		eLoadDynamic						= 4,
		eLoadAsImage						= 5,
		eLoadAsData							= 6,
		eLoadEnclavePrimary					= 7,
		eLoadEnclaveDependency				= 8,
		eLoadPatchImage						= 9,
	};

	enum EImageMachine
	{
		eMachineI386	= 0x014c,
		eMachineArmNt	= 0x01c4,
		eMachineAmd64	= 0x8664,
		eMachineArm64	= 0xAA64,
	};

	enum EEnclaveType
	{
		eEnclaveSgx		= 0x01,
		eEnclaveSgx2	= 0x02,
		eEnclaveVbs		= 0x10,
	};

	virtual quint64 GetType() const					{ return 0; }
	virtual qint32  GetLoadReason() const			{ return eLoadReasonNotAvailable; }
	virtual quint16 GetLoadCount() const			{ return 0; }
	virtual quint64 GetLoadTime() const				{ return 0; }
	virtual quint64 GetEntryPoint() const			{ return 0; }

	virtual quint16 GetImageMachine() const			{ return 0; }
	virtual quint32 GetImageCHPEVersion() const		{ return 0; }
	//
	// Mitigations an image opted into in its own header. A module carries only
	// the three that are decided at link time; what is actually in force for a
	// running process is CProcessInfo's business.
	//
	enum EImageMitigation
	{
		eImageAslr	= 0x0001,	// IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		eImageCfg	= 0x0002,	// IMAGE_DLLCHARACTERISTICS_GUARD_CF
		eImageCet	= 0x0004,	// IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT
	};
	virtual quint32 GetMitigationFlags() const		{ return 0; }

	// Services hosted by this module, for a shared service DLL.
	virtual QStringList GetRefServices() const		{ return QStringList(); }

	// Enclave the module was loaded into, where the platform has enclaves.
	virtual quint32 GetEnclaveType() const			{ return 0; }
	virtual quint64 GetEnclaveBaseAddress() const	{ return 0; }
	virtual quint64 GetEnclaveSize() const			{ return 0; }

	virtual STATUS				Unload(bool bForce = false) = 0;

protected:
	friend class CWinModuleFinder;

	QString						m_FileName;
	quint64						m_FileSize;
	quint64						m_ModificationTime;

	QString						m_ModuleName;
	quint64						m_BaseAddress;
	quint64						m_Size;
    quint64						m_ParentBaseAddress;

	bool						m_IsFirst;
	bool						m_IsLoaded;

	QMap<QString, QString>		m_FileDetails;

	QByteArray					m_SmallIcon;
	QByteArray					m_LargeIcon;

	QSharedPointer<QObject>		m_pProcess;
};

typedef QSharedPointer<CModuleInfo> CModulePtr;
typedef QWeakPointer<CModuleInfo> CModuleRef;