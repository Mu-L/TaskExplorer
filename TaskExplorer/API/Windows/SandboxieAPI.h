#pragma once
#include "../../taskcore_global.h"

#include <QObject>

#define CONF_GET_NO_GLOBAL          0x40000000L
#define CONF_GET_NO_EXPAND          0x20000000L
#define CONF_GET_NO_TEMPLS          0x10000000L

class TASKCORE_EXPORT CSandboxieAPI : public QObject
{
	Q_OBJECT

	TRACK_OBJECT(CSandboxieAPI)
public:
	CSandboxieAPI(QObject* parent = NULL);
	virtual ~CSandboxieAPI();

	//bool UpdateSandboxes();

	QString GetSandBoxName(quint64 ProcessId) const;

	bool IsSandBoxed(quint64 ProcessId) const;

	quint64 OpenOriginalToken(quint64 ProcessId) const;
	quint64 OpenOriginalToken(quint64 ProcessId, quint64 ThreadId) const;
	bool TestOriginalToken(quint64 ProcessId, quint64 ThreadId) const;

	bool QueryProcess(quint64 ProcessId, QString& BoxName, QString& ImagName, QString& SID, quint32* SessionId = NULL, quint64* CreationTime = NULL);

	void GetProcessPaths(quint64 ProcessId, QString& FilePath, QString& KeyPath, QString& IpcPath) const;

	void QueryPathList(quint64 ProcessId, quint32 path_code, QStringList& Paths) const;

	struct SbieIniValue
	{
		QString Name;
		quint32 Type = 0;
		QString Value;
	};
	virtual QList<SbieIniValue> GetIniSection(const QString& BoxName, qint32* pStatus = NULL, bool withTemplates = true, bool withGlobals = true) const;

	quint32 QueryProcessInfoEx(quint64 ProcessId, quint32* pil = NULL, quint32* pit = NULL);

	//
	// How Sandboxie classified the image a boxed process was started from, and
	// what it decided to do about it. Both are the service's own numbering.
	//
	enum EImageType
	{
		eImageUnspecified = 0,
		eImageSandboxieRpcSs,
		eImageSandboxieDcomLaunch,
		eImageSandboxieCrypto,
		eImageSandboxieWuAu,
		eImageSandboxieBits,
		eImageSandboxieSbieSvc,
		eImageMsiInstaller,
		eImageTrustedInstaller,
		eImageWuaucLt,
		eImageShellExplorer,
		eImageInternetExplorer,
		eImageMozillaFirefox,
		eImageWindowsMediaPlayer,
		eImageNullsoftWinamp,
		eImagePandoraKmPlayer,
		eImageWindowsLiveMail,
		eImageServiceModelReg,
		eImageRunDll32,
		eImageDllHost,
		eImageDllHostWinInetCache,
		eImageWispTis,
		eImageGoogleChrome,
		eImageGoogleUpdate,
		eImageAcrobatReader,
		eImageOfficeOutlook,
		eImageOfficeExcel,
		eImageFlashPlayerSandbox,
		eImagePluginContainer,
		eImageOtherWebBrowser,
		eImageOtherMailClient,
	};

	enum EImageFlag
	{
		eSbieValidProcess		= 0x00000001,
		eSbieForcedProcess		= 0x00000002,
		eSbieProcessIsStartExe	= 0x00000008,
		eSbieParentWasStartExe	= 0x00000010,
		eSbieImageFromSbieDir	= 0x00000020,
		eSbieImageFromSandbox	= 0x00000040,
		eSbieDropRights			= 0x00000080,
		eSbieRightsDropped		= 0x00000100,
		eSbieOpenAllWinClass	= 0x00002000,
		eSbieProcessInPcaJob	= 0x08000000,
		eSbieCreateConsoleHide	= 0x10000000,
		eSbieCreateConsoleShow	= 0x20000000,
		eSbieProtectedProcess	= 0x40000000,
		eSbieHostInjectProcess	= 0x80000000,
	};

protected:
	/*struct SBoxedProcess
	{
		quint64		ProcessId;

		QString		BoxName;
	};
	QMap<quint64, SBoxedProcess*> m_BoxedProcesses;

	struct SBoxInfo
	{
		QString		BoxName;

		QString		FileRoot;
		QString		KeyRoot;
		QString		IpcRoot;
	};
	QMap<QString, SBoxInfo*> m_SandBoxes;

	mutable QReadWriteLock m_Mutex;*/

private:
	struct SSandboxieAPI* m;
};

