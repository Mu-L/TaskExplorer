#pragma once
#include "../API/StatusEx.h"
#include "../MiscHelpers/Common/NetworkAccessManager.h"
#include "../MiscHelpers/Common/ProgressDialog.h"

#define UPDATE_INTERVAL (7 * 24 * 60 * 60)

/////////////////////////////////////////////////////////////////////////////////////////
// Updater Jobs

class CUpdaterJob : public QObject
{
	Q_OBJECT

protected:
	friend class COnlineUpdater;

	CUpdaterJob(const QVariantMap& Params, QObject* parent = nullptr) : QObject(parent)
	{
		m_Params = Params;
	}

	void SetProgressDialog(const CProgressDialogPtr& pDialog) { m_pProgress = pDialog; }

	QVariantMap			m_Params;
	CProgressDialogPtr	m_pProgress;
	bool				m_bCanceled = false;
};

/////////////////////////////////////////////////////////////////////////////////////////
// Network Jobs

class CNetworkJob : public CUpdaterJob
{
	Q_OBJECT

protected:
	friend class COnlineUpdater;

	CNetworkJob(const QVariantMap& Params, QObject* parent = nullptr) : CUpdaterJob(Params, parent) {}

	void SetReply(QNetworkReply* pReply)
	{
		m_pReply = pReply;
		connect(m_pReply, SIGNAL(finished()), this, SLOT(OnRequestFinished()));
		connect(m_pReply, SIGNAL(downloadProgress(qint64, qint64)), this, SLOT(OnDownloadProgress(qint64, qint64)));
		if (m_pProgress) connect(m_pProgress.data(), &CProgressDialog::Cancel, this, [&]() { 
			m_bCanceled = true;
			m_pReply->abort();
		});
	}

	virtual void Finish(QNetworkReply* pReply) = 0;

	QNetworkReply* m_pReply = nullptr;

private slots:
	void OnDownloadProgress(qint64 bytes, qint64 bytesTotal)
	{
		if (bytesTotal != 0 && !m_pProgress.isNull())
			m_pProgress->ShowProgress("", 100 * bytes / bytesTotal);
	}

	void OnRequestFinished()
	{
		QNetworkReply* pReply = qobject_cast<QNetworkReply*>(sender());
		Finish(pReply);
		pReply->deleteLater();
		deleteLater();
	}
};

class CGetUpdatesJob : public CNetworkJob
{
	Q_OBJECT

protected:
	friend class COnlineUpdater;

	CGetUpdatesJob(const QVariantMap& Params, QObject* parent = nullptr) : CNetworkJob(Params, parent) {}

	void Finish(QNetworkReply* pReply) override;

signals:
	void				UpdateData(const QVariantMap& Data, const QVariantMap& Params);
};

//
// The supporter certificate, fetched from the issuer.
//
// A job of its own rather than a use of CGetFileJob, because what comes back is
// not a file to save but either a certificate or a reason there is none: the
// service answers with the certificate as plain text, or with a JSON object
// carrying an error. Both arrive as a 200, so the two are told apart by what
// the body starts with.
//
class CGetCertJob : public CNetworkJob
{
	Q_OBJECT

protected:
	friend class COnlineUpdater;

	CGetCertJob(const QVariantMap& Params, QObject* parent = nullptr) : CNetworkJob(Params, parent) {}

	void Finish(QNetworkReply* pReply) override;

signals:
	//
	// The certificate, or an empty one with "error" filled in. Never both.
	//
	void				Certificate(const QByteArray& Certificate, const QVariantMap& Params);
};

class CGetFileJob : public CNetworkJob
{
	Q_OBJECT

protected:
	friend class COnlineUpdater;

	CGetFileJob(const QVariantMap& Params, QObject* parent = nullptr) : CNetworkJob(Params, parent) {}

	void Finish(QNetworkReply* pReply) override;

signals:
	void				Download(const QString& Path, const QVariantMap& Params);
};

/////////////////////////////////////////////////////////////////////////////////////////
// Utility Jobs

class CUtilityJob : public CUpdaterJob
{
	Q_OBJECT

protected:
	friend class COnlineUpdater;

	CUtilityJob(const QVariantMap& Params, QObject* parent = nullptr) : CUpdaterJob(Params, parent) {}

	bool Run(const QStringList Args)
	{
		m_pUpdUtil = new QProcess(this);
		m_pUpdUtil->setProgram(QApplication::applicationDirPath() + "/UpdUtil.exe");
		m_pUpdUtil->setArguments(Args);
		connect(m_pUpdUtil, SIGNAL(finished(int, QProcess::ExitStatus)), this, SLOT(OnPrepareFinished(int, QProcess::ExitStatus)));
		connect(m_pUpdUtil, SIGNAL(readyReadStandardOutput()), this, SLOT(OnPrepareOutput()));
		connect(m_pUpdUtil, SIGNAL(readyReadStandardError()), this, SLOT(OnPrepareError()));
		m_pUpdUtil->start();

		if (m_pUpdUtil->state() != QProcess::Running)
			return false;

		if (m_pProgress) {
			connect(m_pProgress.data(), &CProgressDialog::Cancel, this, [&]() {
				m_bCanceled = true;
				m_pUpdUtil->terminate();
			});
		}
		return true;
	}

	virtual void Finish(int exitCode) { emit Finished(exitCode, m_Params); }

	QProcess*			m_pUpdUtil = nullptr;

private slots:
	void OnPrepareOutput() {
		QByteArray Text = m_pUpdUtil->readAllStandardOutput();
		qDebug() << "UPD-OUT:\t" << Text;
		if (m_pProgress)
			m_pProgress->ShowStatus(Text.trimmed());
	}

	void OnPrepareError() {
		QByteArray Text = m_pUpdUtil->readAllStandardOutput();
		qDebug() << "UPD-ERR:\t" << Text;
	}

	void OnPrepareFinished(int exitCode, QProcess::ExitStatus exitStatus) {
		if (m_pProgress)
			m_pProgress->OnFinished();
		if (!m_bCanceled)
			Finish(exitCode);
		deleteLater();
	}

signals:
	void				Finished(int exitCode, const QVariantMap& Params);
};


/////////////////////////////////////////////////////////////////////////////////////////
// Online Updater

class COnlineUpdater : public QObject
{
	Q_OBJECT
public:
	COnlineUpdater(QObject* parent);

	void				GetUpdates(QObject* receiver, const char* member, const QVariantMap& Params = QVariantMap(), const CProgressDialogPtr& pDialog = CProgressDialogPtr());
	void				DownloadFile(const QString& Url, QObject* receiver, const char* member, const QVariantMap& Params = QVariantMap(), const CProgressDialogPtr& pDialog = CProgressDialogPtr());

	// Update Handling
	void				Process();

	void				CheckForUpdates(bool bManual);
	QDateTime			GetLastUpdateTime()		{ return m_LastUpdate; }
	bool 				HasUpdates()			{ return !m_UpdateVersion.isEmpty() || !m_InstallerVersion.isEmpty(); }
	QString				GetUpdateVersion()		{ return m_UpdateVersion + (m_UpdateNumber ? QString() + QChar('a' + (m_UpdateNumber - 1)) : QString()); }
	QString 			GetInstallerVersion()	{ return m_InstallerVersion; }
	bool				IsUpdateReady()			{ return m_UpdatePrepared; }
	bool				IsInstallerReady()		{ return !m_InstallerPath.isEmpty(); }

	bool				RunInstaller(bool bSilent);

	// Incremental updating
	bool				ApplyUpdate(bool bSilent);

	//
	// Asks the issuer for the certificate belonging to a serial number.
	//
	// The answer arrives at receiver/member as
	// (const QByteArray&, const QVariantMap&) - see CGetCertJob. Params may
	// carry "key", the UPDATEKEY out of a certificate already held, which is
	// how a renewal is recognised as belonging to the same person.
	//
	// The hardware id is sent only when it is needed: for a node-locked serial
	// and for an evaluation. There is no reason to hand it over otherwise.
	//
	void				GetSupportCert(const QString& Serial, QObject* receiver, const char* member,
									   const QVariantMap& Params = QVariantMap(),
									   const CProgressDialogPtr& pDialog = CProgressDialogPtr());

	//
	// A number that identifies this installation to the issuer and says nothing
	// about the machine.
	//
	// Made once and kept in the configuration. It exists so that two requests
	// can be recognised as coming from the same place - which the issuer needs
	// to limit how many evaluation certificates one installation asks for -
	// without a hardware id being sent for a request that does not need one.
	//
	static quint64		GetRandID();

	// Helpers
	static QString		GetCurrentVersion();
	static int			GetCurrentUpdate();

	static QString		GetUpdateDir(bool bCreate = false);

signals:
	void				StateChanged();

private slots:

	// Update Handling
	void				OnUpdateData(const QVariantMap& Data, const QVariantMap& Params);

	void				OnInstallerDownload(const QString& Path, const QVariantMap& Params);

	//void				OnTweaksDownload(const QString& Path, const QVariantMap& Params);

	// Incremental updating
	void				OnUpdateDownload(int exitCode, const QVariantMap& Params);

protected:

	void				StartNetworkJob(CNetworkJob* pJob, const QUrl& Url);

	// Update Handling
	QStringList			ScanUpdateFiles(const QVariantMap& Update);
	void				LoadState();
	void				UpdateState();
	void				ClearUpdate();
	void				ClearRelease();
	bool				HandleUpdate(const QVariantMap& Data);

	int					AskDownload(const QVariantMap& Update, bool bAuto);

	bool				DownloadInstaller(const QVariantMap& Release);
	static bool			RunInstaller2(const QString& FilePath, bool bSilent);

	bool				HandleUserMessage(const QVariantMap& Data);

	// Incremental updating
	bool				DownloadUpdate(const QVariantMap& Update, const QStringList& Files);
	QString				GetUpdErrorStr(int exitCode);
	bool				OnlyMetaDataChanged(const QStringList& Files);
	bool				ApplyUpdate(const QStringList& Files, bool bSilent);
	static RESULT(int)	RunUpdater(const QStringList& Params, bool bSilent, bool Wait = false);


	// Helpers
	static QString		MakeVersionStr(const QVariantMap& Data);
	static QString		ParseVersionStr(const QString& Str, int* pUpdate = NULL);

	static quint32		GetCurrentVersionInt();
	static quint32		VersionToInt(const QString& VersionStr);
	static bool			IsVersionNewer(const QString& VersionStr);

	QString				GetOnNewUpdateOption() const; // Incremental update
	QString				GetOnNewReleaseOption() const; // Release with installer

	CNetworkAccessManager*	m_RequestManager = nullptr;

	QStringList			m_IgnoredUpdates;

	QDateTime			m_LastUpdate;				// time of last update check
	enum ECheckState
	{
		eIdle = 0,
		eAuto,
		eManual,
		// pending actions
		eDownloadUpdate,
		eDownloadInstall,
		eApplyUpdate,
		eRunInstall,
	}					m_CheckState = eIdle;		// current operation or pending action
	QString				m_UpdateVersion;			// version of incremental update
	int					m_UpdateNumber = 0;			// index of incremental update	
	bool				m_UpdatePrepared = false;	// true if update files are ready to be applied
	QString				m_InstallerVersion;			// version of full upgrade
	QString				m_InstallerPath;			// path to downloaded installer
};
