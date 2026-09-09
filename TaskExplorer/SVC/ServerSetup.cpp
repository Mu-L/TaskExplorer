#include "stdafx.h"
#include "ServerSetup.h"
#include "../../MiscHelpers/Common/PasswordHash.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSettings>
#include <QRandomGenerator>
#include <QProcess>
#include <QStandardPaths>
#include <QThread>
#include <QRegularExpression>

#ifdef WIN32
#include "../API/Windows/WinAdmin.h"
#include <aclapi.h>
#include <shellapi.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

//
// The service name, and the file name under it, are literals rather than
// settings. A service somebody can rename is a service the next version cannot
// find to upgrade.
//
#define TASK_SERVER_KEY_FILE		"TaskServerKeys.ini"

//
// The same name CSettings is given as its group by all three front ends, so
// the machine-wide directory sits beside the per-user ones.
//
#define TASK_VENDOR_FOLDER			"Xanasoft"
#define TASK_SERVER_CONFIG_FILE		"TaskServer.ini"

QString CServerSetup::ServiceNameFor(const QString& InstanceName)
{
	//
	// The instance name *is* the service name. One field, one name, one thing
	// to get right: a machine running two of these has two services and two
	// endpoints, and they are called the same as each other.
	//
	// Empty means the default rather than a service with no name - a blank
	// field is somebody leaving it alone, not asking for something impossible.
	//
	return InstanceName.isEmpty() ? QStringLiteral(MY_DAEMON_NAME_STRING) : InstanceName;
}

QString CServerSetup::ServiceName()
{
	//
	// Read from the configuration rather than kept, because this is asked from
	// three programs and one of them is the settings page that has just changed
	// it. A QSettings read of one key is cheaper than the service call that
	// follows it.
	//
	SServerSetup Setup;
	ReadConfig(&Setup);
	return ServiceNameFor(Setup.Name);
}

QString CServerSetup::ServerBinaryPath()
{
#ifdef WIN32
	const QString Name = "TaskServer.exe";
#else
	const QString Name = "TaskServer";
#endif
	return QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(Name);
}

bool CServerSetup::IsAvailable()
{
	return QFile::exists(ServerBinaryPath());
}

//
// The directory the running program is in, without Qt.
//
// QCoreApplication::applicationDirPath needs an application object, and this is
// asked before there is one: the daemon installs its crash handler in main()
// before RunServer builds the QCoreApplication, and where the dumps go depends
// on where the configuration is. Asking the operating system directly has no
// such order to get wrong.
//
static QString ExecutableDir()
{
#ifdef WIN32
	wchar_t Path[MAX_PATH] = { 0 };
	if (!GetModuleFileNameW(NULL, Path, ARRAYSIZE(Path)))
		return QString();
	return QFileInfo(QString::fromWCharArray(Path)).absolutePath();
#else
	return QFileInfo(QFile::symLinkTarget("/proc/self/exe")).absolutePath();
#endif
}

QString CServerSetup::ConfigFilePath()
{
	//
	// A configuration beside the program wins, the way the viewer's own does.
	//
	// The viewer is portable when a TaskExplorer.ini sits next to it - see
	// CSettings - and this is the same rule for the same reason: a copy that
	// carries its own configuration is one that can be put on a stick, run from
	// a build directory, or kept beside a second instance without either of
	// them reaching into a machine-wide file the other is also using.
	//
	// Only when the file is already there. Creating one here would make every
	// installation portable by accident, and an installed copy's secrets do
	// belong somewhere an upgrade will not replace.
	//
	// The log and the crash dumps follow it, because both are derived from this
	// directory rather than named separately.
	//
	const QString Beside = ExecutableDir() + "/" TASK_SERVER_CONFIG_FILE;
	if (QFile::exists(Beside))
		return Beside;

#ifdef WIN32
	//
	// ProgramData, not the installation directory. A file that holds the
	// server's secrets would be inside whatever an installer or an update
	// replaces wholesale, and would be lost on the first upgrade.
	//
	// Under the vendor folder, which is where every other config directory of
	// ours already is - CSettings is given "Xanasoft" as its group name by all
	// three front ends, so the per-user settings live in Xanasoft/TaskExplorer
	// and Xanasoft/TaskServer. This is the machine-wide counterpart of those and
	// belongs beside them rather than one level up on its own.
	//
	// Only the leaf is locked down in WriteConfig, not the vendor folder, which
	// other products of ours share.
	//
	QString Base = QString::fromLocal8Bit(qgetenv("ProgramData"));
	if (Base.isEmpty())
		Base = "C:/ProgramData";
	return QDir(Base).absoluteFilePath(TASK_VENDOR_FOLDER "/TaskExplorer/" TASK_SERVER_CONFIG_FILE);
#else
	return QStringLiteral("/etc/taskexplorer/" TASK_SERVER_CONFIG_FILE);
#endif
}

bool CServerSetup::IsPrivileged()
{
#ifdef WIN32
	return IsElevated();
#else
	return geteuid() == 0;
#endif
}

QStringList CServerSetup::BuildArguments(const SServerSetup& Setup)
{
	Q_UNUSED(Setup);

	//
	// One argument, and it is not a setting.
	//
	// Everything this used to spell out - the port, the bind address, the
	// discovery switches, the key file - is in ConfigFilePath() now, which the
	// server reads for itself. What is left says what the process *is* rather
	// than what it does, and on Windows that has to be decided before anything
	// else: it has to reach the service control dispatcher within a few seconds
	// of starting or the manager gives up on it.
	//
	// The change is worth stating plainly, because a command line is a
	// configuration store people reach for without noticing what they have
	// chosen. It can only be edited by reconfiguring the service, it has to be
	// parsed back to be read, it is visible to every process on the machine, and
	// a server somebody starts by hand shares none of it. A file in a directory
	// only administrators can write has none of those properties - and now that
	// the file holds secrets, that last one is not a convenience but the point.
	//
	return QStringList() << "--service";
}

bool CServerSetup::ReadTransportKey(QString* pKey)
{
	if (!pKey)
		return false;
	pKey->clear();

	if (!IsPrivileged())
		return false;

	const QString File = ConfigFilePath();
	if (!QFile::exists(File))
		return false;

	QSettings Ini(File, QSettings::IniFormat);
	*pKey = Ini.value("Server/PSK").toString();
	return !pKey->isEmpty();
}

QString CServerSetup::GenerateTransportKey()
{
	//
	// QRandomGenerator::system() is the operating system's generator, not the
	// seeded one QRandomGenerator::global() gives. For a key that is the whole
	// difference.
	//
	QByteArray Key(32, 0);
	for (int i = 0; i < Key.size(); i++)
		Key[i] = (char)QRandomGenerator::system()->bounded(256);
	return QString::fromLatin1(Key.toHex());
}

#ifdef WIN32
//
// Locks a file or a directory down to SYSTEM and the administrators, and to
// nobody else.
//
// Inheritance is switched off rather than added to. Anything under ProgramData
// inherits an ACE letting every user read it, which for this file would mean
// every account on the machine can read the key that lets a viewer connect - so
// the inherited set is discarded and replaced, not appended to.
//
// bDirectory makes the two entries inheritable, which is the whole reason the
// directory is locked down as well as the file. QSettings does not write in
// place: it writes a temporary file beside the target and renames it over.
// The rename keeps the temporary file’s permissions, so a lone chmod of the
// target is undone by the next save - and this was found by looking, after a
// file that had just been "restricted" still showed Users:(RX).
//
static bool RestrictToAdministrators(const QString& Path, bool bDirectory, QString* pError)
{
	PSID pSystem = NULL, pAdmins = NULL;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

	if (!AllocateAndInitializeSid(&NtAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
			0, 0, 0, 0, 0, 0, 0, &pSystem) ||
		!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdmins))
	{
		if (pError)
			*pError = QString("could not build the security identifiers (%1)").arg((quint32)GetLastError());
		if (pSystem) FreeSid(pSystem);
		if (pAdmins) FreeSid(pAdmins);
		return false;
	}

	EXPLICIT_ACCESSW Access[2] = {};
	for (int i = 0; i < 2; i++)
	{
		Access[i].grfAccessPermissions = GENERIC_ALL;
		Access[i].grfAccessMode = SET_ACCESS;
		Access[i].grfInheritance = bDirectory
			? (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE) : NO_INHERITANCE;
		Access[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		Access[i].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	}
	Access[0].Trustee.ptstrName = (LPWSTR)pSystem;
	Access[1].Trustee.ptstrName = (LPWSTR)pAdmins;

	PACL pAcl = NULL;
	DWORD Result = SetEntriesInAclW(2, Access, NULL, &pAcl);
	if (Result == ERROR_SUCCESS)
	{
		const std::wstring Native = QDir::toNativeSeparators(Path).toStdWString();
		Result = SetNamedSecurityInfoW((LPWSTR)Native.c_str(), SE_FILE_OBJECT,
			DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
			NULL, NULL, pAcl, NULL);
	}

	if (pAcl) LocalFree(pAcl);
	FreeSid(pSystem);
	FreeSid(pAdmins);

	if (Result != ERROR_SUCCESS)
	{
		if (pError)
			*pError = QString("could not restrict access to %1 (%2)")
			.arg(QDir::toNativeSeparators(Path)).arg((quint32)Result);
		return false;
	}
	return true;
}
#endif

//
// Creates a directory that only administrators can write, or reports why not.
//
// Shared by the key file and the configuration because they live in the same
// directory and it has to be locked before either is created - a file born into
// an inheriting directory under ProgramData is readable by every account on the
// machine for as long as it takes to correct it, and QSettings replaces files by
// renaming a new one over the old, which discards whatever was set on the file
// itself. The directory is the only thing that holds.
//
// It follows that the configuration is administrators-only too, which is more
// than it needs on its own - it holds no secret. That is the price of keeping
// the key beside it, and it is the right way round: a server started by hand
// without privileges falls back to the built-in defaults, which is a smaller
// problem than a key file that is briefly world-readable.
//
// None of which applies to the directory the program is installed in. A
// configuration file sitting there is the portable case, and that directory is
// not ours to re-permission: it is whatever the person chose - a stick, a build
// output, a folder in their own profile - and it holds the program itself, not
// just this file. Locking it to administrators would take a copy that runs from
// a user's own directory and make it unreadable to the user who put it there.
// Portable means the file is where it is because somebody said so, and the
// permissions on it are theirs as well.
//
static STATUS EnsurePrivateDirectory(const QString& Path)
{
	QDir Dir(Path);
	if (!Dir.exists() && !Dir.mkpath("."))
		return ERR(TE_ServerKeyFileFailed, QVariantList() << QString("could not create %1").arg(Path));

	const QString Exe = ExecutableDir();
	if (!Exe.isEmpty())
	{
		const QString Here = QDir::cleanPath(QFileInfo(Path).absoluteFilePath());
		const QString There = QDir::cleanPath(QFileInfo(Exe).absoluteFilePath());
#ifdef WIN32
		const bool bPortable = (Here.compare(There, Qt::CaseInsensitive) == 0);
#else
		const bool bPortable = (Here == There);
#endif
		if (bPortable)
			return OK;
	}

#ifdef WIN32
	QString Error;
	if (!RestrictToAdministrators(Path, true, &Error))
		return ERR(TE_ServerKeyFileFailed, QVariantList() << Error);
#else
	if (chmod(Path.toLocal8Bit().constData(), S_IRWXU) != 0)
		return ERR(TE_ServerKeyFileFailed, QVariantList()
			<< QString("could not restrict %1 (errno %2)").arg(Path).arg(errno));
#endif
	return OK;
}

//
// ---- the configuration ----
//

//
// One group rather than the file's top level, because on Linux this is the same
// file the daemon keeps its own settings in - /etc/taskexplorer/TaskServer.ini
// is both. Naming the group keeps the two sets from growing into each other.
//
#define SERVER_CONFIG_GROUP		"Server"

bool CServerSetup::ReadConfig(SServerSetup* pSetup, const QString& Path)
{
	if (!pSetup)
		return false;

	const QString File = Path.isEmpty() ? ConfigFilePath() : Path;
	if (!QFile::exists(File))
		return false;

	QSettings Ini(File, QSettings::IniFormat);
	Ini.beginGroup(SERVER_CONFIG_GROUP);

	//
	// Each one defaulted to what the caller already had, so a file that names
	// three of them leaves the rest alone rather than resetting them to whatever
	// this function thinks the defaults are. There is then one place defaults are
	// written down - SServerSetup's own initialisers.
	//
	pSetup->Port = (quint16)Ini.value("Port", pSetup->Port).toUInt();
	pSetup->Bind = Ini.value("Bind", pSetup->Bind).toString();
	pSetup->bAllUsers = Ini.value("AllUsers", pSetup->bAllUsers).toBool();
	pSetup->Name = Ini.value("Name", pSetup->Name).toString();
	pSetup->bLocalPipe = Ini.value("LocalPipe", pSetup->bLocalPipe).toBool();
	pSetup->bLog = Ini.value("Log", pSetup->bLog).toBool();
	pSetup->bAnnounce = Ini.value("Announce", pSetup->bAnnounce).toBool();
	pSetup->bProcessBlocking = Ini.value("ProcessBlocking", pSetup->bProcessBlocking).toBool();
	pSetup->bUseDriver = Ini.value("UseDriver", pSetup->bUseDriver).toBool();
	pSetup->AnnounceInterval = Ini.value("AnnounceInterval", pSetup->AnnounceInterval).toInt();
	pSetup->DiscoveryPort = (quint16)Ini.value("DiscoveryPort", pSetup->DiscoveryPort).toUInt();
	pSetup->bHasPsk = !Ini.value("PSK").toString().isEmpty();

	Ini.endGroup();
	return true;
}

STATUS CServerSetup::WriteConfig(const SServerSetup& Setup)
{
	if (!IsPrivileged())
		return ERR(TE_ServerSetupNeedsAdmin);

	const QString File = ConfigFilePath();

	STATUS Status = EnsurePrivateDirectory(QFileInfo(File).absolutePath());
	if (Status.IsError())
		return Status;

	QSettings Ini(File, QSettings::IniFormat);
	Ini.beginGroup(SERVER_CONFIG_GROUP);
	Ini.setValue("Port", Setup.Port);
	Ini.setValue("Bind", Setup.Bind);
	Ini.setValue("AllUsers", Setup.bAllUsers);
	Ini.setValue("Name", Setup.Name);
	Ini.setValue("LocalPipe", Setup.bLocalPipe);
	Ini.setValue("Log", Setup.bLog);
	Ini.setValue("Announce", Setup.bAnnounce);
	Ini.setValue("ProcessBlocking", Setup.bProcessBlocking);
	Ini.setValue("UseDriver", Setup.bUseDriver);
	Ini.setValue("AnnounceInterval", Setup.AnnounceInterval);
	Ini.setValue("DiscoveryPort", Setup.DiscoveryPort);

	//
	// An empty PSK leaves whatever is stored alone, the same way an empty
	// password does for a user. It is how the port can be changed by somebody
	// who does not have the transport secret to hand - and there is no way to
	// read one back out of the dialog, because the dialog never shows it.
	//
	if (!Setup.Psk.isEmpty())
		Ini.setValue("PSK", Setup.Psk);
	Ini.endGroup();
	Ini.sync();

	if (Ini.status() != QSettings::NoError)
		return ERR(TE_ServerServiceFailed, QVariantList() << QString("could not write %1").arg(File));

	return OK;
}

//
// ---- the accounts that may log in ----
//
bool CServerSetup::ReadUsers(QList<SServerUserRecord>* pUsers)
{
	if (!pUsers)
		return false;
	pUsers->clear();

	const QString File = ConfigFilePath();
	if (!QFile::exists(File))
		return false;

	QSettings Ini(File, QSettings::IniFormat);
	Ini.beginGroup("Users");
	foreach(const QString& Name, Ini.childGroups())
	{
		Ini.beginGroup(Name);

		SServerUserRecord User;
		User.Name = Name;
		User.bAdmin = Ini.value("Role", "User").toString().compare("Admin", Qt::CaseInsensitive) == 0;
		User.bActions = Ini.value("Actions", false).toBool();

		//
		// No hash means the operating system is asked instead. Read as a fact
		// about the record rather than as its contents: the salt and the hash
		// themselves are never carried out of here, because nothing above this
		// has any use for them and a value that is never fetched cannot be
		// shown, logged or copied by accident.
		//
		User.bSystemAccount = Ini.value("Hash").toString().isEmpty();
		Ini.endGroup();

		pUsers->append(User);
	}
	Ini.endGroup();
	return true;
}

STATUS CServerSetup::WriteUser(const SServerUserRecord& User)
{
	if (!IsPrivileged())
		return ERR(TE_ServerSetupNeedsAdmin);

	//
	// A name has to be a name QSettings can put in a group, and it is used as
	// one. '/' would silently create a subgroup and make the account
	// unreachable; the rest are refused for being the sort of thing that is a
	// typo rather than a login.
	//
	const QString Name = User.Name.trimmed();
	if (Name.isEmpty() || Name.contains('/') || Name.startsWith('.'))
		return ERR(TE_ServerServiceFailed, QVariantList()
			<< QString("\"%1\" is not a usable user name").arg(User.Name));

	const QString File = ConfigFilePath();
	STATUS Status = EnsurePrivateDirectory(QFileInfo(File).absolutePath());
	if (Status.IsError())
		return Status;

	QSettings Ini(File, QSettings::IniFormat);
	Ini.beginGroup("Users");
	Ini.beginGroup(Name);

	Ini.setValue("Role", User.bAdmin ? "Admin" : "User");
	Ini.setValue("Actions", User.bActions);

	if (User.bSetPassword)
	{
		if (User.NewPassword.isEmpty())
		{
			//
			// Emptied on purpose, which is the instruction to stop keeping a
			// password for this name and ask the operating system instead. The
			// old salt and hash are removed rather than left: a stale hash
			// beside a system account is a second way in that nobody meant to
			// leave open.
			//
			Ini.remove("Salt");
			Ini.remove("Hash");
			Ini.remove("Iterations");
		}
		else
		{
			//
			// A fresh salt every time, including when a password is merely being
			// changed. Reusing the old one would mean two hashes of the same
			// account share a cracking run, and there is no reason to spend that.
			//
			const QByteArray Salt = CPasswordHash::MakeSalt();
			const QByteArray Hash = CPasswordHash::Derive(User.NewPassword.toUtf8(),
				Salt, PWHASH_ITERATIONS_DEFAULT);

			Ini.setValue("Salt", QString::fromLatin1(Salt.toHex()));
			Ini.setValue("Hash", QString::fromLatin1(Hash.toHex()));
			Ini.setValue("Iterations", PWHASH_ITERATIONS_DEFAULT);
		}
	}

	Ini.endGroup();
	Ini.endGroup();
	Ini.sync();

	if (Ini.status() != QSettings::NoError)
		return ERR(TE_ServerServiceFailed, QVariantList() << QString("could not write %1").arg(File));

	return OK;
}

STATUS CServerSetup::RemoveUser(const QString& Name)
{
	if (!IsPrivileged())
		return ERR(TE_ServerSetupNeedsAdmin);

	const QString File = ConfigFilePath();
	if (!QFile::exists(File))
		return OK;

	QSettings Ini(File, QSettings::IniFormat);
	Ini.beginGroup("Users");
	Ini.remove(Name);
	Ini.endGroup();
	Ini.sync();

	if (Ini.status() != QSettings::NoError)
		return ERR(TE_ServerServiceFailed, QVariantList() << QString("could not write %1").arg(File));

	return OK;
}

#ifdef WIN32

//
// ---- Windows: a service ----
//

//
// The port and the bind address are read back out of the service's own command
// line rather than kept anywhere else. There is then only one record of what
// the server is doing, and it is the one that decides what it does.
//
static void ParseServiceCommandLine(const QString& CommandLine, SServerSetup* pSetup)
{
	int Count = 0;
	LPWSTR* Argv = CommandLineToArgvW((LPCWSTR)CommandLine.utf16(), &Count);
	if (!Argv)
		return;

	for (int i = 0; i < Count; i++)
	{
		const QString Arg = QString::fromWCharArray(Argv[i]);
		const QString Next = (i + 1 < Count) ? QString::fromWCharArray(Argv[i + 1]) : QString();

		if (Arg == "--port" || Arg == "-p")
			pSetup->Port = (quint16)Next.toUShort();
		else if (Arg == "--bind")
			pSetup->Bind = Next;
		else if (Arg == "--announce-port")
			pSetup->DiscoveryPort = (quint16)Next.toUShort();
		else if (Arg == "--announce-every")
			pSetup->AnnounceInterval = Next.toInt();
		else if (Arg == "--all-users" || Arg == "-a")
			pSetup->bAllUsers = true;
	}

	//
	// Absent means off, which a loop that only ever sets it cannot express.
	//
	if (!CommandLine.contains("--all-users") && !CommandLine.contains(" -a "))
		pSetup->bAllUsers = false;

	pSetup->bAnnounce = CommandLine.contains("--announce");

	LocalFree(Argv);
}

bool CServerSetup::Query(SServerSetup* pSetup)
{
	if (!pSetup)
		return false;

	//
	// Cleared first, and the key read whether or not anything is installed.
	//
	// Returning false and leaving the caller’s struct as it was is what this did
	// at first, and it is a trap: the settings dialog removed the service, asked
	// again, was told "no" without being told what "no" looked like, and drew
	// the state it had been holding since before the removal. An out parameter
	// that is only written on success is one every caller has to remember to
	// reset, and one of them will not.
	//
	// The identity survives the service on purpose - Remove() leaves the key
	// file behind, and a machine that is turned back on should not have to be
	// told its own name again.
	//
	//
	// Cleared first, and deliberately without the transport secret.
	//
	// ReadConfig below does not fetch it either. Nothing that asks what is
	// installed has any use for the secret itself, and a value that is never
	// fetched cannot be shown in a dialog, written to a log or copied into a
	// message by accident. What the dialog needs to know is whether one is set,
	// which the file answers without handing it over.
	//
	*pSetup = SServerSetup();

	//
	// Before anything is asked of the service manager, and whether or not there
	// is a service: what the machine is configured to serve is a fact about the
	// machine, and the dialog has to be able to show it - and let it be edited -
	// on a machine where nothing is installed yet. That is the whole point of
	// keeping it in a file rather than on a command line that only exists once
	// something has been installed to carry it.
	//
	const bool bHaveConfig = ReadConfig(pSetup);

	SC_HANDLE hManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (!hManager)
		return false;

	const std::wstring Name = ServiceName().toStdWString();
	SC_HANDLE hService = OpenServiceW(hManager, Name.c_str(),
		SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
	if (!hService)
	{
		CloseServiceHandle(hManager);
		return false;
	}

	pSetup->bInstalled = true;

	DWORD Needed = 0;
	QueryServiceConfigW(hService, NULL, 0, &Needed);
	if (Needed)
	{
		QByteArray Buffer(Needed, 0);
		LPQUERY_SERVICE_CONFIGW pConfig = (LPQUERY_SERVICE_CONFIGW)Buffer.data();
		if (QueryServiceConfigW(hService, pConfig, Needed, &Needed))
		{
			pSetup->bAutoStart = (pConfig->dwStartType == SERVICE_AUTO_START);
			ParseServiceCommandLine(QString::fromWCharArray(pConfig->lpBinaryPathName), pSetup);
		}
	}

	//
	// And the file wins over either of them.
	//
	// Everything above reads a setup made by an older build, which spelled its
	// settings out where it was installed; that is worth reading once so nothing
	// is lost the first time this machine is saved. From then on there is a
	// configuration file and it is the only thing that counts.
	//
	if (bHaveConfig)
		ReadConfig(pSetup);

	SERVICE_STATUS Status = {};
	if (QueryServiceStatus(hService, &Status))
		pSetup->bRunning = (Status.dwCurrentState == SERVICE_RUNNING);

	CloseServiceHandle(hService);
	CloseServiceHandle(hManager);
	return true;
}

//
// Restart it if it fails, which is load-bearing rather than tidy.
//
// The server deliberately exits with a failure the first time it loads the
// kernel driver: KPH grants its maximum level only to a process it saw created
// while the driver was already running, so a process that loaded the driver
// itself can never have it. The way out of that for a service is to leave the
// driver loaded and let the manager start it again - and without a recovery
// configuration the manager does nothing at all, so the server would exit once
// and stay stopped. See the driver block in TaskServer's main().
//
// Three actions rather than one, because SC_ACTION_RESTART applies per failure
// and the list is walked in order: the first failure is the expected one and is
// retried at once, the second is retried after a pause, and anything past that
// is a server that is failing for a reason restarting will not fix. dwResetPeriod
// puts the counter back after a day, so a machine that runs for a month does not
// slowly use its retries up.
//
static void ConfigureRecovery(SC_HANDLE hService)
{
	SC_ACTION Actions[3] = {};
	Actions[0].Type = SC_ACTION_RESTART;
	Actions[0].Delay = 1000;
	Actions[1].Type = SC_ACTION_RESTART;
	Actions[1].Delay = 10000;
	Actions[2].Type = SC_ACTION_NONE;
	Actions[2].Delay = 0;

	SERVICE_FAILURE_ACTIONSW Failure = {};
	Failure.dwResetPeriod = 86400;
	Failure.lpRebootMsg = NULL;
	Failure.lpCommand = NULL;
	Failure.cActions = 3;
	Failure.lpsaActions = Actions;

	//
	// Not checked, and not reported. A service that runs but would not restart
	// itself is worth having; refusing to install one because the recovery
	// configuration could not be set would trade a working server for a tidy
	// one. The consequence shows up in the log as a driver level below maximum.
	//
	ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &Failure);

	//
	// And restart on a plain non-zero exit, not only on a crash. The exit above
	// is a deliberate, orderly failure - without this flag the manager treats it
	// as the service having simply finished and does nothing.
	//
	SERVICE_FAILURE_ACTIONS_FLAG Flag = {};
	Flag.fFailureActionsOnNonCrashFailures = TRUE;
	ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &Flag);
}

STATUS CServerSetup::Install(const SServerSetup& Setup)
{
	if (!IsPrivileged())
		return ERR(TE_ServerSetupNeedsAdmin);

	const QString Binary = ServerBinaryPath();
	if (!QFile::exists(Binary))
		return ERR(TE_ServerBinaryMissing, QVariantList() << QDir::toNativeSeparators(Binary));

	//
	// The configuration, before the service that will read it. Written every
	// time rather than only when it changed: this is the file the server starts
	// from, and a service registered against a file that is not there yet would
	// come up on the defaults instead of on what was just asked for.
	//
	STATUS ConfStatus = WriteConfig(Setup);
	if (ConfStatus.IsError())
		return ConfStatus;

	QString CommandLine = "\"" + QDir::toNativeSeparators(Binary) + "\"";
	foreach(const QString& Arg, BuildArguments(Setup))
		CommandLine += Arg.contains(' ') ? (" \"" + Arg + "\"") : (" " + Arg);

	SC_HANDLE hManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!hManager)
		return ERR(TE_ServerServiceFailed, QVariantList()
			<< QString("could not open the service manager (%1)").arg((quint32)GetLastError()));

	const std::wstring Name = ServiceName().toStdWString();
	const std::wstring Line = CommandLine.toStdWString();
	const std::wstring Display = QString("TaskExplorer Server").toStdWString();

	STATUS Result = OK;
	SC_HANDLE hService = OpenServiceW(hManager, Name.c_str(),
		SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);

	if (hService)
	{
		//
		// Already there: reconfigure it. SERVICE_NO_CHANGE for everything not
		// being set, so nothing that was configured outside this dialog is
		// quietly reverted by it.
		//
		if (!ChangeServiceConfigW(hService, SERVICE_NO_CHANGE, SERVICE_AUTO_START,
				SERVICE_NO_CHANGE, Line.c_str(), NULL, NULL, NULL, NULL, NULL, Display.c_str()))
		{
			Result = ERR(TE_ServerServiceFailed, QVariantList()
				<< QString("could not reconfigure the service (%1)").arg((quint32)GetLastError()));
		}
		else
		{
			ConfigureRecovery(hService);

			//
			// A running service is still running the old command line, so it
			// has to go round once for a changed port to mean anything.
			//
			SERVICE_STATUS Status = {};
			if (QueryServiceStatus(hService, &Status) && Status.dwCurrentState != SERVICE_STOPPED)
			{
				ControlService(hService, SERVICE_CONTROL_STOP, &Status);
				for (int i = 0; i < 50 && Status.dwCurrentState != SERVICE_STOPPED; i++)
				{
					QThread::msleep(100);
					if (!QueryServiceStatus(hService, &Status))
						break;
				}
			}
		}
	}
	else
	{
		hService = CreateServiceW(hManager, Name.c_str(), Display.c_str(),
			SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS,
			SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
			Line.c_str(), NULL, NULL, NULL, L"LocalSystem", L"");

		if (!hService)
		{
			Result = ERR(TE_ServerServiceFailed, QVariantList()
				<< QString("could not create the service (%1)").arg((quint32)GetLastError()));
		}
		else
			ConfigureRecovery(hService);
	}

	if (hService && !Result.IsError())
	{
		if (!StartServiceW(hService, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
		{
			Result = ERR(TE_ServerServiceFailed, QVariantList()
				<< QString("the service was installed but would not start (%1)").arg((quint32)GetLastError()));
		}
		else
		{
			//
			// StartService only says the start was accepted, so returning here
			// would report "stopped" for a service that is a second away from
			// running - and the first thing anyone does after installing is ask
			// whether it is running. Waited out rather than explained away.
			//
			SERVICE_STATUS Status = {};
			for (int i = 0; i < 100; i++)
			{
				if (!QueryServiceStatus(hService, &Status))
					break;
				if (Status.dwCurrentState != SERVICE_START_PENDING)
					break;
				QThread::msleep(100);
			}

			//
			// A service that starts and stops again has failed at something the
			// manager cannot see - a port already taken, a key file it cannot
			// read. Its own log says which; this at least says to go and look.
			//
			if (Status.dwCurrentState == SERVICE_STOPPED)
			{
				Result = ERR(TE_ServerServiceFailed, QVariantList()
					<< QString("the service started and stopped again; see %1")
						.arg(QDir::toNativeSeparators(QFileInfo(ConfigFilePath()).absolutePath() + "/TaskServer.log")));
			}
		}
	}

	if (hService) CloseServiceHandle(hService);
	CloseServiceHandle(hManager);
	return Result;
}

//
// Opens the installed service for one operation, or says why it could not be.
//
// Nothing to open is reported as TE_ServerServiceFailed rather than as success:
// unlike Remove(), where a service that is not there is the state the caller
// asked for, being asked to start one that does not exist is a mistake and
// should read like one.
//
static SC_HANDLE OpenInstalledService(SC_HANDLE* phManager, DWORD Access, STATUS* pStatus)
{
	*phManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (!*phManager)
	{
		*pStatus = ERR(TE_ServerServiceFailed, QVariantList()
			<< QString("could not open the service manager (%1)").arg((quint32)GetLastError()));
		return NULL;
	}

	const std::wstring Name = CServerSetup::ServiceName().toStdWString();
	SC_HANDLE hService = OpenServiceW(*phManager, Name.c_str(), Access);
	if (!hService)
	{
		*pStatus = ERR(TE_ServerServiceFailed, QVariantList()
			<< QString("could not open the service (%1)").arg((quint32)GetLastError()));
		CloseServiceHandle(*phManager);
		*phManager = NULL;
	}
	return hService;
}

//
// Waits for a state the manager has only been asked for.
//
// StartService and ControlService both return as soon as the request is
// accepted, so returning here would report the state the service was in before
// the button was pressed - and the first thing anybody does after pressing it is
// look at the state. Five seconds, then the truth either way.
//
static bool WaitForServiceState(SC_HANDLE hService, DWORD Wanted)
{
	SERVICE_STATUS Status = {};
	for (int i = 0; i < 50; i++)
	{
		if (!QueryServiceStatus(hService, &Status))
			return false;
		if (Status.dwCurrentState == Wanted)
			return true;
		QThread::msleep(100);
	}
	return false;
}

STATUS CServerSetup::StartServer()
{
	if (!IsPrivileged())
		return ERR(TE_ServerSetupNeedsAdmin);

	SC_HANDLE hManager = NULL;
	STATUS Result = OK;
	SC_HANDLE hService = OpenInstalledService(&hManager,
		SERVICE_START | SERVICE_QUERY_STATUS, &Result);
	if (!hService)
		return Result;

	if (!StartServiceW(hService, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
	{
		Result = ERR(TE_ServerServiceFailed, QVariantList()
			<< QString("the service would not start (%1)").arg((quint32)GetLastError()));
	}
	else if (!WaitForServiceState(hService, SERVICE_RUNNING))
	{
		//
		// Started and stopped again means it failed at something the manager
		// cannot see - a port already taken, a key file it cannot read. Its own
		// log says which; this at least says to go and look.
		//
		Result = ERR(TE_ServerServiceFailed, QVariantList()
			<< QString("the service did not come up; see %1")
				.arg(QDir::toNativeSeparators(QFileInfo(ConfigFilePath()).absolutePath() + "/TaskServer.log")));
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hManager);
	return Result;
}

STATUS CServerSetup::StopServer()
{
	if (!IsPrivileged())
		return ERR(TE_ServerSetupNeedsAdmin);

	SC_HANDLE hManager = NULL;
	STATUS Result = OK;
	SC_HANDLE hService = OpenInstalledService(&hManager,
		SERVICE_STOP | SERVICE_QUERY_STATUS, &Result);
	if (!hService)
		return Result;

	SERVICE_STATUS Status = {};
	if (!ControlService(hService, SERVICE_CONTROL_STOP, &Status)
		&& GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
	{
		Result = ERR(TE_ServerServiceFailed, QVariantList()
			<< QString("the service would not stop (%1)").arg((quint32)GetLastError()));
	}
	else if (!WaitForServiceState(hService, SERVICE_STOPPED))
	{
		Result = ERR(TE_ServerServiceFailed, QVariantList()
			<< QString("the service did not stop"));
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hManager);
	return Result;
}

STATUS CServerSetup::Remove(const QString& ServiceName_)
{
	if (!IsPrivileged())
		return ERR(TE_ServerSetupNeedsAdmin);

	SC_HANDLE hManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (!hManager)
		return ERR(TE_ServerServiceFailed, QVariantList()
			<< QString("could not open the service manager (%1)").arg((quint32)GetLastError()));

	//
	// The name given, or the one the configuration describes. They differ
	// exactly once: while an instance is being renamed, when what has to go is
	// the service the old name made.
	//
	const std::wstring Name = (ServiceName_.isEmpty() ? ServiceName() : ServiceName_).toStdWString();
	SC_HANDLE hService = OpenServiceW(hManager, Name.c_str(),
		SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);

	if (!hService)
	{
		CloseServiceHandle(hManager);

		//
		// Nothing to remove is the state the caller asked for, so it is not a
		// failure. Anything else is.
		//
		if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
			return OK;

		return ERR(TE_ServerServiceFailed, QVariantList()
			<< QString("could not open the service (%1)").arg((quint32)GetLastError()));
	}

	SERVICE_STATUS Status = {};
	if (QueryServiceStatus(hService, &Status) && Status.dwCurrentState != SERVICE_STOPPED)
	{
		ControlService(hService, SERVICE_CONTROL_STOP, &Status);
		for (int i = 0; i < 50 && Status.dwCurrentState != SERVICE_STOPPED; i++)
		{
			QThread::msleep(100);
			if (!QueryServiceStatus(hService, &Status))
				break;
		}
	}

	STATUS Result = OK;
	if (!DeleteService(hService))
	{
		Result = ERR(TE_ServerServiceFailed, QVariantList()
			<< QString("could not remove the service (%1)").arg((quint32)GetLastError()));
	}

	CloseServiceHandle(hService);

	//
	// DeleteService only marks it. The entry survives until the last handle to
	// it is closed - including handles nothing here owns, which is why anyone
	// with services.msc open has seen a deleted service sit there greyed out.
	//
	// Waited for, because the caller’s next move is to ask whether it is still
	// installed and it would be told yes. Found exactly that way: the settings
	// dialog removed the service, re-read the state, and drew the checkbox
	// ticked again over a service that was on its way out.
	//
	if (!Result.IsError())
	{
		for (int i = 0; i < 20; i++)
		{
			SC_HANDLE hGone = OpenServiceW(hManager, Name.c_str(), SERVICE_QUERY_STATUS);
			if (!hGone)
				break;
			CloseServiceHandle(hGone);
			QThread::msleep(100);
		}
	}

	CloseServiceHandle(hManager);
	return Result;
}

#else // !WIN32

//
// ---- Linux: a systemd unit ----
//
// systemd only, deliberately. Writing an init script as well would double this
// for a case that is now rare, and a machine without systemd is a machine whose
// administrator knows how to write their own unit - BuildArguments() gives them
// the command line to put in it.
//

static QString UnitPath()
{
	return QString("/etc/systemd/system/%1.service").arg(CServerSetup::ServiceName().toLower());
}

static QString UnitName()
{
	return CServerSetup::ServiceName().toLower() + ".service";
}

//
// systemctl, with its output. Its exit code alone says "it did not work" and
// its stderr says why - which is the difference between a message somebody can
// act on and one they cannot.
//
static bool RunSystemctl(const QStringList& Arguments, QString* pOutput)
{
	QProcess Process;
	Process.start("systemctl", Arguments);
	if (!Process.waitForFinished(20000))
	{
		if (pOutput)
			*pOutput = QString("systemctl %1 did not finish").arg(Arguments.join(' '));
		return false;
	}

	const QString Text = QString::fromLocal8Bit(Process.readAllStandardOutput()
		+ Process.readAllStandardError()).trimmed();
	if (pOutput)
		*pOutput = Text;

	return Process.exitStatus() == QProcess::NormalExit && Process.exitCode() == 0;
}

bool CServerSetup::Query(SServerSetup* pSetup)
{
	if (!pSetup)
		return false;

	//
	// Cleared first, and the key read whether or not anything is installed.
	//
	// Returning false and leaving the caller’s struct as it was is what this did
	// at first, and it is a trap: the settings dialog removed the service, asked
	// again, was told "no" without being told what "no" looked like, and drew
	// the state it had been holding since before the removal. An out parameter
	// that is only written on success is one every caller has to remember to
	// reset, and one of them will not.
	//
	// The identity survives the service on purpose - Remove() leaves the key
	// file behind, and a machine that is turned back on should not have to be
	// told its own name again.
	//
	//
	// Cleared first, and deliberately without the transport secret.
	//
	// ReadConfig below does not fetch it either. Nothing that asks what is
	// installed has any use for the secret itself, and a value that is never
	// fetched cannot be shown in a dialog, written to a log or copied into a
	// message by accident. What the dialog needs to know is whether one is set,
	// which the file answers without handing it over.
	//
	*pSetup = SServerSetup();

	//
	// Before anything is asked of the service manager, and whether or not there
	// is a service: what the machine is configured to serve is a fact about the
	// machine, and the dialog has to be able to show it - and let it be edited -
	// on a machine where nothing is installed yet. That is the whole point of
	// keeping it in a file rather than on a command line that only exists once
	// something has been installed to carry it.
	//
	const bool bHaveConfig = ReadConfig(pSetup);

	QFile Unit(UnitPath());
	if (!Unit.open(QIODevice::ReadOnly))
		return false;

	const QString Text = QString::fromLocal8Bit(Unit.readAll());
	Unit.close();

	pSetup->bInstalled = true;
	pSetup->bAllUsers = Text.contains("--all-users");
	pSetup->bAnnounce = Text.contains("--announce");

	foreach(const QString& Line, Text.split('\n'))
	{
		if (!Line.startsWith("ExecStart"))
			continue;

		const QStringList Parts = Line.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
		for (int i = 0; i < Parts.count() - 1; i++)
		{
			if (Parts[i] == "--port")
				pSetup->Port = (quint16)Parts[i + 1].toUShort();
			else if (Parts[i] == "--bind")
				pSetup->Bind = Parts[i + 1];
			else if (Parts[i] == "--announce-port")
				pSetup->DiscoveryPort = (quint16)Parts[i + 1].toUShort();
			else if (Parts[i] == "--announce-every")
				pSetup->AnnounceInterval = Parts[i + 1].toInt();
		}
		break;
	}

	//
	// And the file wins over either of them.
	//
	// Everything above reads a setup made by an older build, which spelled its
	// settings out where it was installed; that is worth reading once so nothing
	// is lost the first time this machine is saved. From then on there is a
	// configuration file and it is the only thing that counts.
	//
	if (bHaveConfig)
		ReadConfig(pSetup);

	//
	// Asked of systemd rather than inferred from the file: a unit that exists
	// is not a unit that is enabled, and the symlink that would say so lives in
	// a directory whose name depends on the target.
	//
	QString Output;
	pSetup->bAutoStart = RunSystemctl(QStringList() << "is-enabled" << UnitName(), &Output);
	pSetup->bRunning = RunSystemctl(QStringList() << "is-active" << UnitName(), &Output);
	return true;
}

STATUS CServerSetup::Install(const SServerSetup& Setup)
{
	if (!IsPrivileged())
		return ERR(TE_ServerSetupNeedsAdmin);

	const QString Binary = ServerBinaryPath();
	if (!QFile::exists(Binary))
		return ERR(TE_ServerBinaryMissing, QVariantList() << Binary);

	//
	// The configuration, before the service that will read it. Written every
	// time rather than only when it changed: this is the file the server starts
	// from, and a service registered against a file that is not there yet would
	// come up on the defaults instead of on what was just asked for.
	//
	STATUS ConfStatus = WriteConfig(Setup);
	if (ConfStatus.IsError())
		return ConfStatus;

	//
	// Type=simple and no forking: the server is a plain event loop that does
	// not daemonise itself, which is what systemd prefers anyway. Restart=on
	// failure rather than always, so a server that refuses to start because its
	// port is taken says so once instead of filling the journal.
	//
	QString Unit;
	Unit += "[Unit]\n";
	Unit += "Description=TaskExplorer Server\n";
	Unit += "After=network.target\n\n";
	Unit += "[Service]\n";
	Unit += "Type=simple\n";
	Unit += "ExecStart=" + Binary + " " + BuildArguments(Setup).join(' ') + "\n";
	Unit += "Restart=on-failure\n";
	Unit += "RestartSec=5\n\n";
	Unit += "[Install]\n";
	Unit += "WantedBy=multi-user.target\n";

	QFile File(UnitPath());
	if (!File.open(QIODevice::WriteOnly | QIODevice::Truncate))
		return ERR(TE_ServerServiceFailed, QVariantList() << File.errorString());
	File.write(Unit.toLocal8Bit());
	File.close();

	QString Output;
	if (!RunSystemctl(QStringList() << "daemon-reload", &Output))
		return ERR(TE_ServerServiceFailed, QVariantList() << Output);

	//
	// enable and restart rather than enable --now: --now only starts one that is
	// stopped, and a running one would go on serving the previous port.
	//
	if (!RunSystemctl(QStringList() << "enable" << UnitName(), &Output))
		return ERR(TE_ServerServiceFailed, QVariantList() << Output);
	if (!RunSystemctl(QStringList() << "restart" << UnitName(), &Output))
		return ERR(TE_ServerServiceFailed, QVariantList() << Output);

	return OK;
}

//
// start and stop rather than enable and disable: whether the unit comes up with
// the machine is part of its configuration and is not what these ask about.
//
STATUS CServerSetup::StartServer()
{
	if (!IsPrivileged())
		return ERR(TE_ServerSetupNeedsAdmin);

	QString Output;
	if (!RunSystemctl(QStringList() << "start" << UnitName(), &Output))
		return ERR(TE_ServerServiceFailed, QVariantList() << Output);
	return OK;
}

STATUS CServerSetup::StopServer()
{
	if (!IsPrivileged())
		return ERR(TE_ServerSetupNeedsAdmin);

	QString Output;
	if (!RunSystemctl(QStringList() << "stop" << UnitName(), &Output))
		return ERR(TE_ServerServiceFailed, QVariantList() << Output);
	return OK;
}

STATUS CServerSetup::Remove(const QString& ServiceName_)
{
	if (!IsPrivileged())
		return ERR(TE_ServerSetupNeedsAdmin);

	//
	// The unit given, or the one the configuration describes - see the Windows
	// half for when the two differ.
	//
	const QString Unit = ServiceName_.isEmpty() ? UnitName()
	                                            : ServiceName_.toLower() + ".service";
	const QString Path = QString("/etc/systemd/system/%1").arg(Unit);

	if (!QFile::exists(Path))
		return OK;

	QString Output;
	RunSystemctl(QStringList() << "disable" << "--now" << Unit, &Output);

	if (!QFile::remove(Path))
		return ERR(TE_ServerServiceFailed, QVariantList()
			<< QString("could not remove %1").arg(Path));

	RunSystemctl(QStringList() << "daemon-reload", &Output);
	return OK;
}

#endif // WIN32
