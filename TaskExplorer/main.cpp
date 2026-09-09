#include "../TaskExplorer/version.h"
#include "stdafx.h"
#include <QSslSocket>
#include "GUI/TaskExplorer.h"
#include <QtWidgets/QApplication>
//#include <vld.h>
#include <QThreadPool>
#include "SVC/TaskService.h"

// Needed on every platform - the single-instance guard is not Windows specific.
#include "../qtsingleapp/src/qtsingleapplication.h"

#ifdef WIN32
#include <phnt_windows.h>
#include "API/Windows/WinAdmin.h"
#include "API/Windows/WinHelper.h"
#include <codecvt>
#include "../MiscHelpers/Common/qRC4.h"
#include "../MiscHelpers/Common/CheckableMessageBox.h"
#include "../MiniDump/MiniDumpFilter.h"

#else
#include <unistd.h>

//
// On Windows "elevated" means running with an elevated token; the closest
// Linux equivalent for the purpose this is used for - deciding whether we can
// inspect other users' processes, and which single-instance key to claim - is
// an effective uid of 0.
//
static bool IsElevated()
{
	return geteuid() == 0;
}
#endif



int main(int argc, char *argv[])
{
	//
	// The application directory. This used to be derived from
	// GetModuleFileNameW before QApplication existed; QCoreApplication's static
	// helper works the same way and needs no instance either, but it does need
	// argv, so it is resolved from /proc/self/exe on Linux and the module path
	// on Windows by Qt itself.
	//
	QString AppDir;
#ifdef WIN32
	{
		wchar_t szPath[MAX_PATH];
		GetModuleFileNameW(NULL, szPath, ARRAYSIZE(szPath));
		*wcsrchr(szPath, L'\\') = L'\0';

		AppDir = QString::fromWCharArray(szPath);
	}
#else
	AppDir = QFileInfo(QFile::symLinkTarget("/proc/self/exe")).absolutePath();
#endif

	srand(QTime::currentTime().msec());

#ifndef USE_TASK_HELPER	
	bool bSvc = false;
	bool bWrk = false;
	QString svcName = TASK_SERVICE_NAME;
	const char* run_svc = NULL;
#endif
	bool bMulti = false;
	bool bNoSkip = false;
	int timeOut = 0;
    for(int i = 1; i < argc; i++)
    {
#ifndef USE_TASK_HELPER	
		if (strcmp(argv[i], "-svc") == 0 || strcmp(argv[i], "-wrk") == 0)
		{
			bSvc = (strcmp(argv[i], "-svc") == 0);
			bWrk = (strcmp(argv[i], "-wrk") == 0);
			if(++i < argc)
				svcName =  argv[i];
		}
		else 
#endif
#ifdef WIN32
		// -kx / -kh control the KSystemInformer driver startup level, which
		// only exists on Windows.
		if (strcmp(argv[i], "-kx") == 0)
			SetKernelDriverStartup(true, false);
		else if (strcmp(argv[i], "-kh") == 0)
			SetKernelDriverStartup(false, true);
		else
#endif
		if (strcmp(argv[i], "-multi") == 0)
			bMulti = true;
		else if (strcmp(argv[i], "-no_elevate") == 0)
			bNoSkip = true;
		else if (strcmp(argv[i], "-timeout") == 0)
			timeOut = ++i < argc ? atoi(argv[i]) : 10000;
		else if (strcmp(argv[i], "-dbg_wait") == 0)
		{
			// add timeout?
			WaitForDebugger();
		}
#ifndef USE_TASK_HELPER	
		else if (strcmp(argv[i], "-runsvc") == 0)
		{
			run_svc = ++i < argc ? argv[i] : TASK_SERVICE_NAME;
		}
#endif
    }

	// Set when we could not determine our own elevation state and have to probe
	// for an already-running elevated instance instead. Only ever true on
	// Windows, but referenced further down on both platforms.
	bool bTestElevated = false;
#ifdef WIN32
#ifndef USE_TASK_HELPER
	if (!bSvc && !bWrk)
#endif
	if (!IsElevated() && !bNoSkip)
	{
		int ret = SkipUacRun(); // Warning: the started process will have lower priority!
		if (ret == 1)
			return 0;
		if (ret == -1) { // the driver does not allow us the know the state, so we wait a second and check if an other instance has came up
			bTestElevated = true;
			QThread::msleep(1000);
		}
	}
#endif

#ifndef USE_TASK_HELPER	
	if (run_svc)
	{
		if (CTaskService::RunService(run_svc)) {
			//_exit(EXIT_SUCCESS);
			return EXIT_SUCCESS; // 0
		}
		return EXIT_FAILURE; // 1
	}
#endif

	QStringList dirs = QStandardPaths::standardLocations(QStandardPaths::GenericDataLocation);
	if (dirs.count() > 2) { // Note: last 2 are AppDir and AppDir/data
		QString OldPath;
		QString NewPath;
		if (dirs.count() > 3 && QFile::exists((OldPath = dirs[1] + "/TaskExplorer") + "/TaskExplorer.ini"))
			NewPath = dirs[1] + "/Xanasoft";
		else if (QFile::exists((OldPath = dirs[0] + "/TaskExplorer") + "/TaskExplorer.ini"))
			NewPath = dirs[0] + "/Xanasoft";

		if (!NewPath.isEmpty() && !QFile::exists(NewPath + "/TaskExplorer" + "/TaskExplorer.ini")){
			QDir().mkpath(NewPath);
			QDir().rename(OldPath, NewPath + "/TaskExplorer");
		}
	}
	theConf = new CSettings(AppDir, "TaskExplorer", "Xanasoft");

#ifdef WIN32
	//
	// Crash handling, as soon as there is somewhere to put a dump.
	//
	// Not the in-process writer this used to call. That one ran inside the
	// process that had just failed - allocating, loading dbghelp, putting up a
	// message box - which is the least reliable moment to do any of those things.
	// MiniDumpFilter spawns MiniDump.exe instead and lets *that* read the corpse
	// from outside, which still works when the heap is what was corrupted.
	//
	// Here rather than at the top of main because the dumps go in a MiniDump
	// folder beside the configuration file, and where that is depends on the
	// settings themselves: beside the program for a portable copy, in the user's
	// data directory otherwise. What runs before this is argument scanning and an
	// elevation check, which is not where crashes happen - and anything there
	// still meets the operating system's own reporting.
	//
	// Not under a debugger: there the exception belongs to whoever attached.
	//
	if (!IsDebuggerPresent())
	{
		//
		// MiniDump.exe is looked for beside the program, which is where both the
		// build and the installer put it.
		//
		const std::wstring DumpDir = QDir::toNativeSeparators(
			theConf->GetConfigDir() + "/MiniDump").toStdWString();

		const std::wstring AppName = QString("TaskExplorer-v%1")
			.arg(CTaskExplorer::GetVersion()).toStdWString();

		MiniDumpFilter_Init(NULL, AppName.c_str(), MDF_TYPE_TRIAGE, NULL, DumpDir.c_str());
	}
#endif

	//
	// Once the settings exist, because the key store's location is derived from
	// them - and before anything can ask for a key. See SetupCredentialStore.
	//
	SetupCredentialStore();

#ifdef WIN32
	InitNativeApi();
#endif

#ifndef USE_TASK_HELPER
#ifdef WIN32
	if (bSvc)
		EnableServicePrivileges();
#endif
#endif

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
	QApplication::setAttribute(Qt::AA_DisableWindowContextHelpButton);
#endif

#ifdef WIN32
	//
	// Qt 6 uses the windows font cache which wants to access our process but our driver blocks it
	// that causes a lot of log entries, hence we disable the use of windows fonr cache.
	//
	qputenv("QT_QPA_PLATFORM", QByteArrayLiteral("windows:nodirectwrite"));
#endif



	STATUS DrvStatus = OK;

#ifdef Q_OS_WIN
#ifndef _DEBUG
	// Set the default priority.
	SetOwnProcessPriority();
#endif
#endif // Q_OS_WIN


	QtSingleApplication* pApp = NULL;
#ifndef USE_TASK_HELPER
	if (bSvc || bWrk)
	{
		new QCoreApplication(argc, argv);
	}
	else if (!bSvc && !bWrk)
#endif
	{
		// this must be done before we create QApplication
		int DPI = theConf->GetInt("Options/DPIScaling", 1);
#ifdef WIN32
		if (DPI == 1) {
			SetSystemDpiAware();
		}
		else
#endif
		if (DPI == 2) {
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
			QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
#endif
		}
		//else {
		//	QCoreApplication::setAttribute(Qt::AA_DisableHighDpiScaling);
		//}

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
		QApplication::setAttribute(Qt::AA_DisableWindowContextHelpButton);
#endif

		//new QApplication(argc, argv);
		pApp = new QtSingleApplication((IsElevated() || bTestElevated) ? "TaskExplorer" : "UTaskExplorer", argc, argv);

#ifndef WIN32
		//
		// On Windows the icon comes for free: the linker embeds TaskExplorer.ico
		// as the executable's resource, and the shell reads it from there for
		// the title bar and the task bar.
		//
		// Nothing equivalent exists on Linux - an ELF binary carries no icon -
		// so without this the window manager falls back to a generic placeholder
		// (the X logo on this desktop). Setting it on the application means
		// every window and dialog inherits it, and Qt publishes it to the window
		// manager as _NET_WM_ICON.
		//
		// The .ico is used rather than TaskExplorer.png because it carries
		// purpose-made 16, 32 and 48 pixel renditions; scaling the 256x256 PNG
		// down to task bar size blurs the trace line that makes the icon
		// recognisable.
		//
		QApplication::setWindowIcon(QIcon(":/TaskExplorer.ico"));

		//
		// Ties the window to its .desktop entry, which is how a modern task bar
		// finds an application's icon and groups its windows.
		//
		// Only claimed when such a file is actually installed: announcing an
		// app id that resolves to nothing makes the desktop portal log
		// "App info not found" on every start, and buys nothing until the
		// application is packaged.
		//
		if (!QStandardPaths::locate(QStandardPaths::ApplicationsLocation, "taskexplorer.desktop").isEmpty())
			QGuiApplication::setDesktopFileName("taskexplorer");
#endif

#ifdef WIN32
		if (theConf->GetBool("OptionsKSI/KsiEnable", true) && IsElevated() && !IsRunningUnderWow64())
		{
			DrvStatus = LoadKernelDriver(AppDir);
		}
#endif
	}

	//
	// OpenSSL, as early as there is somewhere to say it.
	//
	// Qt will not change backend once one is in use, so this wants to be the
	// first thing said about TLS in the process - but it cannot be the first
	// thing in main(). The backend list is a QFactoryLoader held in an
	// application static, and reaching it before the application object exists
	// asserts in a debug build ("The application static was used without a
	// QCoreApplication instance") and quietly does nothing in a release one.
	// The release build therefore looked fine while its guard was inert, which
	// is the worse of the two failures; the debug build is what said so.
	//
	// So: immediately after the application is constructed, and still long
	// before anything opens a socket.
	//
	// It matters because Schannel, which Qt falls back to on Windows when the
	// OpenSSL libraries are not beside the executable, offers no forward-secret
	// PSK suite at all. A connection would still be made and would still be
	// encrypted; it would simply have lost the property that makes a captured
	// session useless to somebody who later learns the key.
	//
	// A false return is not fatal: a viewer that never connects to anything
	// over the network never asks for any of this.
	//
	QSslSocket::setActiveBackend("openssl");

	if (pApp)
	{
		if (bTestElevated && pApp->isClient())
			return 0;

		if (!theConf->GetBool("Options/AllowMultipleInstances", false) && !bMulti && pApp->sendMessage("ShowWnd"))
			return 0;
	}

#ifdef WIN32
	//
	// KSystemInformer driver diagnostics. DrvStatus is only ever set by
	// LoadKernelDriver(), which does not exist on Linux, so this loop would never be
	// entered there anyway - but it references a pile of Windows-only symbols,
	// so it is compiled out entirely.
	//
	//DrvStatus = ERR(0xC0000058); // STATUS_UNKNOWN_REVISION
	int DynDataUpdate = 0;
	while (DrvStatus.IsError() || DynDataUpdate == 2)
	{
		QString Message;
		QDialogButtonBox::StandardButtons buttons = QDialogButtonBox::Ok;
		if (DynDataUpdate == -1)
		{
			Message = CTaskExplorer::tr("Failed to update DynData, %1, Error: 0x%2 (%3).").arg(CTaskExplorer::FormatError(DrvStatus)).arg((quint32)DrvStatus.GetStatus(), 8, 16, QChar('0')).arg(GetNtStatusMessage(DrvStatus.GetStatus()));
		}
		else if (IsUnsupportedKernel(DrvStatus.GetStatus()) || DynDataUpdate != 0) 
		{
			QString windowsVersion = QString("%1").arg(GetWindowsVersion()); // todo
			QString kernelVersion = GetKernelVersionString();

			Message = CTaskExplorer::tr("The current DynData for the KTaskExplorer driver does not yet supported on your windows kernel version.<br />"
				"You can check for <a href=\"https://github.com/DavidXanatos/TaskExplorer/releases\">TaskExplorer updates on github</a>, "
				"or grab the latest ksidyn.bin and ksidyn.sig from <a href=\"https://systeminformer.sourceforge.io/downloads\">the latest SystemInformer</a> "
				"and put them in the instalaltion directors next to KTaskExplorer.sys.<br />"
				"Instalation Directory: %4<br />"
				"<br />"
				"Operating System Details:<br />"
				"&nbsp;&nbsp;&nbsp;&nbsp;Windows %1<br />"
				"&nbsp;&nbsp;&nbsp;&nbsp;Windows Kernel %2<br />"
				"&nbsp;&nbsp;&nbsp;&nbsp;TaskExplorer %3<br />"
				"<br />").arg(windowsVersion).arg(kernelVersion).arg(CTaskExplorer::GetVersion()).arg(AppDir);

			if (DynDataUpdate == 1)
				Message += CTaskExplorer::tr("Update did not resolve the issue.");
			else {
				Message += CTaskExplorer::tr("Do you want to try to download updated DynData Yes, start without the driver No?");
				buttons = QDialogButtonBox::Yes | QDialogButtonBox::No | QDialogButtonBox::Cancel;
			}
		} 
		else {
			Message = CTaskExplorer::tr("Failed to load KTaskExplorer driver, %1, Error: 0x%2 (%3).").arg(CTaskExplorer::FormatError(DrvStatus)).arg((quint32)DrvStatus.GetStatus(), 8, 16, QChar('0')).arg(GetNtStatusMessage(DrvStatus.GetStatus()));
		}

		bool State = false;
		int Ret = CCheckableMessageBox::question(NULL, "TaskExplorer", Message
			, CTaskExplorer::tr("Disable KTaskExplorer driver. Note: this will limit the aplications functionality!"), &State, 
			buttons, QDialogButtonBox::Ok, QMessageBox::Warning);

		if (Ret == QDialogButtonBox::Yes)
		{
			DrvStatus = CTaskExplorer::UpdateDynData(AppDir);
			if (DrvStatus.IsError()) {
				QMessageBox::critical(NULL, "TaskExplorer", CTaskExplorer::tr("Failed to update DynData, %1.").arg(CTaskExplorer::FormatError(DrvStatus)));
				DynDataUpdate = -1;
			}
			else {
				DynDataUpdate = 1;
				UnloadKernelDriver();
				DrvStatus = LoadKernelDriver(AppDir);
			}
			continue;
		}

		if (State)
			theConf->SetValue("OptionsKSI/KsiEnable", false);

		break;
	}
#endif // WIN32

	QThreadPool::globalInstance()->setMaxThreadCount(theConf->GetInt("Options/MaxThreadPool", 10));

	int ret = 0;
#ifndef USE_TASK_HELPER
	// Old behavior: TaskExplorer handles service/worker modes
	if (bSvc || bWrk)
	{
		CTaskService Svc(1/*argc*/, argv, svcName, timeOut);
		if(bSvc)
			ret = Svc.exec();
		else
		{
			Svc.start();
			QCoreApplication::exec();
			Svc.stop();
		}
	}
	else
#endif
	if(pApp)
	{
#ifdef WIN32
#ifndef _WIN64
#ifndef _DEBUG
		if (IsRunningUnderWow64())
		{
//			QString BinaryPath = "";
//
//			static char* relativeFileNames[] =
//			{
//				"\\x64\\TaskExplorer.exe",
//				"\\..\\x64\\TaskExplorer.exe",
//#ifdef DEBUG
//				"\\..\\..\\x64\\Debug\\TaskExplorer.exe"
//#else
//				"\\..\\..\\x64\\Release\\TaskExplorer.exe"
//#endif
//			};
//
//			QString AppDir = QApplication::applicationDirPath();
//
//			for (int i = 0; i < RTL_NUMBER_OF(relativeFileNames); i++)
//			{
//				QString TestPath = QDir::cleanPath(AppDir + relativeFileNames[i]);
//				if (QFile::exists(TestPath))
//				{
//					BinaryPath = TestPath.replace("/", "\\");
//					break;
//				}
//			}
//
//			if (!BinaryPath.isEmpty()) 
//			{
//				QStringList Args = QCoreApplication::instance()->arguments();
//				Args.removeFirst();
//				QProcess::startDetached(BinaryPath, Args);
//			}
//			else
			{
				QMessageBox::critical(NULL, "TaskExplorer", CTaskExplorer::tr(
					"You are attempting to run the 32-bit version of Task Explorer on 64-bit Windows. "
					"Most features will not work correctly.\n\n"
					"Please run the 64-bit version of Task Explorer instead."
				));
			}
			//QApplication::instance()->quit();
			return 0;
		}
#endif
#endif
#endif
		pApp->setQuitOnLastWindowClosed(false);

#if QT_VERSION > QT_VERSION_CHECK(6, 7, 0)
		if (pApp->style()->name() == "windows11" && !theConf->GetBool("Options/UseW11Style", false))
			pApp->setStyle("windowsvista");
#endif

		new CTaskExplorer();

		QObject::connect(pApp, SIGNAL(messageReceived(const QString&)), theGUI, SLOT(OnMessage(const QString&)));
		
		ret = pApp->exec();

		delete theGUI;

		CTaskService::TerminateWorkers();
	}

#ifdef WIN32
	UnloadKernelDriver();
#endif

	// note: if ran as a service teh instance wil have already been delted, but delete NULL is ok
	delete pApp;

	delete theConf;
	theConf = NULL;

	return ret;
}
