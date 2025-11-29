#include "stdafx.h"
#include "GUI/TaskExplorer.h"
#include <QtWidgets/QApplication>
//#include <vld.h>
#include <QThreadPool>
#include "SVC/TaskService.h"
#ifdef WIN32
#include "API/Windows/ProcessHacker.h"
#include "API/Windows/WinAdmin.h"
#include <codecvt>
#include "../QtSingleApp/src/qtsingleapplication.h"
#include "../MiscHelpers/Common/qRC4.h"
#include "../../MiscHelpers/Common/CheckableMessageBox.h"
#include "..\ProcessHacker\kphlib\include\sistatus.h"

int SkipUacRun(bool test_only = false);
#endif

CSettings* theConf = NULL;


int main(int argc, char *argv[])
{
#ifndef _DEBUG
	InitMiniDumpWriter(L"TaskExplorer", L"");
#endif

	srand(QTime::currentTime().msec());

#ifndef USE_TASK_HELPER	
	bool bSvc = false;
	bool bWrk = false;
#endif
	bool bMulti = false;
	bool bNoSkip = false;
	QString svcName = TASK_SERVICE_NAME;
	int timeOut = 0;
    const char* run_svc = NULL;
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
		if (strcmp(argv[i], "-kx") == 0)
			g_KphStartupMax = TRUE;
		else if (strcmp(argv[i], "-kh") == 0)
			g_KphStartupHigh = TRUE;
		else if (strcmp(argv[i], "-multi") == 0)
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
		else if (strcmp(argv[i], "-runsvc") == 0)
		{
			run_svc = ++i < argc ? argv[i] : TASK_SERVICE_NAME;
		}
    }

#ifdef WIN32
	bool bTestElevated = false;
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

	if (run_svc)
	{
		if (CTaskService::RunService(run_svc)) {
			//_exit(EXIT_SUCCESS);
			return EXIT_SUCCESS; // 0
		}
		return EXIT_FAILURE; // 1
	}

	wchar_t szPath[MAX_PATH];
	GetModuleFileNameW(NULL, szPath, ARRAYSIZE(szPath));
	*wcsrchr(szPath, L'\\') = L'\0';
	QString AppDir = QString::fromWCharArray(szPath);

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

#ifndef USE_TASK_HELPER
	InitPH(bSvc);
#else
	InitPH();
#endif

	STATUS DrvStatus = OK;

#ifdef Q_OS_WIN
#ifndef _DEBUG
	// Set the default priority.
	{
		PhSetProcessPriorityClass(NtCurrentProcess(), PROCESS_PRIORITY_CLASS_ABOVE_NORMAL);

		PhSetProcessPagePriority(NtCurrentProcess(), MEMORY_PRIORITY_NORMAL);
		PhSetProcessIoPriority(NtCurrentProcess(), IoPriorityNormal);
	}
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
		if (theConf->GetBool("OptionsKSI/KsiEnable", true) && IsElevated() && !PhIsExecutingInWow64())
		{
			DrvStatus = InitKSI(AppDir);
		}

#ifdef Q_OS_WIN
		SetProcessDPIAware();
#endif // Q_OS_WIN 
		//QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling); 
		//QCoreApplication::setAttribute(Qt::AA_DisableHighDpiScaling);

		//new QApplication(argc, argv);
		pApp = new QtSingleApplication((IsElevated() || bTestElevated) ? "TaskExplorer" : "UTaskExplorer", argc, argv);
	}

	if (pApp)
	{
		if (bTestElevated && pApp->isClient())
			return 0;

		if (!theConf->GetBool("Options/AllowMultipleInstances", false) && !bMulti && pApp->sendMessage("ShowWnd"))
			return 0;
	}

	//DrvStatus = ERR(STATUS_UNKNOWN_REVISION);
	int DynDataUpdate = 0;
	while (DrvStatus.IsError() || DynDataUpdate == 2)
	{
		QString Message;
		QDialogButtonBox::StandardButtons buttons = QDialogButtonBox::Ok | QDialogButtonBox::Cancel;
		if (DynDataUpdate == -1)
		{
			Message = CTaskExplorer::tr("Failed to update DynData, %1, Error: 0x%2 (%3).\n"
				"Do you want to continue anyways (Ok), or terminate (Cancel)?").arg(DrvStatus.GetText()).arg((quint32)DrvStatus.GetStatus(), 8, 16, QChar('0')).arg(CastPhString(PhGetNtMessage(DrvStatus.GetStatus())));
		}
		else if (DrvStatus.GetStatus() == STATUS_SI_DYNDATA_UNSUPPORTED_KERNEL || DrvStatus.GetStatus() == STATUS_UNKNOWN_REVISION || DynDataUpdate != 0) 
		{
			QString windowsVersion = QString("%1").arg(WindowsVersion); // todo
			QString kernelVersion = CastPhString(KsiGetKernelVersionString());

			Message = CTaskExplorer::tr("The current DynData for the KTaskExplorer driver does not yet supported on your windows kernel version.<br />"
				"You can check for <a href=\"https://github.com/DavidXanatos/TaskExplorer/releases\">TaskExplorer updates on github</a>, "
				"or grab the latest ksidyn.bin and ksidyn.sig from <a href=\"https://systeminformer.sourceforge.io/downloads\">the latest SystemInformer</a> "
				"and put them in the instalaltion directors next to KSystemInformer.sys.<br />"
				"Instalation Directory: %4<br />"
				"<br />"
				"Operating System Details:<br />"
				"&nbsp;&nbsp;&nbsp;&nbsp;Windows %1<br />"
				"&nbsp;&nbsp;&nbsp;&nbsp;Windows Kernel %2<br />"
				"&nbsp;&nbsp;&nbsp;&nbsp;TaskExplorer %3<br />"
				"<br />").arg(windowsVersion).arg(kernelVersion).arg(CTaskExplorer::GetVersion()).arg(AppDir);

			if (DynDataUpdate == 1)
				Message += CTaskExplorer::tr("Update did not help, do you want to continue anyways (Ok), or terminate (Cancel)?");
			else {
				Message += CTaskExplorer::tr("Do you want to try to download updated DynData (Yes), start without the driver (No), or terminate (Cancel)?");
				buttons = QDialogButtonBox::Yes | QDialogButtonBox::No | QDialogButtonBox::Cancel;
			}
		} 
		else {
			Message = CTaskExplorer::tr("Failed to load KTaskExplorer driver, %1, Error: 0x%2 (%3).\n"
				"Do you want to continue anyways (Ok), or terminate (Cancel)?").arg(DrvStatus.GetText()).arg((quint32)DrvStatus.GetStatus(), 8, 16, QChar('0')).arg(CastPhString(PhGetNtMessage(DrvStatus.GetStatus())));
		}

		bool State = false;
		int Ret = CCheckableMessageBox::question(NULL, "TaskExplorer", Message
			, CTaskExplorer::tr("Disable KTaskExplorer driver. Note: this will limit the aplications functionality!"), &State, 
			buttons, QDialogButtonBox::Cancel, QMessageBox::Warning);

		if (Ret == QDialogButtonBox::Yes)
		{
			DrvStatus = TryUpdateDynData(AppDir);
			if (DrvStatus.IsError()) {
				QMessageBox::critical(NULL, "TaskExplorer", CTaskExplorer::tr("Failed to update DynData, %1.").arg(DrvStatus.GetText()));
				DynDataUpdate = -1;
			}
			else {
				DynDataUpdate = 1;
				CleanupKSI();
				DrvStatus = InitKSI(AppDir);
			}
			continue;
		}

		if (Ret == QDialogButtonBox::Cancel)
			return -1;

		if (State)
			theConf->SetValue("Options/UseDriver", false);

		break;
	}

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
		if (PhIsExecutingInWow64())
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

		new CTaskExplorer();
		QObject::connect(QtSingleApplication::instance(), SIGNAL(messageReceived(const QString&)), theGUI, SLOT(OnMessage(const QString&)));
		
		ret = QApplication::exec();

		delete theGUI;

		CTaskService::TerminateWorkers();
	}

	CleanupKSI();

	// note: if ran as a service teh instance wil have already been delted, but delete NULL is ok
	delete QCoreApplication::instance();

	delete theConf;
	theConf = NULL;

	return ret;
}
