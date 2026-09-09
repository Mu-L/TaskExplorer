#include "stdafx.h"
#include "SettingsWindow.h"
#include "../version.h"
#include "ServerUserDialog.h"
#include "ConnectDialog.h"
#include "../SVC/WndAgents.h"
#include "TaskExplorer.h"
#include "../../MiscHelpers/Common/Settings.h"
#ifdef WIN32
#include "../../MiscHelpers/Archive/ArchiveFS.h"
#endif
#include "OnlineUpdater.h"
#include "../SVC/ServerSetup.h"
#include "../../MiscHelpers/Common/CredentialStore.h"
#include "../API/Cluster.h"
#include "../API/RemoteApi.h"
#include "../../TaskCommon/Support.h"	// the certificate's numbers; the words for them are at the end of this file
#include "UnlockDialog.h"
#include "../../MiscHelpers/Common/Crypto.h"
#ifdef WIN32
#include "../API/Windows/WinAdmin.h"
#else
#include "../API/Linux/LinuxHelper.h"
#include <QElapsedTimer>
#include <QThread>
#endif
#ifdef WIN32
#include <windows.h>
#include <shellapi.h>	// SHFileOperationW - see MoveFileWithPrompt
#endif
#include <QClipboard>
#include <QInputDialog>
#include <QNetworkInterface>
#include <QHostAddress>
#include <QHostInfo>
#include <QMessageBox>
#include <QDir>
#include <QFontDialog>
#include <QDesktopServices>

int CSettingsWindow__Chk2Int(Qt::CheckState state)
{
	switch (state) {
	case Qt::Unchecked: return 0;
	case Qt::Checked: return 1;
	default:
	case Qt::PartiallyChecked: return 2;
	}
}

Qt::CheckState CSettingsWindow__Int2Chk(int state)
{
	switch (state) {
	case 0: return Qt::Unchecked;
	case 1: return Qt::Checked;
	default:
	case 2: return Qt::PartiallyChecked;
	}
}

CSettingsWindow::CSettingsWindow(QWidget *parent)
	: QMainWindow(parent)
{
	QWidget* centralWidget = new QWidget();
	ui.setupUi(centralWidget);
	this->setCentralWidget(centralWidget);
	this->setWindowTitle(tr("Task Explorer - Settings"));

	FixTriStateBoxPallete(this);

	//
	// By page rather than by number: the icons used to be assigned to 0..4 and
	// inserting a tab anywhere but the end silently gave every page after it the
	// wrong picture.
	//
	ui.tabWidget->setTabPosition(QTabWidget::West);
	ui.tabWidget->setTabIcon(ui.tabWidget->indexOf(ui.tab), QIcon(":/Actions/Design"));
	ui.tabWidget->setTabIcon(ui.tabWidget->indexOf(ui.tab_4), QIcon(":/Actions/MiscOptions"));
	ui.tabWidget->setTabIcon(ui.tabWidget->indexOf(ui.tabRemote), QIcon(":/Actions/Computer"));
	ui.tabWidget->setTabIcon(ui.tabWidget->indexOf(ui.tab_2), QIcon(":/Actions/GUI"));
	ui.tabWidget->setTabIcon(ui.tabWidget->indexOf(ui.tab_3), QIcon(":/Actions/Settings"));
	ui.tabWidget->setTabIcon(ui.tabWidget->indexOf(ui.tabSupport), QIcon(":/Actions/Support"));

	//
	// Nothing on the Remote Machines page can be acted on without TaskRemote:
	// no connection can be made, no server can be reached, no announcement can
	// be listened for. The page is greyed with the reason rather than hidden,
	// so that somebody looking for a feature they know exists is told why it is
	// not here instead of finding nothing.
	//
	if (!CRemoteLoader::IsAvailable())
	{
		const int Index = ui.tabWidget->indexOf(ui.tabRemote);
		ui.tabWidget->setTabEnabled(Index, false);
		ui.tabWidget->setTabToolTip(Index, tr("This installation cannot connect to other machines: %1")
			.arg(CRemoteLoader::GetError()));
	}
	else if (!CRemoteLoader::CertificateState())
	{
		//
		// The module is there and will refuse: connecting to another machine is
		// a supporter feature. The page is left usable - the settings on it are
		// still worth reading and editing, and the server half of it works
		// without any of this - but the tab says so, because otherwise the only
		// place that mentions it is the error from a connection that failed.
		//
		const int Index = ui.tabWidget->indexOf(ui.tabRemote);
		ui.tabWidget->setTabToolTip(Index, tr("Connecting to other machines needs a supporter certificate - "
											  "see the Certificate tab on the Support && Updates page."));
	}

	InitCertificate();

	ui.tabWidget->setCurrentIndex(0);

	int size = 16.0;
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
	size *= (QApplication::desktop()->logicalDpiX() / 96.0); // todo Qt6
#endif

	{
		ui.uiLang->addItem(tr("Auto Detection"), "");
		ui.uiLang->addItem(tr("No Translation"), "native");

		QString langDir;
#ifdef WIN32
		// See CTaskExplorer::LoadLanguage - the 7-Zip file engine is
		// Windows-only, Linux reads the loose translations directory.
		C7zFileEngineHandler LangFS("lang", this);
		if (LangFS.Open(QApplication::applicationDirPath() + "/translations.7z"))
			langDir = LangFS.Prefix() + "/";
		else
#endif
			langDir = QApplication::applicationDirPath() + "/translations/";

		foreach(const QString & langFile, QDir(langDir).entryList(QStringList("taskexplorer_*.qm"), QDir::Files))
		{
			QString Code = langFile.mid(13, langFile.length() - 13 - 3);
			QLocale Locale(Code);
			QString Lang = Locale.nativeLanguageName();
			ui.uiLang->addItem(Lang, Code);
		}
		ui.uiLang->setCurrentIndex(ui.uiLang->findData(theConf->GetString("General/Language")));
	}

	ui.chkUseCycles->setChecked(theConf->GetBool("Options/EnableCycleCpuUsage", true));
	ui.chkLinuxStyle->setTristate(true);
	ui.chkLinuxStyle->setToolTip(tr("Linux CPU Usage shows 100% per core, i.e. if a process is using 2 cores to 100% it will show as 200% total cpu usage.\r\nPartiallyChecked state means apply only to thread std::list."));
	switch (theConf->GetInt("Options/LinuxStyleCPU", 2))
	{
	case 0:	ui.chkLinuxStyle->setCheckState(Qt::Unchecked); break;
	case 1:	ui.chkLinuxStyle->setCheckState(Qt::Checked); break;
	case 2:	ui.chkLinuxStyle->setCheckState(Qt::PartiallyChecked); break;
	}
	ui.chkClearZeros->setChecked(theConf->GetBool("Options/ClearZeros", true));

	ui.chkMaxThread->setChecked(theConf->GetBool("Options/ShowMaxThread", false));

	ui.chkShow32->setChecked(theConf->GetBool("Options/Show32", true));

	ui.chkDarkTheme->setCheckState(CSettingsWindow__Int2Chk(theConf->GetInt("MainWindow/DarkTheme", 2)));
	ui.chkFusionTheme->setCheckState(CSettingsWindow__Int2Chk(theConf->GetInt("MainWindow/UseFusionTheme", 2)));

	ui.cmbDPI->addItem(tr("None"), 0);
	ui.cmbDPI->addItem(tr("Native"), 1);
	ui.cmbDPI->addItem(tr("Qt"), 2);
	ui.cmbDPI->setCurrentIndex(theConf->GetInt("Options/DPIScaling", 1));

	int FontScales[] = { 75,100,125,150,175,200,225,250,275,300,350,400, 0 };
	for (int* pFontScales = FontScales; *pFontScales != 0; pFontScales++)
		ui.cmbFontScale->addItem(tr("%1").arg(*pFontScales), *pFontScales);
	//ui.cmbFontScale->setCurrentIndex(ui.cmbFontScale->findData(theConf->GetInt("Options/FontScaling", 100)));
	ui.cmbFontScale->setCurrentText(QString::number(theConf->GetInt("Options/FontScaling", 100)));

	// UI Font
	ui.btnSelectUiFont->setIcon(QPixmap(":/Actions/Font").scaled(size, size));
	ui.btnSelectUiFont->setToolTip(tr("Select font"));
	ui.btnResetUiFont->setIcon(QPixmap(":/Actions/ResetFont").scaled(size, size));
	ui.btnResetUiFont->setToolTip(tr("Reset font"));

	connect(ui.btnSelectUiFont, SIGNAL(clicked(bool)), this, SLOT(OnSelectUiFont()));
	connect(ui.btnResetUiFont, SIGNAL(clicked(bool)), this, SLOT(OnResetUiFont()));
	ui.lblUiFont->setText(QApplication::font().family());

	// Updater
	ui.cmbInterval->addItem(tr("Every Day"), 1 * 24 * 60 * 60);
	ui.cmbInterval->addItem(tr("Every Week"), 7 * 24 * 60 * 60);
	ui.cmbInterval->addItem(tr("Every 2 Weeks"), 14 * 24 * 60 * 60);
	ui.cmbInterval->addItem(tr("Every 30 days"), 30 * 24 * 60 * 60);

	ui.cmbUpdate->addItem(tr("Ignore"), "ignore");
	ui.cmbUpdate->addItem(tr("Notify"), "notify");
	ui.cmbUpdate->addItem(tr("Download & Notify"), "download");
	ui.cmbUpdate->addItem(tr("Download & Install"), "install");

	ui.cmbRelease->addItem(tr("Notify"), "notify");
	ui.cmbRelease->addItem(tr("Download & Notify"), "download");
	ui.cmbRelease->addItem(tr("Download & Install"), "install");

	ui.chkAutoUpdate->setCheckState(CSettingsWindow__Int2Chk(theConf->GetInt("Options/CheckForUpdates", 2)));

	int UpdateInterval = theConf->GetInt("Options/UpdateInterval", UPDATE_INTERVAL);
	int pos = ui.cmbInterval->findData(UpdateInterval);
	if (pos == -1)
		ui.cmbInterval->setCurrentText(QString::number(UpdateInterval));
	else
		ui.cmbInterval->setCurrentIndex(pos);

	QString ReleaseChannel = theConf->GetString("Options/ReleaseChannel", "stable");
	ui.radStable->setChecked(ReleaseChannel == "stable");
	ui.radPreview->setChecked(ReleaseChannel == "preview");

	UpdateUpdater();

	ui.cmbUpdate->setCurrentIndex(ui.cmbUpdate->findData(theConf->GetString("Options/OnNewUpdate", "ignore")));
	ui.cmbRelease->setCurrentIndex(ui.cmbRelease->findData(theConf->GetString("Options/OnNewRelease", "download")));

	connect(ui.lblCurrent, SIGNAL(linkActivated(const QString&)), this, SLOT(OnUpdate(const QString&)));
	connect(ui.lblStable, SIGNAL(linkActivated(const QString&)), this, SLOT(OnUpdate(const QString&)));
	connect(ui.lblPreview, SIGNAL(linkActivated(const QString&)), this, SLOT(OnUpdate(const QString&)));

	connect(ui.chkAutoUpdate, SIGNAL(toggled(bool)), this, SLOT(UpdateUpdater()));
	connect(ui.radStable, SIGNAL(toggled(bool)), this, SLOT(UpdateUpdater()));
	connect(ui.radPreview, SIGNAL(toggled(bool)), this, SLOT(UpdateUpdater()));
	//

	ui.highlightCount->setValue(theConf->GetInt("Options/HighLoadHighlightCount", 5));

	ui.refreshInterval->setValue(theConf->GetInt("Options/RefreshInterval", 1000));
	ui.graphLength->setValue(theConf->GetInt("Options/GraphLength", 300));

	ui.chkUdpCons->setChecked(theConf->GetBool("Options/UseUDPPseudoConnectins", false));
	ui.chkLanPlot->setChecked(theConf->GetBool("Options/ShowLanPlot", false));
	ui.chkSmartDns->setChecked(theConf->GetBool("Options/MonitorDnsCache", false));
	//
	// Off by default: the socket lists are a network view, as they are on
	// Windows, and a Linux machine has hundreds of these. Also on the View menu,
	// which is where one reaches for it while looking at a list.
	//
	ui.chkUnixSockets->setChecked(theConf->GetBool("Options/ShowUnixSockets", false));
	ui.chkReverseDns->setChecked(theConf->GetBool("Options/UserReverseDns", false));

	ui.chkUndecorate->setChecked(theConf->GetBool("Options/DbgHelpUndecorate", true));
	ui.symbolPath->setText(theConf->GetString("Options/DbgHelpSearchPath", "SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols"));

	int DbgHelpSearch = theConf->GetInt("Options/DbgHelpSearch", 2);
	if (DbgHelpSearch == 2) {
		ui.chkSymbolPath->setTristate(true);
		ui.chkSymbolPath->setCheckState(Qt::PartiallyChecked);
	} else
		ui.chkSymbolPath->setChecked(DbgHelpSearch == 1);

	ui.onClose->addItem(tr("Close to Tray"), "ToTray");
	ui.onClose->addItem(tr("Prompt before Close"), "Prompt");
	ui.onClose->addItem(tr("Close"), "Close");
	ui.onClose->setCurrentIndex(ui.onClose->findData(theConf->GetString("Options/OnClose", "ToTray")));


	ui.chkShowTray->setChecked(theConf->GetBool("SysTray/Show", true));

	ui.trayMode->addItem(tr("Show static Icon"), "Icon");
	ui.trayMode->addItem(tr("CPU plot"), "Cpu");
	ui.trayMode->addItem(tr("CPU plot and Memory bar"), "CpuMem");
	ui.trayMode->addItem(tr("CPU plot and RAM bar"), "CpuMem1");
	ui.trayMode->addItem(tr("CPU plot and RAM+Swap bars"), "CpuMem2");
	ui.trayMode->setCurrentIndex(ui.trayMode->findData(theConf->GetString("SysTray/GraphMode", "CpuMem")));

	ui.chkSandboxie->setChecked(theConf->GetBool("Options/UseSandboxie", false));

	ui.chkSoftForce->setCheckState((Qt::CheckState)theConf->GetInt("Options/UseSoftForce", 2));

	ui.highlightTime->setValue(theConf->GetUInt64("Options/HighlightTime", 2500));
	ui.persistenceTime->setValue(theConf->GetUInt64("Options/PersistenceTime", 5000));

	ui.processName->addItem(tr("Description (Binary name)"), 1);
	ui.processName->addItem(tr("Binary name (Description)"), 2);
	ui.processName->addItem(tr("Binary name only"), 0);
	ui.processName->setCurrentIndex(ui.processName->findData(theConf->GetInt("Options/ShowProcessDescr", 1)));

	ui.chkParents->setChecked(theConf->GetBool("Options/EnableParentRetention", true));
	//
	// Grouping by user account is not here any more either - it is a toolbar
	// button beside the tree/list switch, which is what it belongs with. The
	// window writes Options/MultiUser itself; see CProcessTree::SetMultiUser.
	//

	//
	// Only where the notion exists. Window stations and desktops are a Windows
	// idea; X11 and Wayland have the same problem in a different shape and
	// nothing has been built for it, so the box is not offered rather than
	// offered and inert.
	//
#ifdef WIN32
	ui.chkDeskAgents->setChecked(theConf->GetBool("Options/UseDesktopAgents", false));
#else
	ui.chkDeskAgents->setVisible(false);
#endif
	//
	// Cluster mode is not here any more. It moved to the toolbar, next to the
	// other switch that decides how the tree is arranged - it is answered while
	// looking at the tree rather than while in a dialog. The stored value is
	// untouched; only the place it is set from changed.
	//

	//
	// Seconds here and seconds in the file. Ten thousand milliseconds reads as a
	// number somebody has to convert; ten seconds reads as an interval.
	//
	ui.spinReconnect->setValue(theConf->GetInt("Options/ReconnectInterval", 10));

	//
	// Two switches, deliberately unrelated. Looking is this viewer's business;
	// being found is the daemon's, and lives with the rest of the server setup
	// because that is what it changes.
	//
	ui.chkDiscover->setChecked(theConf->GetBool("Options/Discover", false));
	ui.spinDiscoverEvery->setValue(theConf->GetInt("Options/DiscoveryInterval", 30));
	ui.spinDiscoveryPort->setValue(theConf->GetInt("Options/DiscoveryPort", 28334));
	connect(ui.chkDiscover, SIGNAL(stateChanged(int)), this, SLOT(OnDiscoveryToggled()));
	connect(ui.spinDiscoverEvery, SIGNAL(valueChanged(int)), this, SLOT(OnChange()));
	connect(ui.spinDiscoveryPort, SIGNAL(valueChanged(int)), this, SLOT(OnChange()));
	connect(ui.chkAnnounce, SIGNAL(stateChanged(int)), this, SLOT(OnChange()));
	connect(ui.spinAnnounceEvery, SIGNAL(valueChanged(int)), this, SLOT(OnChange()));

	LoadServerSetup();
	connect(ui.chkServer, SIGNAL(stateChanged(int)), this, SLOT(OnServerToggled()));
	connect(ui.btnServerKey, SIGNAL(clicked()), this, SLOT(OnGenerateServerKey()));
	connect(ui.btnServerShow, SIGNAL(clicked()), this, SLOT(OnShowServerKey()));
	connect(ui.btnServerStart, SIGNAL(clicked()), this, SLOT(OnStartServer()));
	connect(ui.btnServerStop, SIGNAL(clicked()), this, SLOT(OnStopServer()));
	connect(ui.btnUserAdd, SIGNAL(clicked()), this, SLOT(OnAddUser()));
	connect(ui.btnUserEdit, SIGNAL(clicked()), this, SLOT(OnEditUser()));
	connect(ui.btnUserRemove, SIGNAL(clicked()), this, SLOT(OnRemoveUser()));
	connect(ui.treeServerUsers, SIGNAL(itemSelectionChanged()), this, SLOT(OnUserSelectionChanged()));
	connect(ui.treeServerUsers, SIGNAL(itemDoubleClicked(QTreeWidgetItem*,int)), this, SLOT(OnEditUser()));
	connect(ui.btnForgetKeys, SIGNAL(clicked()), this, SLOT(OnForgetKeys()));
	connect(ui.btnMachineEdit, SIGNAL(clicked()), this, SLOT(OnEditMachine()));
	connect(ui.btnMachineRemove, SIGNAL(clicked()), this, SLOT(OnRemoveMachine()));
	connect(ui.treeMachines, SIGNAL(itemSelectionChanged()), this, SLOT(OnMachineSelectionChanged()));
	connect(ui.treeMachines, SIGNAL(itemDoubleClicked(QTreeWidgetItem*,int)), this, SLOT(OnEditMachine()));
	connect(ui.chkRememberPassword, SIGNAL(clicked()), this, SLOT(OnRememberPassword()));
	UpdateSavedKeys();
	LoadMachines();
	connect(ui.spinListenPort, SIGNAL(valueChanged(int)), this, SLOT(OnChange()));
	connect(ui.cmbBindAddress, SIGNAL(currentTextChanged(const QString&)), this, SLOT(OnChange()));
	ui.chkGetRefServices->setChecked(theConf->GetBool("Options/GetServicesRefModule", true));
	ui.chkTraceDLLs->setChecked(theConf->GetBool("Options/TraceUnloadedModules", false));

	//ui.chkOpenFilePos->setChecked(theConf->GetBool("Options/OpenFileGetPosition", false));

	connect(ui.colorList, SIGNAL(itemDoubleClicked(QListWidgetItem*)), this, SLOT(OnChangeColor(QListWidgetItem*)));

	connect(ui.chkShowTray, SIGNAL(stateChanged(int)), this, SLOT(OnChange()));
	//connect(ui.chkUseCycles, SIGNAL(stateChanged(int)), this, SLOT(OnChange()));

	connect(ui.chkSimpleCopy, SIGNAL(stateChanged(int)), this, SLOT(OnChange()));

	ui.chkSimpleCopy->setChecked(theConf->GetBool("Options/PanelCopySimple", false));
	ui.maxCellWidth->setValue(theConf->GetInt("Options/PanelCopyMaxCellWidth", 0));
	ui.cellSeparator->setText(theConf->GetString("Options/PanelCopyCellSeparator", "\\t"));


	foreach(const CTaskExplorer::SColor& Color, theGUI->GetAllColors())
	{
		QListWidgetItem* pItem = new QListWidgetItem(Color.Description);

		StrPair ColorUse = Split2(theConf->GetString("Colors/" + Color.Name, Color.Default), ";");

		// pItem->setFlags(pItem->flags() | Qt::ItemIsUserCheckable); // set checkable flag
		if (Color.Name == "GridColor")
			pItem->setCheckState(theConf->GetBool("Options/ShowGrid", true) ? Qt::Checked : Qt::Unchecked);
		else if (Color.Name != "Background" 
		 && Color.Name != "GraphBack" && Color.Name != "GraphFront"
		 && Color.Name != "PlotBack" && Color.Name != "PlotFront" && Color.Name != "PlotGrid" 
		)
		{
			bool bUse = ColorUse.second.isEmpty() || ColorUse.second.compare("true", Qt::CaseInsensitive) == 0 || ColorUse.second.toInt() != 0;
			pItem->setCheckState(bUse ? Qt::Checked : Qt::Unchecked);
		}

		pItem->setData(Qt::UserRole, Color.Name);
		pItem->setBackground(QColor(ColorUse.first));

		ui.colorList->addItem(pItem);
	}

	connect(ui.buttonBox->button(QDialogButtonBox::Ok), SIGNAL(pressed()), this, SLOT(accept()));
	connect(ui.buttonBox->button(QDialogButtonBox::Apply), SIGNAL(pressed()), this, SLOT(apply()));
	connect(ui.buttonBox, SIGNAL(rejected()), this, SLOT(reject()));

	connect(ui.tabWidget, SIGNAL(currentChanged(int)), this, SLOT(OnTab()));

	restoreGeometry(theConf->GetBlob("SettingsWindow/Window_Geometry"));

	OnChange();
}

CSettingsWindow::~CSettingsWindow()
{
	theConf->SetBlob("SettingsWindow/Window_Geometry",saveGeometry());
}

void CSettingsWindow::closeEvent(QCloseEvent *e)
{
	this->deleteLater();
}

void CSettingsWindow::apply()
{
	//
	// The certificate first, because it is the one thing on this window that is
	// written to a file outside the configuration and may put a prompt on
	// screen. Doing it after everything else would mean a settings page that
	// looked applied while a dialog was still asking about a file.
	//
	if (m_bCertChanged)
		ApplyCertificate();

	theConf->SetValue("General/Language", ui.uiLang->currentData());

	theConf->SetValue("Options/EnableCycleCpuUsage", ui.chkUseCycles->isChecked());
	switch (ui.chkLinuxStyle->checkState())
	{
	case Qt::Unchecked: theConf->GetInt("Options/LinuxStyleCPU", 0); break;
	case Qt::Checked: theConf->GetInt("Options/LinuxStyleCPU", 1); break;
	case Qt::PartiallyChecked:theConf->GetInt("Options/LinuxStyleCPU", 2); break;
	}
	theConf->SetValue("Options/ClearZeros", ui.chkClearZeros->isChecked());

	theConf->SetValue("Options/ShowMaxThread", ui.chkMaxThread->isChecked());

	theConf->SetValue("Options/Show32", ui.chkShow32->isChecked());

	theConf->SetValue("MainWindow/DarkTheme", CSettingsWindow__Chk2Int(ui.chkDarkTheme->checkState()));
	theConf->SetValue("MainWindow/UseFusionTheme", CSettingsWindow__Chk2Int(ui.chkFusionTheme->checkState()));


	theConf->SetValue("Options/UIFont", ui.lblUiFont->text());
	theConf->SetValue("Options/DPIScaling", ui.cmbDPI->currentData());
	int Scaling = ui.cmbFontScale->currentText().toInt();
	if (Scaling < 75)
		Scaling = 75;
	else if (Scaling > 500)
		Scaling = 500;
	theConf->SetValue("Options/FontScaling", Scaling);


	theConf->SetValue("Options/HighLoadHighlightCount", ui.highlightCount->value());

	theConf->SetValue("Options/RefreshInterval", ui.refreshInterval->value());
	theConf->SetValue("Options/GraphLength", ui.graphLength->value());

	theConf->SetValue("Options/UseUDPPseudoConnectins", ui.chkUdpCons->isChecked());
	theConf->SetValue("Options/ShowLanPlot", ui.chkLanPlot->isChecked());
	theConf->SetValue("Options/MonitorDnsCache", ui.chkSmartDns->isChecked());
	theConf->SetValue("Options/ShowUnixSockets", ui.chkUnixSockets->isChecked());
	theConf->SetValue("Options/UserReverseDns", ui.chkReverseDns->isChecked());


	theConf->SetValue("Options/DbgHelpUndecorate", ui.chkUndecorate->isChecked());
	theConf->SetValue("Options/DbgHelpSearchPath", ui.symbolPath->text());
	if(ui.chkSymbolPath->checkState() != Qt::PartiallyChecked)
		theConf->SetValue("Options/DbgHelpSearch", ui.chkSymbolPath->isChecked() ? 1 : 0);

	theConf->SetValue("SysTray/OnClose", ui.onClose->currentData());

	theConf->SetValue("SysTray/Show", ui.chkShowTray->isChecked());

	theConf->SetValue("SysTray/GraphMode", ui.trayMode->currentData());

	theConf->SetValue("Options/UseSandboxie", ui.chkSandboxie->isChecked());

	theConf->SetValue("Options/UseSoftForce", (int)ui.chkSoftForce->checkState());

	theConf->SetValue("Options/HighlightTime", ui.highlightTime->value());
	theConf->SetValue("Options/PersistenceTime", ui.persistenceTime->value());
	
	theConf->SetValue("Options/ShowProcessDescr", ui.processName->currentData());

	theConf->SetValue("Options/EnableParentRetention", ui.chkParents->isChecked());


	//
	// Through the manager rather than by writing the value, because turning it
	// off has to stop the helpers that are already running in other people's
	// sessions - see CWndAgents::SetEnabled.
	//
	CWndAgents::Instance()->SetEnabled(ui.chkDeskAgents->isChecked());

	theConf->SetValue("Options/ReconnectInterval", ui.spinReconnect->value());

	theConf->SetValue("Options/Discover", ui.chkDiscover->isChecked());
	theConf->SetValue("Options/DiscoveryInterval", ui.spinDiscoverEvery->value());
	theConf->SetValue("Options/DiscoveryPort", ui.spinDiscoveryPort->value());

	//
	// Applied here rather than at the next start: somebody who has just ticked
	// the box expects the list to fill in, and somebody who has just cleared it
	// expects the traffic to stop.
	//
	if (theCluster)
	{
		if (ui.chkDiscover->isChecked())
		{
			QString Error;
			if (!theCluster->StartDiscovery(&Error) && !Error.isEmpty())
				QMessageBox::warning(this, "TaskExplorer",
					tr("Cannot look for machines: %1").arg(Error));
		}
		else
			theCluster->StopDiscovery();
	}

	//
	// After the settings, not among them: this one leaves the file and changes
	// the machine, and it can fail in ways a setting cannot.
	//
	ApplyServerSetup();
	theConf->SetValue("Options/GetServicesRefModule", ui.chkGetRefServices->isChecked());
	theConf->SetValue("Options/TraceUnloadedModules", ui.chkTraceDLLs->isChecked());

	//theConf->SetValue("Options/OpenFileGetPosition", ui.chkOpenFilePos->isChecked());

	theConf->SetValue("Options/PanelCopySimple", ui.chkSimpleCopy->isChecked());
	theConf->SetValue("Options/PanelCopyMaxCellWidth", ui.maxCellWidth->value());
	theConf->SetValue("Options/PanelCopyCellSeparator", ui.cellSeparator->text());


	for (int i = 0; i < ui.colorList->count(); i++)
	{
		QListWidgetItem* pItem = ui.colorList->item(i);
		QString Name = pItem->data(Qt::UserRole).toString();

		QString ColorStr = pItem->background().color().name();

		if (Name == "GridColor")
			theConf->SetValue("Options/ShowGrid", pItem->checkState() == Qt::Checked);
		else if (Name != "Background"
		 && Name != "GraphBack" && Name != "GraphFront"
		 && Name != "PlotBack" && Name != "PlotFront" && Name != "PlotGrid"
		)
			ColorStr += ";" + QString((pItem->checkState() == Qt::Checked) ? "true" : "false");

		theConf->SetValue("Colors/" + Name, ColorStr);
	}

	// Updater
	theConf->SetValue("Options/CheckForUpdates", CSettingsWindow__Chk2Int(ui.chkAutoUpdate->checkState()));

	int UpdateInterval = ui.cmbInterval->currentData().toInt();
	if (!UpdateInterval)
		UpdateInterval = ui.cmbInterval->currentText().toInt();
	if (!UpdateInterval)
		UpdateInterval = UPDATE_INTERVAL;
	theConf->SetValue("Options/UpdateInterval", UpdateInterval);

	QString ReleaseChannel;
	if (ui.radStable->isChecked())
		ReleaseChannel = "stable";
	else if (ui.radPreview->isChecked())
		ReleaseChannel = "preview";
	if(!ReleaseChannel.isEmpty()) theConf->SetValue("Options/ReleaseChannel", ReleaseChannel);

	theConf->SetValue("Options/OnNewUpdate", ui.cmbUpdate->currentData());
	theConf->SetValue("Options/OnNewRelease", ui.cmbRelease->currentData());
	//

	emit OptionsChanged();
}

void CSettingsWindow::accept()
{
	apply();

	this->close();
}

void CSettingsWindow::reject()
{
	this->close();
}

void CSettingsWindow::OnChangeColor(QListWidgetItem* pItem)
{
	QColor color = QColorDialog::getColor(pItem->background().color(), this, "Select color");
	if (color.isValid())
		pItem->setBackground(color);
}

void CSettingsWindow::OnChange()
{
	//ui.chkLinuxStyle->setEnabled(!ui.chkUseCycles->isChecked());

	QStandardItemModel *model = qobject_cast<QStandardItemModel *>(ui.onClose->model());
	QStandardItem *item = model->item(0);
	item->setFlags((!ui.chkShowTray->isChecked()) ? item->flags() & ~Qt::ItemIsEnabled : item->flags() | Qt::ItemIsEnabled);

	ui.trayMode->setEnabled(ui.chkShowTray->isChecked());

	ui.cellSeparator->setEnabled(ui.chkSimpleCopy->isChecked());
	ui.maxCellWidth->setEnabled(!ui.chkSimpleCopy->isChecked());
}

void CSettingsWindow::OnSelectUiFont()
{
	bool ok;
	auto newFont = QFontDialog::getFont(&ok, QApplication::font(), this);
	if (!ok) return;
	ui.lblUiFont->setText(newFont.family());
}

void CSettingsWindow::OnResetUiFont()
{
	QFont defaultFont = QFontDatabase::systemFont(QFontDatabase::GeneralFont);
	ui.lblUiFont->setText(defaultFont.family());
}

void CSettingsWindow::UpdateUpdater()
{
	if (!ui.chkAutoUpdate->isChecked())
	{
		ui.cmbInterval->setEnabled(false);
		ui.cmbUpdate->setEnabled(false);
		ui.cmbRelease->setEnabled(false);
		ui.lblRevision->setText(QString());
		ui.lblRelease->setText(QString());
	}
	else
	{
		ui.cmbInterval->setEnabled(true);
		ui.cmbUpdate->setEnabled(true);
		ui.cmbRelease->setEnabled(true);

		ui.lblRevision->setText(QString());
		ui.lblRelease->setText(QString());
	}
}

void CSettingsWindow::OnTab()
{
	// The updater tab, asked by page rather than by number - see the icons above.
	if (ui.tabWidget->currentWidget() == ui.tabSupport)
	{
		if (ui.lblCurrent->text().isEmpty()) {
			if (ui.chkAutoUpdate->checkState() == Qt::Checked)
				GetUpdates();
			else
				ui.lblCurrent->setText(tr("<a href=\"check\">Check Now</a>"));
		}
	}
}

void CSettingsWindow::GetUpdates()
{
	QVariantMap Params;
	Params["channel"] = "all";
	theGUI->GetOnlineUpdater()->GetUpdates(this, SLOT(OnUpdateData(const QVariantMap&, const QVariantMap&)), Params);
}

QString CSettingsWindow__MkVersion(const QString& Name, const QVariantMap& Releases)
{
	QVariantMap Release = Releases[Name].toMap();
	QString Version = Release.value("version").toString();
	int iUpdate = Release["update"].toInt();
	if(iUpdate) Version += QChar('a' + (iUpdate - 1));
	return QString("<a href=\"%1\">%2</a>").arg(Name, Version);
}

void CSettingsWindow::OnUpdateData(const QVariantMap& Data, const QVariantMap& Params)
{
	if (Data.isEmpty() || Data["error"].toBool())
		return;

	m_UpdateData = Data;
	QVariantMap Releases = m_UpdateData["releases"].toMap();
	ui.lblCurrent->setText(tr("%1 (Current)").arg(COnlineUpdater::GetCurrentVersion()));
	ui.lblStable->setText(CSettingsWindow__MkVersion("stable", Releases));
	ui.lblPreview->setText(CSettingsWindow__MkVersion("preview", Releases));
}

void CSettingsWindow::OnUpdate(const QString& Channel)
{
	if (Channel == "check") {
		GetUpdates();
		return;
	}

	QVariantMap Releases = m_UpdateData["releases"].toMap();
	QVariantMap Release = Releases[Channel].toMap();

	QString VersionStr = Release["version"].toString();
	if (VersionStr.isEmpty())
		return;

	QString InfoUrl = Release["infoUrl"].toString();
	if (InfoUrl.isEmpty())
		InfoUrl = "https://xanasoft.com/go.php?to=sbie-get";
	QDesktopServices::openUrl(InfoUrl);
}

//
// ---- serving this machine ----
//
// The dialog only ever asks CServerSetup; it does not know what a service is on
// either platform, and it does not have to. What it does own is the awkward
// part: it may be running without the rights to change anything, and the key it
// would set must not travel where a process list can see it.
//

void CSettingsWindow::LoadServerSetup()
{
	if (!m_pServerWas)
		m_pServerWas = new SServerSetup();

	CServerSetup::Query(m_pServerWas);

	ui.chkServer->setChecked(m_pServerWas->bInstalled);
	//
	// Shown as placeholder text when it is the default, so that the field says
	// what the name is without looking like something somebody chose.
	//
	ui.txtServerName->setText(m_pServerWas->Name.compare(MY_DAEMON_NAME_STRING, Qt::CaseInsensitive) == 0
		? QString() : m_pServerWas->Name);

	ui.spinListenPort->setValue(m_pServerWas->Port);
	ui.chkLocalPipe->setChecked(m_pServerWas->bLocalPipe);

	//
	// Windows only, because there is no driver anywhere else. The box is still
	// filled in from the configuration when it is hidden, so that whatever the
	// file says is what gets written back rather than the struct's default.
	//
	ui.chkServerDriver->setChecked(m_pServerWas->bUseDriver);
#ifndef WIN32
	ui.chkServerDriver->setVisible(false);
#endif

	ui.chkAnnounce->setChecked(m_pServerWas->bAnnounce);
	ui.spinAnnounceEvery->setValue(m_pServerWas->AnnounceInterval);
	if (m_pServerWas->DiscoveryPort != 0)
		ui.spinDiscoveryPort->setValue(m_pServerWas->DiscoveryPort);

	//
	// The addresses this machine actually has, offered rather than described.
	// Typing one is still allowed - an address that only exists once a VPN is
	// up cannot be listed and is exactly when somebody would want to bind.
	//
	ui.cmbBindAddress->clear();
	ui.cmbBindAddress->addItem(tr("Every address"), QString());
	foreach(const QHostAddress& Address, QNetworkInterface::allAddresses())
	{
		if (Address.isLoopback())
			continue;
		ui.cmbBindAddress->addItem(Address.toString(), Address.toString());
	}
	ui.cmbBindAddress->addItem(QHostAddress(QHostAddress::LocalHost).toString(),
		QHostAddress(QHostAddress::LocalHost).toString());

	if (m_pServerWas->Bind.isEmpty())
		ui.cmbBindAddress->setCurrentIndex(0);
	else
		ui.cmbBindAddress->setCurrentText(m_pServerWas->Bind);

	//
	// The key is never put in the field, even when it could be read. A password
	// box that is already full invites somebody to leave it alone and then
	// wonder why the key they were told is not the key that works; and the dots
	// would be as long as the real one, which is one bit more than nothing.
	//
	//
	// The transport key is never put in the field, even though this dialog could
	// read it: a password box that is already full invites somebody to leave it
	// alone and then wonder why the key they were told is not the key that
	// works. Query() does not fetch the value at all - see SServerSetup::bHasPsk.
	//
	m_ShownServerKey.clear();
	ui.btnServerShow->setChecked(false);
	ui.btnServerShow->setText(tr("Show"));
	ui.txtServerKey->setEchoMode(QLineEdit::Password);
	ui.txtServerKey->clear();
	ui.txtServerKey->setPlaceholderText(m_pServerWas->bHasPsk
		? tr("Unchanged") : tr("No key set - one will be generated"));

	LoadServerUsers();
	UpdateServerState();
}

//
// The accounts on the server, as it has them.
//
// Read from the file rather than kept in the dialog, and re-read after every
// change. Each edit is written through immediately - see OnEditUser - so there
// is no pending state here to get out of step with what is stored, and no way
// for pressing Cancel to half-apply a list.
//
// That is deliberately unlike the rest of this page, where nothing happens
// until OK. A password is not a setting: batching it would mean holding a
// plaintext password in a dialog until the user got round to pressing a button,
// and losing it if they closed the window instead.
//
void CSettingsWindow::LoadServerUsers()
{
	ui.treeServerUsers->clear();

	QList<SServerUserRecord> Users;
	CServerSetup::ReadUsers(&Users);

	foreach(const SServerUserRecord& User, Users)
	{
		QTreeWidgetItem* pItem = new QTreeWidgetItem();
		pItem->setText(0, User.Name);
		pItem->setText(1, User.bAdmin ? tr("Admin") : tr("User"));
		pItem->setText(2, User.bActions ? tr("May act") : tr("Read only"));
		pItem->setText(3, User.bSystemAccount ? tr("System account") : tr("Set here"));
		pItem->setData(0, Qt::UserRole, User.Name);
		pItem->setData(1, Qt::UserRole, User.bAdmin);
		pItem->setData(2, Qt::UserRole, User.bActions);
		pItem->setData(3, Qt::UserRole, User.bSystemAccount);
		ui.treeServerUsers->addTopLevelItem(pItem);
	}

	for (int i = 0; i < 4; i++)
		ui.treeServerUsers->resizeColumnToContents(i);

	OnUserSelectionChanged();
}

void CSettingsWindow::OnUserSelectionChanged()
{
	const bool bMayChange = CServerSetup::IsPrivileged();
	const bool bOne = ui.treeServerUsers->selectedItems().count() == 1;
	ui.btnUserEdit->setEnabled(bMayChange && bOne);
	ui.btnUserRemove->setEnabled(bMayChange && bOne);
}

//
// Writes one record and re-reads the list, or says why it could not.
//
static bool ApplyUser(QWidget* pParent, const SServerUserRecord& User)
{
	STATUS Status = CServerSetup::WriteUser(User);
	if (Status.IsError())
	{
		QMessageBox::warning(pParent, "TaskExplorer", CTaskExplorer::FormatError(Status));
		return false;
	}
	return true;
}

void CSettingsWindow::OnAddUser()
{
	SServerUserRecord User;
	CServerUserDialog Dialog(User, this);
	if (Dialog.exec() != QDialog::Accepted)
		return;

	const SServerUserRecord Wanted = Dialog.GetUser();

	//
	// Refused here rather than silently replacing: WriteUser would happily
	// overwrite, and "Add" that quietly rewrote somebody else's account - level,
	// actions and password - is not what the button says.
	//
	QList<SServerUserRecord> Existing;
	CServerSetup::ReadUsers(&Existing);
	foreach(const SServerUserRecord& One, Existing)
	{
		if (One.Name.compare(Wanted.Name, Qt::CaseInsensitive) != 0)
			continue;
		QMessageBox::warning(this, "TaskExplorer",
			tr("There is already a user called \"%1\".").arg(Wanted.Name));
		return;
	}

	if (ApplyUser(this, Wanted))
		LoadServerUsers();
}

void CSettingsWindow::OnEditUser()
{
	QList<QTreeWidgetItem*> Selected = ui.treeServerUsers->selectedItems();
	if (Selected.count() != 1)
		return;

	SServerUserRecord User;
	User.Name = Selected[0]->data(0, Qt::UserRole).toString();
	User.bAdmin = Selected[0]->data(1, Qt::UserRole).toBool();
	User.bActions = Selected[0]->data(2, Qt::UserRole).toBool();
	User.bSystemAccount = Selected[0]->data(3, Qt::UserRole).toBool();

	CServerUserDialog Dialog(User, this);
	if (Dialog.exec() != QDialog::Accepted)
		return;

	if (ApplyUser(this, Dialog.GetUser()))
		LoadServerUsers();
}

void CSettingsWindow::OnRemoveUser()
{
	QList<QTreeWidgetItem*> Selected = ui.treeServerUsers->selectedItems();
	if (Selected.count() != 1)
		return;

	const QString Name = Selected[0]->data(0, Qt::UserRole).toString();

	//
	// Asked, because it cannot be undone from here: the stored hash goes with
	// the record and the password would have to be set again by whoever knows
	// it - which, by design, is nobody on this side.
	//
	if (QMessageBox::question(this, "TaskExplorer",
			tr("Remove \"%1\"? Any viewer logged in as this user keeps its connection "
			   "until it disconnects.").arg(Name),
			QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
		return;

	STATUS Status = CServerSetup::RemoveUser(Name);
	if (Status.IsError())
		QMessageBox::warning(this, "TaskExplorer", CTaskExplorer::FormatError(Status));

	LoadServerUsers();
}

void CSettingsWindow::UpdateServerState()
{
	//
	// Nothing here can be done without privileges, so the page is disabled whole
	// rather than each control refusing in turn.
	//
	// It used to offer to ask for them and hand the work to an elevated
	// TaskConsole, which works, but it makes every control on the page a promise
	// this process cannot keep on its own - including the ones that only save a
	// file. Disabling says the same thing once, before anything is typed.
	//
	const bool bMayChange = CServerSetup::IsPrivileged();
	ui.tabRemoteServer->setEnabled(bMayChange);

	//
	// And nothing at all can be done without the program itself. The tab is
	// disabled from the outside in that case, so the label greys out too -
	// there is no point letting somebody open a page to read that it is empty.
	//
	const bool bHaveServer = CServerSetup::IsAvailable();
	const int iServer = ui.tabsRemote->indexOf(ui.tabRemoteServer);
	ui.tabsRemote->setTabEnabled(iServer, bHaveServer);
	if (!bHaveServer)
	{
		ui.tabsRemote->setTabToolTip(iServer, tr("TaskServer is not installed with this copy of TaskExplorer: %1")
			.arg(QDir::toNativeSeparators(CServerSetup::ServerBinaryPath())));
	}


	//
	// The settings are *not* gated on the checkbox any more.
	//
	// They describe what a server on this machine does, and a server on this
	// machine is not only an installed service - one started from a console reads
	// the same file. Greying them out when nothing is installed made them look
	// like properties of the service, which they are not, and left no way to set
	// up the file before installing or after removing.
	//
	const bool bOn = bMayChange;

	ui.lblListenPort->setEnabled(bOn);
	ui.spinListenPort->setEnabled(bOn);
	ui.lblBindAddress->setEnabled(bOn);
	ui.chkLocalPipe->setEnabled(bOn);
	ui.cmbBindAddress->setEnabled(bOn);
	ui.lblServerKey->setEnabled(bOn);
	ui.txtServerKey->setEnabled(bOn);
	ui.btnServerKey->setEnabled(bOn);
	ui.btnServerShow->setEnabled(bOn);
	ui.lblServerUsers->setEnabled(bOn);
	ui.treeServerUsers->setEnabled(bOn);
	ui.btnUserAdd->setEnabled(bOn);

	//
	// Being findable needs something to find, which is still true - but it is the
	// port that decides it, not whether a service is installed.
	//
	// It does need the program though, which is the server's half of discovery
	// and so goes with the server. Looking for machines is this viewer's half
	// and needs only TaskRemote - it keeps working on a machine that serves
	// nothing, which is the ordinary case for a viewer watching daemons
	// elsewhere - so the Discovery tab itself stays open.
	//
	const bool bMayAnnounce = bOn && bHaveServer;
	ui.chkAnnounce->setEnabled(bMayAnnounce);
	ui.lblAnnounceEvery->setEnabled(bMayAnnounce && ui.chkAnnounce->isChecked());
	ui.spinAnnounceEvery->setEnabled(bMayAnnounce && ui.chkAnnounce->isChecked());
	ui.lblAnnounceUnit->setEnabled(bMayAnnounce && ui.chkAnnounce->isChecked());

	//
	// Starting and stopping is for something that exists. Both stay visible so
	// that what installing gets you is clear before you install it.
	//
	const bool bInstalled = m_pServerWas && m_pServerWas->bInstalled;
	ui.btnServerStart->setEnabled(bMayChange && bInstalled && !m_pServerWas->bRunning);
	ui.btnServerStop->setEnabled(bMayChange && bInstalled && m_pServerWas->bRunning);

	OnUserSelectionChanged();

	QString State;
	if (bInstalled)
	{
		State = m_pServerWas->bRunning
			? tr("The server is installed and running on port %1.").arg(m_pServerWas->Port)
			: tr("The server is installed but not running.");
	}
	else
		State = tr("No server is installed on this machine.");

	//
	// Where the settings go, said plainly. A server started by hand reads the
	// same file, and somebody looking at this page is exactly the person who
	// wants to know that - and where to edit it when there is no dialog to hand.
	//
	State += " " + tr("Settings are kept in %1 and are read by a server started by hand as well.")
		.arg(QDir::toNativeSeparators(CServerSetup::ConfigFilePath()));

	//
	// Said before the attempt rather than after it fails. Whether this can
	// change anything is knowable now, and finding out by pressing OK and
	// getting a refusal is a worse way to learn it.
	//
	if (!bMayChange)
	{
#ifdef WIN32
		State += " " + tr("Changing it needs administrator rights; start TaskExplorer as an administrator.");
#else
		State += " " + tr("Changing it needs root; start TaskExplorer as root.");
#endif
	}

	ui.lblServerState->setText(State);
}

//
// Starting and stopping, which are not configuration changes.
//
// Neither writes anything: they act on what is installed and then re-read the
// state, so the buttons and the line above them agree with the service manager
// rather than with what was just asked for.
//
void CSettingsWindow::OnStartServer()
{
	STATUS Status = CServerSetup::StartServer();
	if (Status.IsError())
		QMessageBox::warning(this, "TaskExplorer", CTaskExplorer::FormatError(Status));
	LoadServerSetup();
}

void CSettingsWindow::OnStopServer()
{
	STATUS Status = CServerSetup::StopServer();
	if (Status.IsError())
		QMessageBox::warning(this, "TaskExplorer", CTaskExplorer::FormatError(Status));
	LoadServerSetup();
}

void CSettingsWindow::OnServerToggled()
{
	UpdateServerState();
	OnChange();
}

//
// Shows the key this machine is using, for somebody who is entitled to see it.
//
// Which, by the time this can be pressed, they are: the page is disabled
// outright without administrator rights, and the file it comes from is in a
// directory only administrators can read. ReadTransportKey checks again anyway,
// so the refusal is the one that was asked about rather than a file error.
//
// It is worth having because the key is deliberately write-only everywhere
// else - never filled into the field, never printed, shown once by Generate and
// then not again. That is right for a secret and wrong for the moment somebody
// has to tell a viewer on another machine what to type, which until now meant
// opening the configuration file by hand or generating a new key and
// reconfiguring every viewer that already had the old one.
//
void CSettingsWindow::OnShowServerKey()
{
	if (!ui.btnServerShow->isChecked())
	{
		//
		// Hidden again means gone, not merely dotted out. Leaving the real key
		// in the field would leave it one Ctrl+A away from anybody who walked
		// past afterwards - and would leave apply() reading it as a value that
		// had been typed.
		//
		if (ui.txtServerKey->text() == m_ShownServerKey)
			ui.txtServerKey->clear();
		m_ShownServerKey.clear();
		ui.txtServerKey->setEchoMode(QLineEdit::Password);
		ui.btnServerShow->setText(tr("Show"));
		return;
	}

	//
	// Not shown over the top of something half-typed: that would throw away an
	// edit in progress, and the thing on screen would no longer be what the
	// button says it is.
	//
	if (!ui.txtServerKey->text().isEmpty())
	{
		QMessageBox::information(this, "TaskExplorer",
			tr("Clear the key field first - it holds something that has not been saved yet."));
		ui.btnServerShow->setChecked(false);
		return;
	}

	QString Key;
	if (!CServerSetup::ReadTransportKey(&Key))
	{
		QMessageBox::information(this, "TaskExplorer",
			m_pServerWas && m_pServerWas->bHasPsk
				? tr("The key could not be read.")
				: tr("This machine has no transport key yet. Press Generate to make one."));
		ui.btnServerShow->setChecked(false);
		return;
	}

	m_ShownServerKey = Key;
	ui.txtServerKey->setText(Key);
	ui.txtServerKey->setEchoMode(QLineEdit::Normal);
	ui.btnServerShow->setText(tr("Hide"));
}

void CSettingsWindow::OnGenerateServerKey()
{
	//
	// A generated key is a new one, so it is not what Show revealed - clearing
	// this is what makes apply() treat it as the change it is.
	//
	m_ShownServerKey.clear();
	ui.btnServerShow->setChecked(false);
	ui.btnServerShow->setText(tr("Show"));
	ui.txtServerKey->setText(CServerSetup::GenerateTransportKey());

	//
	// Shown, once, because this is the only moment anybody could read it: it
	// goes into a file only administrators can open, and every viewer that is to
	// reach this machine has to be told it by hand.
	//
	ui.txtServerKey->setEchoMode(QLineEdit::Normal);
	ui.txtServerKey->setToolTip(tr("Write this down - every viewer needs it, and it is not shown again."));

	OnChange();
}

//
// ---- why there is no unprivileged path here any more ----
//
// There was one: the dialog wrote the key to a file only this user could read,
// asked an elevated TaskConsole to adopt it, and waited. It existed so that a
// key never travelled on a command line, where every process list on the
// machine could read it.
//
// Both of its reasons are gone. The page is disabled outright without
// administrator rights - see UpdateServerState - so nothing can be typed to
// hand over; and the thing it handed over does not exist, because there is no
// key file: the transport secret and the salted password hashes are groups in
// the server's configuration file, which only administrators can write.
//
// Kept as a note rather than as code, because the shape of the problem will
// come back if this page is ever offered to a non-administrator again, and the
// answer to it - a file the user already owns, never an argument - is the part
// worth remembering.
//
//
// ---- the certificate, in words ----
//
// The numbers come from TaskCommon/Support.h and are produced by code that runs
// in a service and in a module; the sentences are this window's, because this
// window is the only place with a person reading them.
//
QString GetCertStatusText(ECertStatus Status)
{
	switch (Status)
	{
	case eCertOk:			return CSettingsWindow::tr("The supporter certificate is valid.");
	case eCertNotFound:		return CSettingsWindow::tr("No supporter certificate was found. Watching another machine, "
													   "and serving this one to a viewer elsewhere, are supporter "
													   "features; the certificate belongs in Certificate.dat beside "
													   "the program.");
	case eCertUnreadable:	return CSettingsWindow::tr("The supporter certificate could not be read.");
	case eCertMalformed:	return CSettingsWindow::tr("The supporter certificate is not in the expected form.");
	case eCertNoSignature:	return CSettingsWindow::tr("The supporter certificate carries no signature.");
	case eCertBadSignature:	return CSettingsWindow::tr("The supporter certificate's signature does not match its contents.");
	case eCertWrongSoftware:return CSettingsWindow::tr("This supporter certificate was issued for another program.");
	case eCertWrongMachine:	return CSettingsWindow::tr("This supporter certificate belongs to another machine.");
	case eCertExpired:		return CSettingsWindow::tr("The supporter certificate has expired.");
	case eCertNoCrypto:		return CSettingsWindow::tr("This installation cannot check a signature, so the supporter "
													   "certificate could not be verified.");
	}
	return CSettingsWindow::tr("The supporter certificate could not be verified.");
}

QString GetCertTypeName(const SCertInfo& Info)
{
	if (!Info.active && !Info.expired)
		return CSettingsWindow::tr("None");

	switch (Info.type)
	{
	case eCertContributor:	return CSettingsWindow::tr("Contributor");
	case eCertEternal:		return CSettingsWindow::tr("Eternal");
	case eCertBusiness:		return CSettingsWindow::tr("Business");
	case eCertPersonal:		return CSettingsWindow::tr("Personal");
	case eCertHome:			return CSettingsWindow::tr("Home");
	case eCertFamily:		return CSettingsWindow::tr("Family");
	case eCertDeveloper:	return CSettingsWindow::tr("Developer");
	case eCertPatreon:		return CSettingsWindow::tr("Patreon");
	case eCertGreatPatreon:	return CSettingsWindow::tr("Great Patreon");
	case eCertEntryPatreon:	return CSettingsWindow::tr("Entry Patreon");
	case eCertEvaluation:	return CSettingsWindow::tr("Evaluation");
	}
	return CSettingsWindow::tr("Unknown");
}

QString GetCertLevelName(const SCertInfo& Info)
{
	switch (Info.level)
	{
	case eCertStandard:
	case eCertStandard2:	return CSettingsWindow::tr("Standard");
	case eCertAdvanced1:
	case eCertAdvanced:		return CSettingsWindow::tr("Advanced");
	case eCertMaxLevel:		return CSettingsWindow::tr("Maximum");
	}
	return CSettingsWindow::tr("None");
}

void CSettingsWindow::ApplyServerSetup()
{
	if (!m_pServerWas)
		return;

	SServerSetup Want;

	//
	// What the instance is called. Empty means the default rather than a server
	// with no name, because an empty endpoint name is not a thing that can be
	// listened on and a blank field should mean "the usual one".
	//
	Want.Name = ui.txtServerName->text().trimmed();
	if (Want.Name.isEmpty())
		Want.Name = MY_DAEMON_NAME_STRING;

	Want.Port = (quint16)ui.spinListenPort->value();
	Want.Bind = ui.cmbBindAddress->currentIndex() == 0
		? QString() : ui.cmbBindAddress->currentText().trimmed();
	Want.bAllUsers = m_pServerWas->bInstalled ? m_pServerWas->bAllUsers : true;
	Want.bLocalPipe = ui.chkLocalPipe->isChecked();
	Want.bUseDriver = ui.chkServerDriver->isChecked();
	Want.bAnnounce = ui.chkAnnounce->isChecked();
	Want.AnnounceInterval = ui.spinAnnounceEvery->value();
	Want.DiscoveryPort = (quint16)ui.spinDiscoveryPort->value();

	//
	// Carried rather than defaulted: Want starts as a fresh SServerSetup, so
	// anything this page does not show would be written back as whatever the
	// struct's initialiser says. These two are not on the page - they are
	// deliberate, rarely changed and edited in the file - and applying an
	// unrelated change here must not quietly turn either of them off.
	//
	Want.bProcessBlocking = m_pServerWas->bProcessBlocking;
	Want.bLog = m_pServerWas->bLog;

	//
	// Taken as typed. Empty means "leave whatever is stored alone", which is what
	// lets the port be changed by somebody who does not have the transport secret
	// to hand.
	//
	// And a key that is on screen only because Show put it there is not something
	// that was typed. Treating it as one would make looking at the key a change,
	// and a change reinstalls the service - so every viewer watching this machine
	// would drop because somebody wanted to read a value off it.
	//
	Want.Psk = ui.txtServerKey->text().trimmed();
	if (!m_ShownServerKey.isEmpty() && Want.Psk == m_ShownServerKey)
		Want.Psk.clear();

	const bool bOn = ui.chkServer->isChecked();

	//
	// Three separable questions, because they now have separable answers: what
	// this machine is configured to serve, what key it serves with, and whether
	// a service is installed to do it. The settings outlive the service - they
	// are what a server started by hand reads too - so they are saved whether or
	// not the checkbox is ticked.
	//
	const bool bNameChanged = Want.Name.compare(m_pServerWas->Name, Qt::CaseInsensitive) != 0;

	const bool bConfigChanged =
		   bNameChanged
		|| Want.Port != m_pServerWas->Port
		|| Want.Bind != m_pServerWas->Bind
		|| Want.bLocalPipe != m_pServerWas->bLocalPipe
		|| Want.bUseDriver != m_pServerWas->bUseDriver
		|| Want.bAnnounce != m_pServerWas->bAnnounce
		|| Want.AnnounceInterval != m_pServerWas->AnnounceInterval
		|| Want.DiscoveryPort != m_pServerWas->DiscoveryPort;
	const bool bKeyChanged = !Want.Psk.isEmpty();
	const bool bInstallChanged = bOn != m_pServerWas->bInstalled;

	//
	// Nothing asked for, nothing done. Reinstalling an unchanged service would
	// stop and start it, and every viewer watching this machine would see it
	// drop for no reason anyone could point at.
	//
	if (!bConfigChanged && !bKeyChanged && !bInstallChanged)
		return;

	//
	// A server that is going to listen on the network needs a transport secret,
	// and it is not generated for them: a secret nobody was shown is a secret no
	// viewer can be told, and the server would come up unreachable.
	//
	//
	// The same refusal the server makes on startup, made before it is installed:
	// no local endpoint and no network port is a server nobody can reach, and
	// finding that out from a service that starts and then answers nothing is a
	// worse way to learn it.
	//
	if (!Want.bLocalPipe && Want.Port == 0)
	{
		QMessageBox::warning(this, "TaskExplorer",
			tr("With the local pipe switched off and no network port set, nothing "
			   "could reach this server."));
		return;
	}

	if (bOn && !m_pServerWas->bHasPsk && Want.Psk.isEmpty())
	{
		QMessageBox::warning(this, "TaskExplorer",
			tr("The server needs a transport key. Press Generate, and write down what appears."));
		return;
	}

	//
	// Privileged only: the page is disabled otherwise, so getting here without
	// rights would mean the enable rule and this disagreed. Checked anyway,
	// because a dialog that can be reached by any other route than the one it
	// was designed for should refuse rather than half-work.
	//
	//
	// The viewer keeps its own copy of the name.
	//
	// It is the one thing on this page the viewer itself needs: what to connect
	// to on startup, and which service the Remote Machines page is talking
	// about. Reading the server's configuration for it would mean an
	// unprivileged viewer reading a file it may not be allowed to open, on
	// every start, to answer a question it asked once.
	//
	// Written whatever happens below, because it describes what this machine's
	// daemon is called rather than whether installing it worked.
	//
	theConf->SetValue("Options/LocalDaemon", Want.Name);

	STATUS Status;
	if (!CServerSetup::IsPrivileged())
		Status = ERR(TE_ServerSetupNeedsAdmin);
	else if (bOn)
	{
		//
		// A renamed instance is a differently named service, so the one the old
		// name made has to go before the new one is installed - otherwise the
		// machine ends up running two, and the one nobody can see any more is
		// the one still holding the endpoint.
		//
		// By its old name explicitly: the configuration written below already
		// says the new one.
		//
		if (bNameChanged && m_pServerWas->bInstalled)
		{
			const QString WasCalled = CServerSetup::ServiceNameFor(m_pServerWas->Name);
			if (WasCalled != CServerSetup::ServiceNameFor(Want.Name))
				CServerSetup::Remove(WasCalled);
		}

		//
		// Install() writes the configuration itself, then points a service at it.
		//
		Status = CServerSetup::Install(Want);
	}
	else
	{
		//
		// No service wanted - but the settings are still this machine's, and a
		// server started from a console will read them. Written first, so that
		// removing a service does not also throw away the description of what it
		// was doing.
		//
		Status = CServerSetup::WriteConfig(Want);
		if (!Status.IsError() && m_pServerWas->bInstalled)
			Status = CServerSetup::Remove();
	}
	if (Status.IsError())
	{
		//
		// A refusal at the authentication prompt is an answer, not a fault.
		//
		if (Status.GetMsgCode() != TE_UserCanceled)
			CTaskExplorer::CheckErrors(QList<STATUS>() << Status);
	}
	else if (bOn && !Want.Psk.isEmpty())
	{
		QMessageBox::information(this, "TaskExplorer",
			tr("The server is set up.\n\nViewers on other machines connect to %1:%2 "
			   "with the transport key you just set, and then log in as one of the "
			   "users listed here. The key is not shown again.")
				.arg(Want.Bind.isEmpty() ? QHostInfo::localHostName() : Want.Bind)
				.arg(Want.Port));
	}

	//
	// Re-read rather than assumed: what is installed now is the only thing the
	// next apply() should compare against, and a service that started and
	// stopped again is not what was asked for even though nothing failed.
	//
	LoadServerSetup();
}

//
// ---- the saved connection keys ----
//
// Two controls and a sentence. Everything else about the store happens where
// the keys are used - see CConnectDialog - because a settings page is where
// people go to change their mind, not where they go to type a key.
//

//
// The machines this viewer knows about, as the cluster has them.
//
// Read from the cluster rather than kept here, and re-read after every change,
// so the page cannot drift from what is actually saved. Discovered machines are
// listed too - they are real, reachable and worth editing - but they say so,
// because editing one is what turns it into a saved entry.
//
void CSettingsWindow::LoadMachines()
{
	ui.treeMachines->clear();

	if (!theCluster)
	{
		OnMachineSelectionChanged();
		return;
	}

	CCredentialStore* pStore = CCredentialStore::Instance();

	foreach(const STarget& Target, theCluster->GetTargets())
	{
		//
		// Not this machine's own daemon: it is found at startup rather than
		// configured, has no credentials, and removing it would mean nothing.
		//
		if (Target.bLocalDaemon)
			continue;

		QTreeWidgetItem* pItem = new QTreeWidgetItem();
		pItem->setText(0, Target.Name);
		pItem->setText(1, Target.Address);

		//
		// Whether something is saved, never what. The store is unlocked at this
		// point more often than not, and a column that quietly held a password
		// would be one screenshot away from publishing it.
		//
		QString Creds;
		if (Target.State == STarget::eDiscovered)
			Creds = tr("found on the network");
		else if (!pStore->IsUnlocked())
			Creds = tr("locked");
		else
			Creds = pStore->Get(Target.Name, NULL) ? tr("saved") : tr("not saved");
		pItem->setText(2, Creds);

		pItem->setData(0, Qt::UserRole, Target.Name);
		ui.treeMachines->addTopLevelItem(pItem);
	}

	for (int i = 0; i < 3; i++)
		ui.treeMachines->resizeColumnToContents(i);

	OnMachineSelectionChanged();
}

void CSettingsWindow::OnMachineSelectionChanged()
{
	const bool bOne = ui.treeMachines->selectedItems().count() == 1;
	ui.btnMachineEdit->setEnabled(bOne);
	ui.btnMachineRemove->setEnabled(bOne);
}

//
// Changes a machine, and does not connect or disconnect anything.
//
// Written through immediately, like the server's user list and for the same
// reason: what it changes is a stored password, and holding one in a dialog
// until somebody presses OK is how it gets lost when they close the window
// instead.
//
void CSettingsWindow::OnEditMachine()
{
	QList<QTreeWidgetItem*> Selected = ui.treeMachines->selectedItems();
	if (Selected.count() != 1)
		return;

	if (CConnectDialog::Edit(Selected[0]->data(0, Qt::UserRole).toString(), this))
		LoadMachines();
}

void CSettingsWindow::OnRemoveMachine()
{
	QList<QTreeWidgetItem*> Selected = ui.treeMachines->selectedItems();
	if (Selected.count() != 1)
		return;

	const QString Name = Selected[0]->data(0, Qt::UserRole).toString();

	//
	// Asked, because a connected machine is disconnected by this - the entry and
	// the connection are the same thing to CCluster - and because the saved
	// credentials go with it.
	//
	if (QMessageBox::question(this, "TaskExplorer",
			tr("Remove \"%1\"? It is disconnected if connected, and its saved "
			   "credentials are forgotten.").arg(Name),
			QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
		return;

	theCluster->RemoveTarget(Name);

	CCredentialStore* pStore = CCredentialStore::Instance();
	if (pStore->IsUnlocked())
		pStore->Remove(Name);

	LoadMachines();
	UpdateSavedKeys();
}

void CSettingsWindow::UpdateSavedKeys()
{
	CCredentialStore* pStore = CCredentialStore::Instance();

	QString Why;
	if (!pStore->IsAvailable(&Why))
	{
		ui.lblSavedState->setText(tr("Keys cannot be saved on this machine: %1").arg(Why));
		ui.btnForgetKeys->setEnabled(false);
		ui.chkRememberPassword->setEnabled(false);
		return;
	}

	if (!pStore->Exists())
	{
		ui.lblSavedState->setText(tr("No keys are saved yet."));
		ui.btnForgetKeys->setEnabled(false);
		ui.chkRememberPassword->setEnabled(false);
		ui.chkRememberPassword->setChecked(false);
		return;
	}

	//
	// Opened without asking if it can be, so that the count and the checkbox are
	// right for the common case. A locked store still shows honestly rather than
	// raising a prompt nobody asked for by opening a settings page.
	//
	pStore->TryUnlock();

	ui.btnForgetKeys->setEnabled(true);
	ui.chkRememberPassword->setEnabled(CCrypto::PlatformSecretAvailable());
	ui.chkRememberPassword->setChecked(pStore->HasPlatformUnlock());

	if (pStore->IsUnlocked())
	{
		const int Count = pStore->Targets().count();
		ui.lblSavedState->setText(Count == 1
			? tr("One machine\'s key is saved.")
			: tr("%1 machines\' keys are saved.").arg(Count));
	}
	else
		ui.lblSavedState->setText(tr("Keys are saved, and locked."));
}

void CSettingsWindow::OnForgetKeys()
{
	//
	// Asked for confirmation because it cannot be undone and because the keys
	// may be the only copy - the machine at the other end will not tell you its
	// key back.
	//
	if (QMessageBox::question(this, "TaskExplorer",
			tr("Delete every saved key? They cannot be recovered, and each machine "
			   "will have to be given its key again."),
			QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
		return;

	STATUS Status = CCredentialStore::Instance()->Forget();
	if (Status.IsError())
		CTaskExplorer::CheckErrors(QList<STATUS>() << Status);

	UpdateSavedKeys();
}

void CSettingsWindow::OnRememberPassword()
{
	CCredentialStore* pStore = CCredentialStore::Instance();
	const bool bWanted = ui.chkRememberPassword->isChecked();

	//
	// Turning it *on* needs the master key, which needs the store open - so the
	// password is asked for here, once, and that is the last time. Turning it
	// off needs nothing: it only discards a wrapping.
	//
	if (bWanted && !pStore->IsUnlocked() && !CUnlockDialog::Open(this))
	{
		ui.chkRememberPassword->setChecked(false);
		return;
	}

	STATUS Status = pStore->SetPlatformUnlock(bWanted);
	if (Status.IsError())
		CTaskExplorer::CheckErrors(QList<STATUS>() << Status);

	UpdateSavedKeys();
}

void CSettingsWindow::OnDiscoveryToggled()
{
	//
	// The interval only means anything while something is looking.
	//
	ui.lblDiscoverEvery->setEnabled(ui.chkDiscover->isChecked());
	ui.spinDiscoverEvery->setEnabled(ui.chkDiscover->isChecked());
	OnChange();
}

//
// Moves a file, letting the shell ask for administrator rights if it needs to.
//
// Certificate.dat lives beside the executable, which on an installed copy is a
// directory an ordinary user cannot write. Rather than have the viewer restart
// itself elevated for one file, the file is written where it can be written and
// then handed to the shell's copy engine, which is the thing that knows how to
// put up the "you need administrator permission" prompt and carry on afterwards.
//
// The double null terminators are not a mistake: SHFILEOPSTRUCT takes lists of
// paths and a list ends with an empty one.
//
// Off Windows there is no such prompt and no need for one - the daemon's
// configuration is already root-owned and installing is a package manager's
// job - so it is a plain rename, and failing means the caller has to say so.
//
static bool MoveFileWithPrompt(const QString& From, const QString& To)
{
#ifdef WIN32
	std::wstring From_ = QDir::toNativeSeparators(From).toStdWString();
	From_.append(L"\0", 1);
	std::wstring To_ = QDir::toNativeSeparators(To).toStdWString();
	To_.append(L"\0", 1);

	SHFILEOPSTRUCTW Op;
	memset(&Op, 0, sizeof(Op));
	Op.hwnd = NULL;
	Op.wFunc = FO_MOVE;
	Op.pFrom = From_.c_str();
	Op.pTo = To_.c_str();
	Op.fFlags = FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR;

	return SHFileOperationW(&Op) == 0 && !Op.fAnyOperationsAborted;
#else
	QFile::remove(To);
	return QFile::rename(From, To);
#endif
}

//
// How many days a free evaluation runs, and how many one machine may ask for.
//
// Both are for this page only - the issuer enforces its own limits and is the
// one that counts. They are here so that what the page says matches what
// happens, not so that it decides anything.
//
#define EVAL_DAYS	90
#define EVAL_MAX	3

//
// ---- the supporter certificate ----
//
// The page itself is in the .ui file, laid out as MajorPrivacy's License page.
// What is here is what it does: the two texts that are not static, the state
// the module reports, and writing a certificate to a directory this process
// usually may not write.
//

void CSettingsWindow::InitCertificate()
{
	ui.lblVersion->setText(tr("TaskExplorer version: %1").arg(COnlineUpdater::GetCurrentVersion()));
	ui.chkNoCheck->setChecked(theConf->GetBool("Options/NoSupportCheck", false));

	connect(ui.txtCertificate, SIGNAL(textChanged()), this, SLOT(OnCertChanged()));
	ui.txtCertificate->installEventFilter(this);
	connect(ui.txtSerial, SIGNAL(textChanged(const QString&)), this, SLOT(OnSerialChanged()));
	connect(ui.btnGetCert, SIGNAL(clicked(bool)), this, SLOT(OnGetCert()));
	connect(ui.lblEvalCert, SIGNAL(linkActivated(const QString&)), this, SLOT(OnStartEval()));
	connect(ui.chkNoCheck, &QCheckBox::toggled, this, [](bool bChecked) {
		theConf->SetValue("Options/NoSupportCheck", bChecked); });

	//
	// The hardware id, revealed on request rather than shown.
	//
	// It identifies the machine and a node-locked certificate is issued against
	// it, so it has to be obtainable - but it does not have to sit on screen
	// while somebody is showing their settings to a forum.
	//
	const QString Hwid = CRemoteLoader::CertificateHwid();
	if (Hwid.isEmpty())
		ui.lblHwId->setText(tr("HwId: <i>not readable here</i>"));
	else
	{
		ui.lblHwId->setText(tr("HwId: <a href=\"show\">[click to reveal]</a>"));
		ui.lblHwId->setToolTip(tr("Click to reveal"));
		connect(ui.lblHwId, &QLabel::linkActivated, this, [this, Hwid](const QString& Link) {
			if (Link == "show") {
				ui.lblHwId->setText(tr("HwId: <a href=\"hide\" style=\"text-decoration:none; color:inherit;\">%1</a> "
									"<a href=\"copy\">(copy)</a>").arg(Hwid));
				ui.lblHwId->setToolTip(tr("Click to hide"));
			}
			else if (Link == "hide") {
				ui.lblHwId->setText(tr("HwId: <a href=\"show\">[click to reveal]</a>"));
				ui.lblHwId->setToolTip(tr("Click to reveal"));
			}
			else if (Link == "copy")
				QApplication::clipboard()->setText(Hwid);
		});
	}

	QFile File(CRemoteLoader::CertificateFile());
	if (File.open(QFile::ReadOnly)) {
		m_Certificate = File.readAll();
		File.close();
	}

	UpdateCertState();
}

//
// What is shown instead of the certificate: the machine id and the update key
// cut off, and the name hidden as well.
//
// The same three lines MajorPrivacy does it in, and for the same reason. It is
// the person's own file and none of this is secret, but a settings page is a
// thing people photograph and put in a forum post - and the two lines that
// identify a machine and authorise a renewal, plus the name of whoever it was
// issued to, are the parts of it that are about a person rather than about
// software.
//
static QString Abbreviate(const QByteArray& Certificate)
{
	int Pos = Certificate.indexOf("HWID:");
	if (Pos == -1)
		Pos = Certificate.indexOf("UPDATEKEY:");

	QString Text = Pos == -1 ? QString::fromUtf8(Certificate)
	                         : QString::fromUtf8(Certificate.left(Pos)) + "...";

	//
	// Only when the name comes before the date, which is the order every
	// certificate has - and if one ever does not, the whole of it is shown
	// rather than a piece cut out of the middle by an offset that meant
	// something else.
	//
	const int NamePos = Text.indexOf("NAME:");
	const int DatePos = Text.indexOf("DATE:");
	if (NamePos != -1 && DatePos != -1 && DatePos > NamePos)
		Text = Text.mid(0, NamePos + 5) + " ...\n" + Text.mid(DatePos);

	return Text;
}

void CSettingsWindow::UpdateCertState()
{
	//
	// Re-read rather than trusted: this runs right after the file has been
	// written, and the whole point is to show what the *file* now says.
	//
	//
	// From the module, not from a second reading here. It is the thing that
	// refuses, so it is the thing whose answer is worth showing - and with the
	// implementation out of this executable there is no second reader to
	// disagree with it.
	//
	const ECertStatus Status = (ECertStatus)CRemoteLoader::CertificateStatus(true);
	SCertInfo Info;
	Info.State = CRemoteLoader::CertificateState();

	m_bCertChanged = false;

	//
	// Only when there is something to shorten. With no certificate the text
	// area is empty and there is nothing hidden about it - saying otherwise is
	// what made a pasted first certificate go nowhere: Apply took the flag to
	// mean "the text area is not showing what the person typed" and returned
	// without writing.
	//
	m_bCertHidden = !m_Certificate.isEmpty();

	ui.txtCertificate->blockSignals(true);
	ui.txtCertificate->setPlainText(m_Certificate.isEmpty() ? QString() : Abbreviate(m_Certificate));
	ui.txtCertificate->blockSignals(false);

	const QString RenewUrl = CERT_IS_TYPE(Info, eCertPatreon)
		? "https://xanasoft.com/get-supporter-certificate/"
		: "https://xanasoft.com/go.php?to=renew-cert";

	//
	// The colour of the box says the answer before anything is read: green for
	// a certificate that works, yellow for one that has run out, red for one
	// that is there and is not ours, and the palette left alone when there is
	// none at all.
	//
	QPalette Palette = QApplication::palette();
	ui.lblCertExp->setVisible(false);

	if (!m_Certificate.isEmpty())
	{
		Palette.setColor(QPalette::Text, Qt::black);

		if (Status == eCertOk && !Info.expired)
		{
			Palette.setColor(QPalette::Base, QColor(192, 255, 192));

			if (Info.expirers_in_sec > 0 && Info.expirers_in_sec < (60 * 60 * 24 * 30))
			{
				ui.lblCertExp->setText(tr("This certificate will <font color='red'>expire in %1 days</font>, "
									   "please <a href=\"%2\">obtain a new one</a>.")
					.arg(Info.expirers_in_sec / (60 * 60 * 24)).arg(RenewUrl));
				ui.lblCertExp->setVisible(true);
			}
		}
		else if (Info.expired)
		{
			Palette.setColor(QPalette::Base, QColor(255, 255, 192));

			QString Message = tr("This certificate has expired, please <a href=\"%1\">obtain a new one</a>.")
				.arg(RenewUrl);
			if (Info.active && Info.grace_period)
				Message += tr("<br /><font color='red'>Supporter features will stop working in %1 days.</font>")
					.arg((Info.expirers_in_sec + 30 * 60 * 60 * 24) / (60 * 60 * 24));
			else if (!Info.active)
				Message += tr("<br /><font color='red'>Supporter features are no longer enabled.</font>");
			ui.lblCertExp->setText(Message);
			ui.lblCertExp->setVisible(true);
		}
		else
		{
			//
			// Present and not usable for a reason that is not time: forged, for
			// another program, for another machine, or unreadable.
			//
			Palette.setColor(QPalette::Base, QColor(255, 224, 224));
			ui.lblCertExp->setText(tr("<font color='red'>%1</font>").arg(GetCertStatusText(Status)));
			ui.lblCertExp->setVisible(true);
		}
	}
	ui.txtCertificate->setPalette(Palette);

	//
	// The evaluation offer, only while there is nothing at all. The count is
	// this side's memory of how many have been asked for; the issuer keeps its
	// own and is the one that decides.
	//
	ui.lblEvalCert->setVisible(m_Certificate.isEmpty());
	if (m_Certificate.isEmpty())
	{
		const int EvalCount = theConf->GetInt("Options/EvalCount", 0);
		if (EvalCount >= EVAL_MAX)
			ui.lblEvalCert->setText(tr("<b>You have used %1 of %2 evaluation certificates. "
									"No more can be issued for this machine.</b>").arg(EvalCount).arg(EVAL_MAX));
		else
			ui.lblEvalCert->setText(tr("<b><a href=\"_\">Get a free evaluation certificate</a> and use the supporter "
									"features for %1 days.</b>").arg(EVAL_DAYS));
		ui.lblEvalCert->setToolTip(tr("A free %1-day evaluation certificate can be requested up to %2 times "
								   "for each hardware ID.").arg(EVAL_DAYS).arg(EVAL_MAX));
	}

	//
	// The small print.
	//
	QString CertInfo;
	if (Info.active || Info.expired)
	{
		QStringList Parts;
		if (!CRemoteLoader::CertificateName().isEmpty())
			Parts += tr("Issued to: %1").arg(CRemoteLoader::CertificateName());
		Parts += tr("Type: %1").arg(GetCertTypeName(Info));
		if (Info.expirers_in_sec > 0)
			Parts += tr("Expires in: %1 days").arg(Info.expirers_in_sec / (60 * 60 * 24));
		else if (Info.expirers_in_sec < 0)
			Parts += tr("Expired: %1 days ago").arg(-Info.expirers_in_sec / (60 * 60 * 24));
		if (CERT_IS_TYPE(Info, eCertPatreon))
			Parts += tr("eligible Patreons can always <a href=\"https://xanasoft.com/get-supporter-certificate/\">"
						"obtain an updated certificate</a>");
		CertInfo = Parts.join("; ");
	}
	ui.lblCert->setText(CertInfo);

	QStringList Options;
	if (Info.active)
	{
		Options += tr("Feature level: %1").arg(GetCertLevelName(Info));
		if (Info.locked)
			Options += tr("bound to this machine");
	}

	//
	// With no module there is nobody to ask, and nothing that would act on a
	// certificate anyway - which is worth saying here, because it looks exactly
	// like the certificate not working.
	//
	if (!CRemoteLoader::IsAvailable())
		Options += tr("<font color='red'>%1</font>").arg(CRemoteLoader::GetError());

	ui.lblCertOpt->setText(Options.join("; "));
}

bool CSettingsWindow::eventFilter(QObject* pSource, QEvent* pEvent)
{
	if (pSource == ui.txtCertificate)
	{
		if (pEvent->type() == QEvent::FocusIn && m_bCertHidden)
		{
			m_bCertHidden = false;
			ui.txtCertificate->blockSignals(true);
			ui.txtCertificate->setPlainText(QString::fromUtf8(m_Certificate));
			ui.txtCertificate->blockSignals(false);
		}
		else if (pEvent->type() == QEvent::FocusOut && !m_bCertHidden && !m_bCertChanged
			  && !m_Certificate.isEmpty())
		{
			m_bCertHidden = true;
			ui.txtCertificate->blockSignals(true);
			ui.txtCertificate->setPlainText(Abbreviate(m_Certificate));
			ui.txtCertificate->blockSignals(false);
		}
	}
	return QMainWindow::eventFilter(pSource, pEvent);
}

void CSettingsWindow::OnCertChanged()
{
	m_bCertChanged = true;

	//
	// Back to the ordinary colour while it is being edited: the green of the
	// certificate that was there says nothing about the one being typed.
	//
	ui.txtCertificate->setPalette(QApplication::palette());
	ui.lblCertExp->setVisible(false);
}

void CSettingsWindow::OnSerialChanged()
{
	ui.btnGetCert->setEnabled(ui.txtSerial->text().trimmed().length() > 5);
}

void CSettingsWindow::OnGetCert()
{
	const QString Serial = ui.txtSerial->text().trimmed();

	QVariantMap Params;

	//
	// The update key out of the certificate already held, when there is one.
	// It is what tells the issuer that a renewal belongs to the same person as
	// the certificate being renewed.
	//
	const QByteArray Held = m_bCertHidden ? m_Certificate : ui.txtCertificate->toPlainText().toUtf8();
	foreach(const QByteArray& Line, Held.split('\n'))
	{
		const int Colon = Line.indexOf(':');
		if (Colon > 0 && Line.left(Colon).trimmed().toUpper() == "UPDATEKEY")
			Params["key"] = QString::fromUtf8(Line.mid(Colon + 1)).trimmed();
	}

	CProgressDialogPtr pProgress = CProgressDialogPtr(new CProgressDialog(tr("Retrieving certificate..."), this));
	theGUI->GetOnlineUpdater()->GetSupportCert(Serial, this,
		SLOT(OnCertData(const QByteArray&, const QVariantMap&)), Params, pProgress);
	pProgress->exec();
}

//
// The free evaluation.
//
// It is issued to a person and locked to a machine, so the issuer needs an
// address to send it to and the hardware id - which is why this asks for
// anything at all rather than being a button.
//
void CSettingsWindow::OnStartEval()
{
	const QString Name = theConf->GetString("Options/UserName", QString::fromLocal8Bit(qgetenv("USERNAME")));

	bool bOk = false;
	const QString eMail = QInputDialog::getText(this, tr("TaskExplorer - evaluation certificate"),
		tr("Please enter your email address to receive a free %1-day evaluation certificate.\n"
		   "It will be issued to %2 and locked to this machine.\n\n"
		   "Up to %3 evaluation certificates can be requested for each hardware ID.")
			.arg(EVAL_DAYS).arg(Name).arg(EVAL_MAX),
		QLineEdit::Normal, theConf->GetString("Options/UserEMail"), &bOk);

	if (!bOk || eMail.isEmpty())
		return;

	theConf->SetValue("Options/UserEMail", eMail);

	QVariantMap Params;
	Params["Name"] = Name;
	Params["eMail"] = eMail;
	Params["eval"] = true;

	CProgressDialogPtr pProgress = CProgressDialogPtr(new CProgressDialog(tr("Retrieving certificate..."), this));
	theGUI->GetOnlineUpdater()->GetSupportCert("", this,
		SLOT(OnCertData(const QByteArray&, const QVariantMap&)), Params, pProgress);
	pProgress->exec();
}

void CSettingsWindow::OnCertData(const QByteArray& Certificate, const QVariantMap& Params)
{
	if (Certificate.isEmpty())
	{
		const QString Error = Params["error"].toString();

		//
		// The issuer says when somebody has had their share of evaluations, and
		// it is the one that counts - this side only remembers so that the page
		// can stop offering.
		//
		if (Error.contains("max eval", Qt::CaseInsensitive))
			theConf->SetValue("Options/EvalCount", EVAL_MAX);

		UpdateCertState();

		QMessageBox::critical(this, "TaskExplorer",
			tr("The certificate could not be retrieved: %1")
				.arg(Error.isEmpty() ? tr("no reason was given, which usually means a network problem") : Error));
		return;
	}

	if (Params["eval"].toBool())
		theConf->SetValue("Options/EvalCount", theConf->GetInt("Options/EvalCount", 0) + 1);

	m_bCertHidden = false;
	ui.txtCertificate->setPlainText(QString::fromUtf8(Certificate));
	m_bCertChanged = true;

	//
	// Applied at once. A certificate that arrived from the issuer and then sat
	// in a text area waiting for a button is a support question, not a feature.
	//
	ApplyCertificate();
}

bool CSettingsWindow::ApplyCertificate()
{
	//
	// Nothing typed, nothing to write. The shortened form cannot be in the text
	// area here: it is replaced the moment the area takes focus, and nothing
	// else can have set m_bCertChanged.
	//
	if (!m_bCertChanged)
		return true;

	const QByteArray Certificate = ui.txtCertificate->toPlainText().toUtf8();

	//
	// Written beside the program, which is usually a place this process may not
	// write - so it goes to a temporary file first and is then moved by the
	// shell, which is what knows how to ask for administrator rights. See
	// MoveFileWithPrompt.
	//
	const QString Path = CRemoteLoader::CertificateFile();
	const QString Temp = QDir::tempPath() + "/TaskExplorer-Certificate.dat";

	QFile::remove(Temp);
	QFile File(Temp);
	if (!File.open(QFile::WriteOnly))
	{
		QMessageBox::critical(this, "TaskExplorer",
			tr("The certificate could not be written to %1").arg(QDir::toNativeSeparators(Temp)));
		return false;
	}
	File.write(Certificate);
	File.close();

	//
	// A plain rename first, because when the program is running from a place
	// its user can write - a build directory, a portable copy - there is no
	// reason to put a prompt in front of them.
	//
	bool bOk = false;
	if (QFileInfo(QFileInfo(Path).absolutePath()).isWritable())
	{
		QFile::remove(Path);
		bOk = QFile::rename(Temp, Path);
	}
	if (!bOk)
		bOk = MoveFileWithPrompt(Temp, Path);

	QFile::remove(Temp);

	if (!bOk)
	{
		QMessageBox::critical(this, "TaskExplorer",
			tr("The certificate could not be saved to %1.\n\n"
			   "It has to sit beside the program, where the service and the remote module "
			   "read it, and writing there needs administrator rights.")
				.arg(QDir::toNativeSeparators(Path)));
		return false;
	}

	m_Certificate = Certificate;
	UpdateCertState();

	//
	// And the toolbar, which carries the appeal to support this. A certificate
	// that has just been applied should take it away now rather than at the
	// next start - being asked to support something one has just paid for is
	// the small rudeness this is meant to avoid.
	//
	theGUI->UpdateLabel();

	//
	// Said out loud, because nothing else on this page changes when it works
	// and the two things that were unlocked are not on this screen.
	//
	if (SCertInfo{ CRemoteLoader::CertificateState(true) }.active)
	{
		QMessageBox::information(this, "TaskExplorer",
			tr("The certificate was saved.\n\n"
			   "A running TaskServer reads it when it starts, so restart the service for it "
			   "to take effect there."));
	}

	return true;
}
