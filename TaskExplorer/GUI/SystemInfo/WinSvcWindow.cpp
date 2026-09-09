/*
 * Task Explorer -
 *   qt port of the Extended Service Plugin
 *
 * Copyright (C) 2010-2015 wj32
 * Copyright (C) 2019 David Xanatos
 *
 * This file is part of Task Explorer and contains System Informer code.
 * 
 */

#include "stdafx.h"
#include "WinSvcWindow.h"
//
// Windows SDK only, for the SERVICE_* and SC_ACTION_* constants the API
// reports values from; phlib is not involved.
//
#include <windows.h>
#include <winsvc.h>
#include "../../API/SystemAPI.h"
#include "../../GUI/TaskExplorer.h"
#include "WinSvcTrigger.h"
#include "WinSvcShutdown.h"
#include "ServiceListWidget.h"
#include "../../MiscHelpers/Common/ComboInputDialog.h"
#include "../../SVC/TaskService.h"
#include "../TaskExplorer.h"

CWinSvcWindow::CWinSvcWindow(const CServicePtr& pService, QWidget *parent)
	: QMainWindow(parent)
{
	m_pService = pService;

	m_GeneralChanged = false;
	m_OldDelayedStart = false;

	m_RecoveryValid = false;
	m_RecoveryChanged = false;
	m_NumberOfActions = 0;
	m_EnableFlagCheckBox = false;
	m_RebootAfter = 0;

	m_DependantsValid = false;

	m_TriggerValid = false;
	m_TriggersChanged = false;
	m_InitialNumberOfTriggers = 0;

	m_OtherValid = false;
	m_PreshutdownTimeoutValid = false;
	m_RequiredPrivilegesValid = false;
	m_SidTypeValid = false;
	m_LaunchProtectedValid = false;
	m_OriginalLaunchProtected = 0;

	m_OtherChanged = false;

	QWidget* centralWidget = new QWidget();
	ui.setupUi(centralWidget);
	this->setCentralWidget(centralWidget);

	this->setWindowTitle(tr("Properties of %1").arg(m_pService->GetName()));
	m_pDependencies = new CServiceListWidget(true);
	ui.dependenciesLayout->addWidget(m_pDependencies, 0, 0);
	m_pDependencies->SetLabel(tr("This service depends on the following services:"));
	m_pDependants = new CServiceListWidget();
	ui.dependantsLayout->addWidget(m_pDependants, 0, 0);
	m_pDependants->SetLabel(tr("The following services depend on this service:"));
	ui.triggers->setHeaderLabels(tr("Trigger|Action").split("|"));
	ui.privilegs->setHeaderLabels(tr("Name|Display name").split("|"));

	connect(ui.tabWidget, SIGNAL(currentChanged(int)), this, SLOT(OnTab(int)));

	connect(ui.browseBtn, SIGNAL(pressed()), this, SLOT(OnBrowse()));
	connect(ui.showPW, SIGNAL(stateChanged(int)), this, SLOT(OnShowPW(int)));
	connect(ui.permissionsBtn, SIGNAL(pressed()), this, SLOT(OnPermissions()));
	ui.permissionsBtn->setEnabled(theSystem->HasCapability(CSystemAPI::eCapSecurityEditor));

	connect(ui.firstFailure, SIGNAL(currentTextChanged(const QString &)), this, SLOT(FixReciveryControls()));
	connect(ui.secondFailure, SIGNAL(currentTextChanged(const QString &)), this, SLOT(FixReciveryControls()));
	connect(ui.subsequentFailures, SIGNAL(currentTextChanged(const QString &)), this, SLOT(FixReciveryControls()));

	connect(ui.browseRun, SIGNAL(pressed()), this, SLOT(OnBrowseRun()));
	connect(ui.restartOptionsBtn, SIGNAL(pressed()), this, SLOT(OnRestartOptions()));

	connect(ui.svcType, SIGNAL(currentTextChanged(const QString &)), this, SLOT(OnGeneralChanged()));
	connect(ui.startType, SIGNAL(currentTextChanged(const QString &)), this, SLOT(OnGeneralChanged()));
	connect(ui.errorControl, SIGNAL(currentTextChanged(const QString &)), this, SLOT(OnGeneralChanged()));
	connect(ui.svcGroup, SIGNAL(textEdited(const QString &)), this, SLOT(OnGeneralChanged()));
	connect(ui.binaryPath, SIGNAL(textChanged(const QString &)), this, SLOT(OnGeneralChanged()));
	connect(ui.userName, SIGNAL(textChanged(const QString &)), this, SLOT(OnGeneralChanged()));
	connect(ui.userPW, SIGNAL(textChanged(const QString &)), this, SLOT(OnGeneralChanged()));
	connect(ui.delayedStart, SIGNAL(stateChanged(int)), this, SLOT(OnGeneralChanged()));

	connect(ui.firstFailure, SIGNAL(currentTextChanged(const QString &)), this, SLOT(OnRecoveryChanged()));
	connect(ui.secondFailure, SIGNAL(currentTextChanged(const QString &)), this, SLOT(OnRecoveryChanged()));
	connect(ui.subsequentFailures, SIGNAL(currentTextChanged(const QString &)), this, SLOT(OnRecoveryChanged()));
	connect(ui.resetFailCtr, SIGNAL(textEdited(const QString &)), this, SLOT(OnRecoveryChanged()));
	connect(ui.restartService, SIGNAL(textEdited(const QString &)), this, SLOT(OnRecoveryChanged()));
	connect(ui.actionsForError, SIGNAL(stateChanged(int)), this, SLOT(OnRecoveryChanged()));
	connect(ui.programRun, SIGNAL(textEdited(const QString &)), this, SLOT(OnRecoveryChanged()));


	connect(ui.triggers, SIGNAL(itemDoubleClicked(QTreeWidgetItem*, int)), this, SLOT(OnTrigger(QTreeWidgetItem*, int)));
	connect(ui.newBtn, SIGNAL(pressed()), this, SLOT(OnNewTrigger()));
	connect(ui.editBtn, SIGNAL(pressed()), this, SLOT(OnEditTrigger()));
	connect(ui.deleteBtn, SIGNAL(pressed()), this, SLOT(OnDeleteTrigger()));

	connect(ui.preShutdown, SIGNAL(textEdited(const QString &)), this, SLOT(OnPreShutdown()));
	connect(ui.sidType, SIGNAL(currentTextChanged(const QString &)), this, SLOT(OnSidType()));
	connect(ui.protectionType, SIGNAL(currentTextChanged(const QString &)), this, SLOT(OnProtectionType()));

	connect(ui.addBtn, SIGNAL(pressed()), this, SLOT(OnAddPrivilege()));
	connect(ui.removeBtn, SIGNAL(pressed()), this, SLOT(OnRemovePrivilege()));

	connect(ui.buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
	connect(ui.buttonBox, SIGNAL(rejected()), this, SLOT(reject()));

	restoreGeometry(theConf->GetBlob("ServiceWindow/Window_Geometry"));

	ASSERT(ui.tabWidget->currentWidget() == ui.generalTab);
	LoadGeneral();
}

CWinSvcWindow::~CWinSvcWindow()
{
	// m_Triggers holds values now, so there is nothing to free
	theConf->SetBlob("ServiceWindow/Window_Geometry",saveGeometry());
}

void CWinSvcWindow::closeEvent(QCloseEvent *e)
{
	this->deleteLater();
}

void CWinSvcWindow::OnTab(int tabIndex)
{
	//if (ui.tabWidget->currentWidget() == ui.generalTab)
	//	LoadGeneral();
	//else 
	if (ui.tabWidget->currentWidget() == ui.recoveryTab && !m_RecoveryValid)
		LoadRecovery();
	//else if (ui.tabWidget->currentWidget() == ui.dependenciesTab) // note: this is loaded with LoadGeneral();
	//	LoadDependencies();
	else if (ui.tabWidget->currentWidget() == ui.dependantsTab && !m_DependantsValid)
		LoadDependants();
	else if (ui.tabWidget->currentWidget() == ui.triggersTab && !m_TriggerValid)
		LoadTriggers();
	else if (ui.tabWidget->currentWidget() == ui.otherTab && !m_OtherValid)
		LoadOther();
}

void CWinSvcWindow::accept()
{
	// General Tab
	if(m_GeneralChanged)
	{
		m_GeneralChanged = false;
		SaveGeneral();
	}

	// Recovery Tab
	if (m_RecoveryChanged)
	{
		m_RecoveryChanged = false;
		SaveRecovery();
	}

	// Dependencies tab
	{
		// NOTHING
	}

	// dependants Tab
	{
		// NOTHING
	}

	// Triggers Tab
	if (m_TriggersChanged)
	{
		m_TriggersChanged = false;
		SaveTriggers();
	}

	// Other Tab
    if (m_OtherChanged)
    {
		m_OtherChanged = false;
		SaveOther();
	}

	this->close();
}

void CWinSvcWindow::reject()
{
	this->close();
}

quint32 SvcCallChangeServiceConfig(const QString& ServiceName, quint32 ServiceType, quint32 StartType, quint32 ErrorControl, const QString& BinaryPathName, const QString& LoadOrderGroup,
	quint32* pTagId, const QStringList* pDependencies, const QString& ServiceStartName, const QString& Password, const QString& DisplayName)
{
	QString SocketName = CTaskService::RunWorker();
	if (SocketName.isEmpty())
		return false;

	QVariantMap Parameters;
	Parameters["ServiceName"] = ServiceName;
	Parameters["ServiceType"] = ServiceType;
	Parameters["StartType"] = StartType;
	Parameters["ErrorControl"] = ErrorControl;
	if(!BinaryPathName.isNull())
		Parameters["BinaryPathName"] = BinaryPathName;
	if(!LoadOrderGroup.isNull())
		Parameters["LoadOrderGroup"] = LoadOrderGroup;
	if(pTagId)
		Parameters["LocalAdTagIddress"] = *pTagId;
	if(pDependencies)
		Parameters["Dependencies"] = *pDependencies;
	if(!ServiceStartName.isNull())
		Parameters["ServiceStartName"] = ServiceStartName;
	if(!Password.isNull())
		Parameters["Password"] = Password;
	if(!DisplayName.isNull())
		Parameters["DisplayName"] = DisplayName;

	QVariantMap Request;
	Request["Command"] = "ChangeServiceConfig";
	Request["Parameters"] = Parameters;

	QVariant Response = CTaskService::SendCommand(SocketName, Request);

	if(Response.isNull())
		return WAIT_TIMEOUT;
	if (Response.type() == QVariant::Int || Response.type() == QVariant::UInt)
		return Response.toUInt();
	return ERROR_INVALID_PARAMETER;
}

quint32 SvcCallChangeServiceConfig2(const QString& ServiceName, quint32 InfoLevel, const void* Info, size_t size)
{
	QString SocketName = CTaskService::RunWorker();
	if (SocketName.isEmpty())
		return false;

	QVariantMap Parameters;
	Parameters["ServiceName"] = ServiceName;
	Parameters["InfoLevel"] = InfoLevel;
	Parameters["InfoData"] = QByteArray((char*)Info, size);

	QVariantMap Request;
	Request["Command"] = "ChangeServiceConfig";
	Request["Parameters"] = Parameters;

	QVariant Response = CTaskService::SendCommand(SocketName, Request);

	if(Response.isNull())
		return WAIT_TIMEOUT;
	if (Response.type() == QVariant::Int || Response.type() == QVariant::UInt)
		return Response.toUInt();
	return ERROR_INVALID_PARAMETER;
}

void CWinSvcWindow::LoadGeneral()
{
	CServiceInfo::SConfig Config;
	if (!m_pService->GetConfig(Config))
	{
		ui.description->setPlainText(m_pService->GetDisplayName());
		m_GeneralChanged = false;
		return;
	}

	//
	// These three were never populated, so they always showed empty whatever the
	// service was configured as. The labels come from the target like the rest.
	//
	if (ui.svcType->count() == 0)
	{
		foreach(const CServiceInfo::SLabeledValue& Type, m_pService->GetServiceTypes())
			ui.svcType->addItem(Type.first, (quint64)Type.second);
		foreach(const CServiceInfo::SLabeledValue& Type, m_pService->GetStartTypes())
			ui.startType->addItem(Type.first, (quint64)Type.second);
		foreach(const CServiceInfo::SLabeledValue& Type, m_pService->GetErrorControlTypes())
			ui.errorControl->addItem(Type.first, (quint64)Type.second);
	}

	ui.svcType->setCurrentIndex(ui.svcType->findData((quint64)Config.Type));
	ui.startType->setCurrentIndex(ui.startType->findData((quint64)Config.StartType));
	ui.errorControl->setCurrentIndex(ui.errorControl->findData((quint64)Config.ErrorControl));

	ui.svcGroup->setText(Config.LoadOrderGroup);
	ui.binaryPath->setText(Config.BinaryPath);
	ui.userName->setText(Config.StartName);
	ui.description->setPlainText(Config.Description.isEmpty() ? m_pService->GetDisplayName() : Config.Description);

	m_pDependencies->SetServicesList(Config.Dependencies);
	m_OldDependencies = Config.Dependencies;

	m_OldDelayedStart = Config.DelayedStart;
	ui.delayedStart->setChecked(Config.DelayedStart);

	//
	// Nothing is ever read back out of this box; it is a placeholder, and the
	// password is only written when the user asks for it to be.
	//
	ui.userPW->setText(tr("password"));
	ui.showPW->setChecked(false);

	ui.dllPath->setText(Config.ServiceDll.isEmpty() ? tr("N/A") : Config.ServiceDll);

	m_GeneralChanged = false;
}

void CWinSvcWindow::SaveGeneral()
{
	CServiceInfo::SConfig Config;
	Config.Type = ui.svcType->currentData().toUInt();
	Config.StartType = ui.startType->currentData().toUInt();
	Config.ErrorControl = ui.errorControl->currentData().toUInt();
	Config.LoadOrderGroup = ui.svcGroup->text();
	Config.BinaryPath = ui.binaryPath->text();
	Config.StartName = ui.userName->text();
	Config.DelayedStart = ui.delayedStart->isChecked();

	//
	// Only send the two fields the platform treats as optional when they have
	// actually been touched - see the note on SConfig.
	//
	QStringList serviceList = m_pDependencies->GetServicesList();
	if (m_OldDependencies != serviceList)
	{
		Config.Dependencies = serviceList;
		Config.SetDependencies = true;
	}

	if (ui.showPW->isChecked())
	{
		Config.Password = ui.userPW->text();
		Config.SetPassword = true;
	}

	STATUS Status = m_pService->SetConfig(Config);
	if (Status.IsError())
	{
		QMessageBox::warning(NULL, "TaskExplorer", tr("Unable to change service configuration, error: %1").arg(CTaskExplorer::FormatError(Status)));
		return;
	}

	m_OldDependencies = serviceList;
	m_OldDelayedStart = Config.DelayedStart;
	m_GeneralChanged = false;

	emit ServicesChanged();
}

void CWinSvcWindow::LoadRecovery()
{
	if (m_pService->RunsInSystemProcess())
	{
		// Services which run in system processes don't support failure actions.
		ui.recoveryTab->setEnabled(false);
		return;
	}

	foreach(const CServiceInfo::SLabeledValue& Action, m_pService->GetRecoveryActionTypes())
	{
		ui.firstFailure->addItem(Action.first, (quint64)Action.second);
		ui.secondFailure->addItem(Action.first, (quint64)Action.second);
		ui.subsequentFailures->addItem(Action.first, (quint64)Action.second);
	}

	CServiceInfo::SRecovery Recovery;
	if (!m_pService->GetRecovery(Recovery))
	{
		FixReciveryControls();
		m_RecoveryChanged = false;
		m_RecoveryValid = true;
		return;
	}

	m_NumberOfActions = Recovery.ActionCount;

	//
	// Where fewer than three actions are configured the last one is repeated,
	// which is what the system does anyway.
	//
	quint32 lastType = SC_ACTION_NONE;
	QComboBox* pBoxes[3] = { ui.firstFailure, ui.secondFailure, ui.subsequentFailures };
	for (int i = 0; i < 3; i++)
	{
		if (i < Recovery.Actions.count())
			lastType = Recovery.Actions[i].Type;
		pBoxes[i]->setCurrentIndex(pBoxes[i]->findData(lastType));
	}

	ui.resetFailCtr->setText(QString::number(Recovery.ResetPeriod / (60 * 60 * 24))); // s to days

	ui.restartService->setText("1");
	m_RebootAfter = 1 * 1000 * 60;
	//
	// There is one delay box for all three slots, so the first action of each
	// kind is the one it shows - later ones with a different delay are not
	// representable and are left alone.
	//
	bool bGotRestart = false, bGotReboot = false;
	foreach(const CServiceInfo::SRecoveryAction& Action, Recovery.Actions)
	{
		if (Action.Type == SC_ACTION_RESTART && !bGotRestart)
		{
			bGotRestart = true;
			if (Action.Delay != 0)
				ui.restartService->setText(QString::number(Action.Delay / (1000 * 60))); // ms to min
		}
		else if (Action.Type == SC_ACTION_REBOOT && !bGotReboot)
		{
			bGotReboot = true;
			if (Action.Delay != 0)
				m_RebootAfter = Action.Delay;
		}
	}

	m_EnableFlagCheckBox = Recovery.HasNonCrashFlag;
	if (Recovery.HasNonCrashFlag)
		ui.actionsForError->setChecked(Recovery.NonCrashFailures);

	m_RebootMessage = Recovery.RebootMessage;
	ui.programRun->setText(Recovery.CommandLine);

	if (m_NumberOfActions != 0 && m_NumberOfActions != 3)
	{
		if (m_NumberOfActions > 3)
		{
			QMessageBox::warning(NULL, "TaskExplorer", tr("The service has %1 failure actions configured, but this program only supports editing 3.\r\n"
				"If you save the recovery information using this program, the additional failure actions will be lost.").arg(m_NumberOfActions));
		}
	}

	FixReciveryControls();

	m_RecoveryChanged = false;
	m_RecoveryValid = true;
}

void CWinSvcWindow::SaveRecovery()
{
	CServiceInfo::SRecovery Recovery;
	Recovery.ResetPeriod = ui.resetFailCtr->text().toULong() * 60 * 60 * 24;   // days to s
	Recovery.RebootMessage = m_RebootMessage;
	Recovery.CommandLine = ui.programRun->text();
	Recovery.HasNonCrashFlag = m_EnableFlagCheckBox;
	Recovery.NonCrashFailures = ui.actionsForError->isChecked();

	const quint32 RestartAfter = ui.restartService->text().toULong() * 1000 * 60; // min to ms

	QComboBox* pBoxes[3] = { ui.firstFailure, ui.secondFailure, ui.subsequentFailures };
	for (int i = 0; i < 3; i++)
	{
		CServiceInfo::SRecoveryAction Action;
		Action.Type = pBoxes[i]->currentData().toUInt();

		switch (Action.Type)
		{
		case SC_ACTION_RESTART:		Action.Delay = RestartAfter; break;
		case SC_ACTION_REBOOT:		Action.Delay = m_RebootAfter; break;
		default:					Action.Delay = 0; break;
		}

		Recovery.Actions.append(Action);
	}

	STATUS Status = m_pService->SetRecovery(Recovery);
	if (Status.IsError())
		QMessageBox::warning(NULL, "TaskExplorer", tr("Unable to change service recovery information: %1").arg(CTaskExplorer::FormatError(Status)));
}

//void CWinSvcWindow::LoadDependencies()

//void CWinSvcWindow::SaveDependencies()

void CWinSvcWindow::LoadDependants()
{
	m_pDependants->SetServicesList(m_pService->GetDependents());
	m_DependantsValid = true;
}

//void CWinSvcWindow::SaveDependants()

void CWinSvcWindow::LoadTriggers()
{
	foreach(const CServiceInfo::STrigger& Trigger, m_pService->GetTriggers())
		AddTrigger(Trigger);

	m_InitialNumberOfTriggers = m_Triggers.size();

	m_TriggersChanged = false;
	m_TriggerValid = true;
}

void CWinSvcWindow::SaveTriggers()
{
	STATUS Status = m_pService->SetTriggers(m_Triggers, m_InitialNumberOfTriggers != 0);
	if (Status.IsError())
		QMessageBox::warning(NULL, "TaskExplorer", tr("Unable to change service trigger information: %1").arg(CTaskExplorer::FormatError(Status)));
}

void CWinSvcWindow::LoadOther()
{
	foreach(const CServiceInfo::SLabeledValue& Type, m_pService->GetSidTypes())
		ui.sidType->addItem(Type.first, (quint64)Type.second);
	foreach(const CServiceInfo::SLabeledValue& Type, m_pService->GetLaunchProtectionTypes())
		ui.protectionType->addItem(Type.first, (quint64)Type.second);

	ULONG Type = m_pService->GetType();
	if (Type == SERVICE_KERNEL_DRIVER || Type == SERVICE_FILE_SYSTEM_DRIVER)
	{
		// Drivers don't support required privileges.
		ui.addBtn->setEnabled(false);
		ui.removeBtn->setEnabled(false);
	}

	CServiceInfo::SExtras Extras;
	if (!m_pService->GetExtras(Extras))
	{
		QMessageBox::warning(NULL, "TaskExplorer", tr("Unable to query service information."));
		m_OtherChanged = false;
		m_OtherValid = true;
		return;
	}

	ui.serviceSID->setText(Extras.SidString.isEmpty() ? tr("N/A") : Extras.SidString);

	//
	// A setting the target does not report is one we must not write back, so the
	// control is disabled rather than left showing a made-up value.
	//
	m_PreshutdownTimeoutValid = Extras.HasPreShutdownTimeout;
	if (Extras.HasPreShutdownTimeout)
		ui.preShutdown->setText(QString::number(Extras.PreShutdownTimeout));

	m_RequiredPrivilegesValid = Extras.HasPrivileges;
	foreach(const QString& Privilege, Extras.Privileges)
		AddPrivilege(Privilege);

	m_SidTypeValid = Extras.HasSidType;
	if (Extras.HasSidType)
		ui.sidType->setCurrentIndex(ui.sidType->findData((quint64)Extras.SidType));

	m_LaunchProtectedValid = Extras.HasLaunchProtected;
	ui.protectionType->setEnabled(Extras.HasLaunchProtected);
	if (Extras.HasLaunchProtected)
	{
		ui.protectionType->setCurrentIndex(ui.protectionType->findData((quint64)Extras.LaunchProtected));
		m_OriginalLaunchProtected = Extras.LaunchProtected;
	}

	m_OtherChanged = false;
	m_OtherValid = true;
}

void CWinSvcWindow::SaveOther()
{
	const quint32 LaunchProtected = ui.protectionType->currentData().toUInt();

	if (m_LaunchProtectedValid && LaunchProtected != 0 && LaunchProtected != m_OriginalLaunchProtected)
	{
		if (QMessageBox("TaskExplorer", tr("Setting service protection will prevent the service from being controlled, modified, or deleted. Do you want to continue?"), QMessageBox::Question, QMessageBox::Yes, QMessageBox::No | QMessageBox::Default | QMessageBox::Escape, QMessageBox::NoButton).exec() != QMessageBox::Yes)
			return;
	}

	CServiceInfo::SExtras Extras;

	Extras.HasPreShutdownTimeout = m_PreshutdownTimeoutValid;
	Extras.PreShutdownTimeout = ui.preShutdown->text().toULong();

	Extras.HasPrivileges = m_RequiredPrivilegesValid;
	for (int i = 0; i < ui.privilegs->topLevelItemCount(); i++)
		Extras.Privileges.append(ui.privilegs->topLevelItem(i)->text(0));

	Extras.HasSidType = m_SidTypeValid;
	Extras.SidType = ui.sidType->currentData().toUInt();

	Extras.HasLaunchProtected = m_LaunchProtectedValid;
	Extras.LaunchProtected = LaunchProtected;

	STATUS Status = m_pService->SetExtras(Extras);
	if (Status.IsError())
		QMessageBox::warning(NULL, "TaskExplorer", tr("Unable to change other service information: %1").arg(CTaskExplorer::FormatError(Status)));
}


void CWinSvcWindow::OnBrowse()
{
	QStringList FilePaths = QFileDialog::getOpenFileNames(0, tr("Select binary"), "", tr("All files (*.*)"));
	if (FilePaths.isEmpty())
		return;

	ui.binaryPath->setText(FilePaths.first());
}

void CWinSvcWindow::OnShowPW(int state)
{
	ui.userPW->setEchoMode(state == Qt::Checked ? QLineEdit::Normal : QLineEdit::Password);
}

void CWinSvcWindow::OnPermissions()
{
	CTaskExplorer::ShowSecurity(m_pService->GetSecurityObject(), this);
}

void CWinSvcWindow::OnBrowseRun()
{
	QStringList FilePaths = QFileDialog::getOpenFileNames(0, tr("Select program"), "", tr("All files (*.*)"));
	if (FilePaths.isEmpty())
		return;

	ui.programRun->setText(FilePaths.first());
}

void CWinSvcWindow::OnRestartOptions()
{
	CWinSvcShutdown dialog;
	dialog.SetRestartTime(m_RebootAfter);
	dialog.SetMessageText(m_RebootMessage);
	
	if (!dialog.exec())
		return;

	m_RecoveryChanged = true;
	m_RebootAfter = dialog.GetRestartTime();
	m_RebootMessage = dialog.GetMessageText();
}

void CWinSvcWindow::FixReciveryControls()
{
    SC_ACTION_TYPE action1;
    SC_ACTION_TYPE action2;
    SC_ACTION_TYPE actionS;
    BOOLEAN enableRestart;
    BOOLEAN enableReboot;
    BOOLEAN enableCommand;

	action1 = (SC_ACTION_TYPE)ui.firstFailure->currentData().toULongLong();
    action2 = (SC_ACTION_TYPE)ui.secondFailure->currentData().toULongLong();
    actionS = (SC_ACTION_TYPE)ui.subsequentFailures->currentData().toULongLong();

	ui.actionsForError->setEnabled(m_EnableFlagCheckBox);

    enableRestart = action1 == SC_ACTION_RESTART || action2 == SC_ACTION_RESTART || actionS == SC_ACTION_RESTART;
    enableReboot = action1 == SC_ACTION_REBOOT || action2 == SC_ACTION_REBOOT || actionS == SC_ACTION_REBOOT;
    enableCommand = action1 == SC_ACTION_RUN_COMMAND || action2 == SC_ACTION_RUN_COMMAND || actionS == SC_ACTION_RUN_COMMAND;

	ui.restartService->setEnabled(enableRestart);

	ui.restartOptionsBtn->setEnabled(enableReboot);

	ui.runGroup->setEnabled(enableCommand);
}

void CWinSvcWindow::OnTrigger(QTreeWidgetItem *item, int column)
{
	int index = item->data(0, Qt::UserRole).toInt();
	if (index < 0 || index >= m_Triggers.count())
		return;

	CWinSvcTrigger WinSvcTrigger(m_pService, this);
	WinSvcTrigger.SetTrigger(m_Triggers[index]);
	if (WinSvcTrigger.exec())
	{
		m_TriggersChanged = true;
		m_Triggers[index] = WinSvcTrigger.GetTrigger();
		UpdateTrigger(item, m_Triggers[index]);
	}
}

void CWinSvcWindow::OnNewTrigger()
{
	CWinSvcTrigger WinSvcTrigger(m_pService, this);
	if (WinSvcTrigger.exec())
	{
		m_TriggersChanged = true;
		AddTrigger(WinSvcTrigger.GetTrigger());
	}
}

void CWinSvcWindow::OnEditTrigger()
{
	QTreeWidgetItem *item = ui.triggers->currentItem();
	if (!item)
		return;
	OnTrigger(item, 0);
}

void CWinSvcWindow::OnDeleteTrigger()
{
	QTreeWidgetItem *item = ui.triggers->currentItem();
	if (!item)
		return;

	int index = item->data(0, Qt::UserRole).toInt();
	if (index < 0 || index >= m_Triggers.count())
		return;

	if(QMessageBox("TaskExplorer", tr("Do you want to delete the selected trigger"), QMessageBox::Question, QMessageBox::Yes, QMessageBox::No | QMessageBox::Default | QMessageBox::Escape, QMessageBox::NoButton).exec() != QMessageBox::Yes)
		return;

	m_TriggersChanged = true;
	m_Triggers.removeAt(index);
	delete item;

	//
	// The rows carry their index into the list, so everything after the deleted
	// one has to be renumbered.
	//
	for (int i = 0; i < ui.triggers->topLevelItemCount(); i++)
		ui.triggers->topLevelItem(i)->setData(0, Qt::UserRole, i);
}

void CWinSvcWindow::AddTrigger(const CServiceInfo::STrigger& Trigger)
{
	QTreeWidgetItem* pItem = new QTreeWidgetItem();
	pItem->setData(0, Qt::UserRole, m_Triggers.count());
	m_Triggers.append(Trigger);
	ui.triggers->addTopLevelItem(pItem);

	UpdateTrigger(pItem, Trigger);
}

void CWinSvcWindow::UpdateTrigger(QTreeWidgetItem* pItem, const CServiceInfo::STrigger& Trigger)
{
	QString Description, Action;
	m_pService->GetTriggerStrings(Trigger, Description, Action);

	pItem->setText(0, Description);
	pItem->setText(1, Action);
}

void CWinSvcWindow::OnAddPrivilege()
{
	CComboInputDialog comboDalog(this);
	comboDalog.setText(tr("Select privilege to add:"));

	//
	// The list comes from the machine the service lives on, so its privileges
	// are the ones offered - not this machine's.
	//
	QList<CSystemAPI::SPrivilege> Privileges;
	if (CSystemPtr pSystem = m_pService->GetSystem())
		Privileges = pSystem->EnumPrivileges();
	if (Privileges.isEmpty())
	{
		QMessageBox::critical(NULL, "TaskExplorer", tr("Unable to enumerate privileges."));
		return;
	}

	foreach(const CSystemAPI::SPrivilege& Privilege, Privileges)
		comboDalog.addItem(Privilege.Name);

	if (!comboDalog.exec())
		return;

	QString Privilege = comboDalog.value();

	if (!ui.privilegs->findItems(Privilege, Qt::MatchFixedString, 0).isEmpty())
	{
		QMessageBox::warning(NULL, "TaskExplorer", tr("Privilege '%1' was already added.").arg(Privilege));
		return;
	}

	AddPrivilege(Privilege);

	m_OtherChanged = true;
}

void CWinSvcWindow::OnRemovePrivilege()
{
	QTreeWidgetItem *item = ui.privilegs->currentItem();
	if (!item)
		return;

	if(QMessageBox("TaskExplorer", tr("Do you want to delete the selected privileg"), QMessageBox::Question, QMessageBox::Yes, QMessageBox::No | QMessageBox::Default | QMessageBox::Escape, QMessageBox::NoButton).exec() != QMessageBox::Yes)
		return;

	delete item;
}

void CWinSvcWindow::AddPrivilege(const QString& Privilege)
{
	QTreeWidgetItem* pItem = new QTreeWidgetItem();
	pItem->setData(0, Qt::UserRole, Privilege);
	pItem->setText(0, Privilege);

	//
	// Cached: the dialog adds privileges one at a time, and asking the target
	// again for each would be a round trip per row.
	//
	if (m_Privileges.isEmpty())
		if (CSystemPtr pSystem = m_pService->GetSystem())
			m_Privileges = pSystem->EnumPrivileges();

	foreach(const CSystemAPI::SPrivilege& Known, m_Privileges)
	{
		if (Known.Name.compare(Privilege, Qt::CaseInsensitive) == 0)
		{
			pItem->setText(1, Known.DisplayName);
			break;
		}
	}

	ui.privilegs->addTopLevelItem(pItem);
}





