#include "stdafx.h"
#include "TaskStrings.h"
#include "DriverWindow.h"
#include "../../MiscHelpers/Common/Settings.h"
#include "../API/SystemAPI.h"
#include "TaskExplorer.h"

CDriverWindow::CDriverWindow(QWidget *parent)
	: QMainWindow(parent)
{
	QWidget* centralWidget = new QWidget();
	ui.setupUi(centralWidget);
	this->setCentralWidget(centralWidget);
	this->setWindowTitle("Task Explorer - Driver Options");

	connect(ui.btnGetDynData, SIGNAL(clicked(bool)), this, SLOT(GetDynData()));

	connect(ui.buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
	connect(ui.buttonBox, SIGNAL(rejected()), this, SLOT(reject()));

	ui.chkUseDriver->setChecked(theConf->GetBool("OptionsKSI/KsiEnable", true));
	ui.deviceName->setText(theConf->GetString("OptionsKSI/DeviceName", "KTaskExplorer"));

	Refresh();

	if(theSystem->IsTestSigning())
		ui.signingPolicy->setText(tr("Test Signing Enabled"));
	else if(theSystem->IsCKSEnabled())
		ui.signingPolicy->setText(tr("Signature Required (CKS Enabled)"));
	else
		ui.signingPolicy->setText(tr("Signature Required"));
	
	restoreGeometry(theConf->GetBlob("DriverWindow/Window_Geometry"));

	m_TimerId = startTimer(250);
}

CDriverWindow::~CDriverWindow()
{
	theConf->SetBlob("DriverWindow/Window_Geometry", saveGeometry());

	if(m_TimerId != -1)
		killTimer(m_TimerId);
}

void CDriverWindow::closeEvent(QCloseEvent *e)
{
	this->deleteLater();
}

void CDriverWindow::accept()
{
	theConf->SetValue("OptionsKSI/KsiEnable", ui.chkUseDriver->isChecked());
	//theConf->SetValue("OptionsKSI/DeviceName", ui.deviceName->text());

	this->close();
}

void CDriverWindow::reject()
{
	this->close();
}

void CDriverWindow::timerEvent(QTimerEvent *e)
{
	if (e->timerId() != m_TimerId) 
	{
		QMainWindow::timerEvent(e);
		return;
	}

	Refresh();
}

void CDriverWindow::Refresh()
{
	if (CServicePtr pService = theSystem->GetService(ui.deviceName->text()))
	{
		ui.driverStatus->setText(::GetServiceStateString(pService));
		ui.driverStatus->setToolTip(pService->GetFileName());
	}
	else
	{
		ui.driverStatus->setText(tr("Not installed"));
		ui.driverStatus->setToolTip("");
	}

	CSystemAPI::SKernelDriver Driver = theSystem->GetKernelDriver();
	if (Driver.Connected)
	{
		ui.connection->setText(tr("Connected"));

		ui.dyn_data->setText(Driver.DynDataLoaded ? tr("DynData loaded") : tr("DynData NOT loaded"));

		ui.verification->setText(CTaskExplorer::GetKernelLevelString(Driver.Level));
		ui.verification->setToolTip(CTaskExplorer::GetKernelWeaknessStrings(Driver.Weaknesses).join("\n"));
	}
	else
	{
		ui.connection->setText(tr("Disconnected"));

		ui.dyn_data->setText(tr("N/A"));

		ui.verification->setText(tr("N/A"));
		ui.verification->setToolTip("");
	}
}

void CDriverWindow::GetDynData()
{
	QString AppDir = QCoreApplication::applicationDirPath().replace("/", "\\");

	STATUS Status = CTaskExplorer::UpdateDynData(AppDir);
	if (Status)
		Status = theSystem->LoadDynData(AppDir);

	if (!Status)
		CTaskExplorer::CheckErrors(QList<STATUS>() << Status);
}
