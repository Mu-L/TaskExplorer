#include "stdafx.h"
#include "NewService.h"
#include "../../MiscHelpers/Common/Settings.h"
#include "../API/SystemAPI.h"
#include "TaskExplorer.h"


CNewService::CNewService(QWidget *parent)
	: QMainWindow(parent)
{
	QWidget* centralWidget = new QWidget();
	ui.setupUi(centralWidget);
	this->setCentralWidget(centralWidget);

	foreach(const CServiceInfo::SLabeledValue& Type, theSystem->GetNewServiceTypes())
		ui.svcType->addItem(Type.first, Type.second);
	foreach(const CServiceInfo::SLabeledValue& Type, theSystem->GetNewServiceStartTypes())
		ui.startType->addItem(Type.first, Type.second);
	foreach(const CServiceInfo::SLabeledValue& Type, theSystem->GetNewServiceErrorControlTypes())
		ui.errorControl->addItem(Type.first, Type.second);

	ui.svcType->setCurrentIndex(2); // "Own Process"
	ui.startType->setCurrentIndex(4); // "Demand Start"
	ui.errorControl->setCurrentIndex(0); // "Ignore"

	connect(ui.browseBtn, SIGNAL(pressed()), this, SLOT(OnBrowse()));
	connect(ui.buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
	connect(ui.buttonBox, SIGNAL(rejected()), this, SLOT(reject()));

	restoreGeometry(theConf->GetBlob("NewServiceWindow/Window_Geometry"));
}

CNewService::~CNewService()
{
	theConf->SetBlob("NewServiceWindow/Window_Geometry", saveGeometry());
}

void CNewService::closeEvent(QCloseEvent *e)
{
	this->deleteLater();
}

void CNewService::accept()
{

	quint32 serviceType = ui.svcType->currentData().toInt();
	quint32 serviceStartType = ui.startType->currentData().toInt();
	quint32 serviceErrorControl = ui.errorControl->currentData().toInt();

	STATUS Status = theSystem->CreateNewService(ui.scvName->text(), ui.displayName->text(),
		ui.binaryPath->text().replace("/", "\\"), serviceType, serviceStartType, serviceErrorControl);

	if (Status.IsError())
		QMessageBox::warning(NULL, "TaskExplorer", tr("Failed to create service, error: %1").arg(CTaskExplorer::FormatError(Status)));
	else
	{
		QMessageBox::information(NULL, "TaskExplorer", tr("Successfully created service: %1").arg(ui.scvName->text()));
		this->close();
	}
}

void CNewService::reject()
{
	this->close();
}

void CNewService::OnBrowse()
{
	QStringList FilePaths = QFileDialog::getOpenFileNames(0, tr("Select binary"), "", tr("All files (*.*)"));
	if (FilePaths.isEmpty())
		return;

	ui.binaryPath->setText(FilePaths.first());
}
