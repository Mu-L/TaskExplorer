#include "stdafx.h"
#include "RunDialog.h"
#include "../../MiscHelpers/Common/Settings.h"
#include "../API/SystemAPI.h"
#include "TaskExplorer.h"

CRunDialog::CRunDialog(CSystemAPI* pSystem, QWidget *parent)
	: QMainWindow(parent)
{
	m_pSystem = pSystem ? pSystem : theSystem.data();

	QWidget* centralWidget = new QWidget();
	ui.setupUi(centralWidget);
	this->setCentralWidget(centralWidget);

	ui.binaryPath->addItems(m_pSystem->GetRunHistory());

	//
	// Named in the title when it is not this computer, because "Run" on its own
	// would be the same window for both and there is no undoing a program
	// started on the wrong machine.
	//
	if (!m_pSystem->IsLocal())
		setWindowTitle(tr("Run on %1").arg(m_pSystem->GetHostName()));

	bool IsAdmin = m_pSystem->RootAvaiable();
	ui.elevated->setEnabled(IsAdmin);
	ui.lblShield->setVisible(IsAdmin);

	ui.dllPath->addItems(theConf->GetStringList("General/InjectionDlls"));
	//if(ui.dllPath->count() == 0)
	//	ui.dllPath->addItem("");
	ui.dllPath->addItem(tr("[Browse for Dll]"));
	ui.dllPath->setCurrentIndex(-1);
	ui.dllPath->setEnabled(false);


	connect(ui.injectDll, SIGNAL(stateChanged(int)), this, SLOT(OnInjectDll()));
	connect(ui.dllPath, SIGNAL(currentIndexChanged(int)), this, SLOT(OnDllPath()));
	connect(ui.browseBtn, SIGNAL(pressed()), this, SLOT(OnBrowse()));
	connect(ui.buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
	connect(ui.buttonBox, SIGNAL(rejected()), this, SLOT(reject()));

	restoreGeometry(theConf->GetBlob("RunWindow/Window_Geometry"));
}

CRunDialog::~CRunDialog()
{
	theConf->SetBlob("RunWindow/Window_Geometry",saveGeometry());
}

void CRunDialog::closeEvent(QCloseEvent *e)
{
	this->deleteLater();
}

bool CRunDialog::event(QEvent* event)
{
	if (event->type() == QEvent::KeyPress) {
		QKeyEvent* key = static_cast<QKeyEvent*>(event);
		if ((key->key() == Qt::Key_Enter) || (key->key() == Qt::Key_Return)) {
			accept();
			return true;
		}
	}
	return QMainWindow::event(event);
}

void CRunDialog::accept()
{
	CSystemAPI::SRunOptions Options;
	Options.Program = ui.binaryPath->currentText();
	Options.Elevated = ui.elevated->isChecked();
	Options.Suspended = ui.suspended->isChecked();
	if (ui.injectDll->isChecked())
		Options.InjectDll = ui.dllPath->currentText();

	STATUS Status = m_pSystem->RunProgram(Options);
	if (Status.IsError())
	{
		QMessageBox::warning(this, "TaskExplorer", tr("Unable to execute the program: %1").arg(CTaskExplorer::FormatError(Status)));
		return;
	}

	if (!Options.InjectDll.isEmpty())
	{
		QStringList DLLs = theConf->GetStringList("General/InjectionDlls");
		DLLs.removeAll(Options.InjectDll);
		DLLs.prepend(Options.InjectDll);
		theConf->SetValue("General/InjectionDlls", DLLs);
	}

	this->close();
}

void CRunDialog::reject()
{
	this->close();
}

void CRunDialog::OnBrowse()
{
	QString FilePath = QFileDialog::getOpenFileName(0, tr("Select binary"), "", tr("All files (*.*)"));
	if (!FilePath.isEmpty())
		ui.binaryPath->setEditText(FilePath);
}

void CRunDialog::OnInjectDll()
{
	ui.dllPath->setEnabled(ui.injectDll->isChecked());
}

void CRunDialog::OnDllPath()
{
	if (ui.dllPath->currentIndex() != ui.dllPath->count() - 1)
		return;
	ui.dllPath->setCurrentIndex(-1);
	QString FilePath = QFileDialog::getOpenFileName(0, tr("Select injection DLL"), "", tr("Dll files (*.dll)"));
	if (!FilePath.isEmpty())
		ui.dllPath->setEditText(FilePath);
}