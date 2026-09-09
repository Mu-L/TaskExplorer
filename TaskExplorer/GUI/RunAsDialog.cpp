#include "stdafx.h"
#include "RunAsDialog.h"
#include "../../MiscHelpers/Common/Settings.h"
#include "../API/SystemAPI.h"
#include "TaskExplorer.h"

CRunAsDialog::CRunAsDialog(CSystemAPI* pSystem, quint64 PID, QWidget *parent)
	: QMainWindow(parent)
{
	m_pSystem = pSystem ? pSystem : theSystem.data();

	QWidget* centralWidget = new QWidget();
	ui.setupUi(centralWidget);
	this->setCentralWidget(centralWidget);

	m_PID = PID;

	//
	// Everything the dialog offers comes from the target, so a remote session
	// would list that machine's accounts, sessions and desktops rather than this
	// one's.
	//
	//
	// Named in the title when it is not this computer - see CRunDialog.
	//
	if (!m_pSystem->IsLocal())
		setWindowTitle(tr("Run as, on %1").arg(m_pSystem->GetHostName()));

	CSystemAPI::SRunAsChoices Choices = m_pSystem->GetRunAsChoices();

	typedef QPair<QString, quint32> SLabeledId;

	//
	// A combo with nothing in it says "none of these", which is the opposite of
	// what is meant: a platform that has no logon types has no such notion at
	// all, and a platform whose sessions cannot be honoured should not offer to
	// pick one. Both rows go rather than sit there empty - see
	// CLinuxAPI::GetRunAsChoices, which is where the empty ones came from.
	//
	foreach(const SLabeledId& Type, Choices.LogonTypes)
		ui.loginType->addItem(Type.first, Type.second);

	ui.binaryPath->addItems(m_pSystem->GetRunHistory());
	ui.userName->addItems(Choices.Accounts);

	foreach(const SLabeledId& Session, Choices.Sessions)
		ui.session->addItem(Session.first, Session.second);
	ui.desktop->addItems(Choices.Desktops);

	//
	// A row whose choices are empty is hidden, label and all.
	//
	// The labels are named rather than found through the layout because the
	// grid pairs them by position, and a hidden widget still holds its cell -
	// leaving "Type:" beside nothing would be exactly the confusion this is
	// removing. label_7 is Type, label_5 is Session ID, label_6 is Desktop.
	//
	const bool bTypes = !Choices.LogonTypes.isEmpty();
	ui.label_7->setVisible(bTypes);
	ui.loginType->setVisible(bTypes);

	//
	// The linked token goes with them. It is one particular property of a
	// Windows logon token - the unelevated half of a split administrator - so
	// on a platform that has no logon types to pick from there is nothing for
	// the box to mean, and an unchecked box that cannot do anything still
	// invites somebody to check it.
	//
	ui.useToken->setVisible(bTypes);

	const bool bSessions = !Choices.Sessions.isEmpty();
	ui.label_5->setVisible(bSessions);
	ui.session->setVisible(bSessions);

	const bool bDesktops = !Choices.Desktops.isEmpty();
	ui.label_6->setVisible(bDesktops);
	ui.desktop->setVisible(bDesktops);

	int iSession = ui.session->findData(Choices.CurrentSessionId);
	if (iSession != -1)
		ui.session->setCurrentIndex(iSession);

	int iDesktop = ui.desktop->findText(Choices.CurrentDesktop);
	if (iDesktop != -1)
		ui.desktop->setCurrentIndex(iDesktop);

	if (m_PID != 0)
	{
		ui.userName->setEnabled(false);
		ui.loginType->setEnabled(false);
		ui.password->setEnabled(false);
	}
	OnUserName(ui.userName->currentText());

	connect(ui.userName, SIGNAL(currentTextChanged(const QString&)), this, SLOT(OnUserName(const QString&)));

	connect(ui.browseBtn, SIGNAL(pressed()), this, SLOT(OnBrowse()));
	connect(ui.buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
	connect(ui.buttonBox, SIGNAL(rejected()), this, SLOT(reject()));

	restoreGeometry(theConf->GetBlob("RunAsWindow/Window_Geometry"));
}

CRunAsDialog::~CRunAsDialog()
{
	theConf->SetBlob("RunAsWindow/Window_Geometry",saveGeometry());
}

void CRunAsDialog::closeEvent(QCloseEvent *e)
{
	this->deleteLater();
}

bool CRunAsDialog::event(QEvent* event)
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

void CRunAsDialog::accept()
{
	CSystemAPI::SRunAsOptions Options;
	Options.Program = ui.binaryPath->currentText();
	Options.UserName = ui.userName->currentText();
	Options.Desktop = ui.desktop->currentText();
	Options.LogonType = ui.loginType->currentData().toUInt();
	Options.SessionId = ui.session->currentData().toUInt();
	Options.ParentPid = m_PID;
	Options.UseLinkedToken = ui.useToken->isChecked();
	Options.Suspended = ui.suspended->isChecked();

	if (!m_pSystem->IsServiceAccount(Options.UserName))
	{
		Options.Password = ui.password->text();
		ui.password->clear();
	}

	STATUS Status = m_pSystem->RunProgramAs(Options);
	if (Status.IsError())
	{
		QMessageBox::warning(NULL, "TaskExplorer", tr("Unable to start the program, Error: %1").arg(CTaskExplorer::FormatError(Status)));
		return;
	}

	this->close();
}

void CRunAsDialog::reject()
{
	this->close();
}

void CRunAsDialog::OnBrowse()
{
	QStringList FilePaths = QFileDialog::getOpenFileNames(0, tr("Select binary"), "", tr("All files (*.*)"));
	if (FilePaths.isEmpty())
		return;

	ui.binaryPath->setEditText(FilePaths.first());
}

void CRunAsDialog::OnUserName(const QString& userName)
{
	//
	// A service account has no password to give, so the box is greyed and the
	// logon type follows suit.
	//
	const bool bService = m_pSystem->IsServiceAccount(userName);
	ui.password->setEnabled(!bService);

	int iType = ui.loginType->findData(bService ? 5 /*LOGON32_LOGON_SERVICE*/ : 2 /*LOGON32_LOGON_INTERACTIVE*/);
	if (iType != -1)
		ui.loginType->setCurrentIndex(iType);
}
