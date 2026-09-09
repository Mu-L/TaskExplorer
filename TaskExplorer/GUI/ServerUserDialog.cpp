#include "stdafx.h"
#include "ServerUserDialog.h"

#include <QFormLayout>
#include <QVBoxLayout>
#include <QMessageBox>

CServerUserDialog::CServerUserDialog(const SServerUserRecord& User, QWidget* pParent)
	: QDialog(pParent), m_bNew(User.Name.isEmpty()), m_Was(User)
{
	setWindowTitle(m_bNew ? tr("Add User") : tr("Edit User"));

	QVBoxLayout* pMain = new QVBoxLayout(this);
	QFormLayout* pForm = new QFormLayout();
	pMain->addLayout(pForm);

	m_pName = new QLineEdit(User.Name);
	m_pName->setPlaceholderText(tr("A name, or an account on the server's machine"));
	//
	// A name is the key the account is stored under, so changing it would be a
	// different account rather than the same one renamed - and the stored
	// password would not come with it.
	//
	m_pName->setEnabled(m_bNew);

	//
	// The name decides whether OK is available, so it has to say when it
	// changes.
	//
	// Without this the button only ever re-evaluated when a password field did,
	// which works right up until somebody types a name and leaves the password
	// empty - which is the documented way to ask for a system account. Typing a
	// name and stopping left OK disabled with a hint that said the account was
	// fine.
	//
	connect(m_pName, SIGNAL(textChanged(const QString&)), this, SLOT(OnPasswordChanged()));
	pForm->addRow(tr("User:"), m_pName);

	m_pRole = new QComboBox();
	m_pRole->addItem(tr("User - only their own processes"), false);
	m_pRole->addItem(tr("Admin - everything the server can see"), true);
	m_pRole->setCurrentIndex(User.bAdmin ? 1 : 0);
	pForm->addRow(tr("Level:"), m_pRole);

	//
	// Independent of the level, because they answer different questions: the
	// level decides what may be *seen*, this decides whether what is seen may be
	// touched. A read-only administrator is a sensible thing - a watchdog that
	// should see everything and change nothing is exactly one.
	//
	m_pActions = new QCheckBox(tr("May terminate, suspend and change things"));
	m_pActions->setChecked(User.bActions);
	pForm->addRow(tr("Actions:"), m_pActions);

	//
	// Off for an existing account, so that opening this dialog to flip a
	// checkbox does not quietly rewrite the password to blank - which would
	// change how the account authenticates, not just what it may do.
	//
	m_pSetPassword = new QCheckBox(tr("Set a new password"));
	m_pSetPassword->setChecked(m_bNew);
	if (m_bNew)
		m_pSetPassword->setVisible(false);
	connect(m_pSetPassword, SIGNAL(stateChanged(int)), this, SLOT(OnPasswordChanged()));
	pForm->addRow(QString(), m_pSetPassword);

	m_pPassword = new QLineEdit();
	m_pPassword->setEchoMode(QLineEdit::Password);
	m_pPassword->setPlaceholderText(tr("Leave empty to use the account on the server's machine"));
	connect(m_pPassword, SIGNAL(textChanged(const QString&)), this, SLOT(OnPasswordChanged()));
	pForm->addRow(tr("Password:"), m_pPassword);

	m_pConfirm = new QLineEdit();
	m_pConfirm->setEchoMode(QLineEdit::Password);
	connect(m_pConfirm, SIGNAL(textChanged(const QString&)), this, SLOT(OnPasswordChanged()));
	pForm->addRow(tr("Repeat:"), m_pConfirm);

	m_pHint = new QLabel();
	m_pHint->setWordWrap(true);
	pMain->addWidget(m_pHint);

	m_pButtons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
	connect(m_pButtons, SIGNAL(accepted()), this, SLOT(accept()));
	connect(m_pButtons, SIGNAL(rejected()), this, SLOT(reject()));
	pMain->addWidget(m_pButtons);

	OnPasswordChanged();
	resize(460, sizeHint().height());
}

void CServerUserDialog::OnPasswordChanged()
{
	const bool bSetting = m_bNew || m_pSetPassword->isChecked();
	m_pPassword->setEnabled(bSetting);
	m_pConfirm->setEnabled(bSetting);
	UpdateHint();
}

void CServerUserDialog::UpdateHint()
{
	const bool bSetting = m_bNew || m_pSetPassword->isChecked();
	const QString Password = m_pPassword->text();

	QString Hint;
	bool bOk = !m_pName->text().trimmed().isEmpty();

	if (!bSetting)
	{
		Hint = m_Was.bSystemAccount
			? tr("This account is checked against the machine the server runs on.")
			: tr("The stored password is left unchanged.");
	}
	else if (Password.isEmpty())
	{
		//
		// Said as plainly as it can be, because it is the one place in this
		// dialog where leaving a field alone changes the meaning of the account
		// rather than leaving it as it was.
		//
		Hint = tr("With no password here, logging in as this name is checked against the "
		          "account of the same name on the machine the server runs on. The name "
		          "must be a real account there.");
	}
	else if (Password != m_pConfirm->text())
	{
		Hint = tr("The two passwords do not match.");
		bOk = false;
	}
	else
	{
		Hint = tr("Kept as a salted hash. It cannot be read back out of the server, "
		          "here or anywhere else - if it is forgotten it has to be set again.");
	}

	m_pHint->setText(Hint);
	m_pButtons->button(QDialogButtonBox::Ok)->setEnabled(bOk);
}

SServerUserRecord CServerUserDialog::GetUser() const
{
	SServerUserRecord User = m_Was;
	User.Name = m_pName->text().trimmed();
	User.bAdmin = m_pRole->currentData().toBool();
	User.bActions = m_pActions->isChecked();

	User.bSetPassword = m_bNew || m_pSetPassword->isChecked();
	User.NewPassword = User.bSetPassword ? m_pPassword->text() : QString();
	return User;
}
