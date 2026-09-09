#include "stdafx.h"
#include "UnlockDialog.h"
#include "TaskExplorer.h"
#include "../../MiscHelpers/Common/CredentialStore.h"
#include "../../MiscHelpers/Common/Crypto.h"

#include <QLineEdit>
#include <QLabel>
#include <QCheckBox>
#include <QFormLayout>
#include <QVBoxLayout>
#include <QDialogButtonBox>
#include <QPushButton>
#include <QMessageBox>

CUnlockDialog::CUnlockDialog(bool bCreating, QWidget* pParent)
	: QDialog(pParent), m_bCreating(bCreating)
{
	setWindowTitle(bCreating ? tr("Protect the saved keys") : tr("Saved keys"));

	QVBoxLayout* pMainLayout = new QVBoxLayout(this);

	QLabel* pIntro = new QLabel(bCreating
		? tr("The keys you save are kept encrypted. Choose a password for them - "
		     "it is the only thing that can open the file on another machine, and "
		     "it cannot be recovered.")
		: tr("Enter the password for the saved keys."));
	pIntro->setWordWrap(true);
	pMainLayout->addWidget(pIntro);

	QFormLayout* pForm = new QFormLayout();
	pMainLayout->addLayout(pForm);

	m_pPassword = new QLineEdit();
	m_pPassword->setEchoMode(QLineEdit::Password);
	connect(m_pPassword, SIGNAL(textChanged(const QString&)), this, SLOT(OnChanged()));
	pForm->addRow(tr("Password:"), m_pPassword);

	//
	// Only when it is being set. Confirming a password that already exists adds
	// a field whose only effect is to be typed twice.
	//
	m_pConfirm = new QLineEdit();
	m_pConfirm->setEchoMode(QLineEdit::Password);
	connect(m_pConfirm, SIGNAL(textChanged(const QString&)), this, SLOT(OnChanged()));
	pForm->addRow(tr("Again:"), m_pConfirm);
	if (!bCreating)
	{
		m_pConfirm->hide();
		if (QWidget* pLabel = pForm->labelForField(m_pConfirm))
			pLabel->hide();
	}

	//
	// Offered only where there is something to offer it with. On a platform with
	// no key store this would be a checkbox that silently did nothing.
	//
	m_pRemember = new QCheckBox(tr("Do not ask again on this machine"));
	m_pRemember->setToolTip(tr("Keeps the key where only this account on this machine can read it. "
	                           "The password still opens the file anywhere."));
	m_bPlatformOffered = CCrypto::PlatformSecretAvailable();
	m_pRemember->setChecked(bCreating && m_bPlatformOffered);
	m_pRemember->setVisible(m_bPlatformOffered);
	pMainLayout->addWidget(m_pRemember);

	m_pHint = new QLabel();
	m_pHint->setWordWrap(true);
	pMainLayout->addWidget(m_pHint);

	m_pButtonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
	connect(m_pButtonBox, SIGNAL(accepted()), this, SLOT(accept()));
	connect(m_pButtonBox, SIGNAL(rejected()), this, SLOT(reject()));
	pMainLayout->addWidget(m_pButtonBox);

	m_pPassword->setFocus();
	OnChanged();

	resize(420, sizeHint().height());
}

QString CUnlockDialog::GetPassword() const
{
	return m_pPassword->text();
}

bool CUnlockDialog::GetRemember() const
{
	//
	// A flag rather than isVisible(), which is false for every child of a closed
	// dialog - and this is only read once the dialog has closed. See the same
	// note in CConnectDialog::GetRemember.
	//
	return m_bPlatformOffered && m_pRemember->isChecked();
}

void CUnlockDialog::OnChanged()
{
	QString Problem;
	bool bBlocking = m_pPassword->text().isEmpty();

	if (m_bCreating)
	{
		//
		// A length rule and nothing else. Composition rules push people towards
		// one predictable substitution each and buy less than four more
		// characters would.
		//
		if (!m_pPassword->text().isEmpty() && m_pPassword->text().length() < 8)
		{
			Problem = tr("Use at least 8 characters.");
			bBlocking = true;
		}
		else if (m_pConfirm->text() != m_pPassword->text())
		{
			Problem = m_pConfirm->text().isEmpty() ? QString() : tr("The two do not match.");
			bBlocking = true;
		}
	}

	m_pHint->setText(Problem);
	m_pButtonBox->button(QDialogButtonBox::Ok)->setEnabled(!bBlocking);
}

bool CUnlockDialog::Open(QWidget* pParent)
{
	CCredentialStore* pStore = CCredentialStore::Instance();

	//
	// Nothing to ask if the platform can already open it, and nothing to ask
	// twice if something else opened it earlier this session.
	//
	if (pStore->TryUnlock())
		return true;

	QString Why;
	if (!pStore->IsAvailable(&Why))
	{
		CTaskExplorer::CheckErrors(QList<STATUS>()
			<< ERR(MH_CredStoreUnavailable, QVariantList() << Why));
		return false;
	}

	//
	// Before any password is asked for: a file this build cannot read will not
	// become readable by typing the right password, and finding that out after
	// three attempts is the worst way to learn it.
	//
	bool bCreating = !pStore->Exists();
	if (!bCreating)
	{
		const STATUS Probe = pStore->Probe();
		if (Probe.IsError() && Probe.GetMsgCode() == MH_CredStoreVersion)
		{
			//
			// Asked, not done. Replacing it loses every saved key, and the
			// alternative - going back to the version that wrote it - is a real
			// option that this program cannot offer.
			//
			if (QMessageBox::question(pParent, "TaskExplorer",
					CTaskExplorer::FormatError(Probe) + "\n\n"
					+ tr("Replace it with an empty one? Every saved key is lost, and each "
					     "machine has to be given its key again."),
					QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
				return false;

			STATUS Status = pStore->Discard();
			if (Status.IsError())
			{
				CTaskExplorer::CheckErrors(QList<STATUS>() << Status);
				return false;
			}
			bCreating = true;
		}
	}

	//
	// Three attempts, then it gives up rather than looping. Somebody who has
	// mistyped three times has forgotten it, and the fourth identical prompt
	// only makes that harder to say.
	//
	for (int Attempt = 0; Attempt < 3; Attempt++)
	{
		CUnlockDialog Dialog(bCreating, pParent);
		if (Dialog.exec() != QDialog::Accepted)
			return false;

		STATUS Status = bCreating
			? pStore->Create(Dialog.GetPassword(), Dialog.GetRemember())
			: pStore->Unlock(Dialog.GetPassword());

		if (!Status.IsError())
		{
			//
			// Asked at the prompt, applied after the store is open - it cannot
			// wrap a master key it does not have yet.
			//
			if (!bCreating && Dialog.GetRemember() && !pStore->HasPlatformUnlock())
				pStore->SetPlatformUnlock(true);
			return true;
		}

		if (Status.GetMsgCode() != MH_CredStoreBadPassword)
		{
			CTaskExplorer::CheckErrors(QList<STATUS>() << Status);
			return false;
		}

		QMessageBox::warning(pParent, "TaskExplorer",
			tr("That password did not open the saved keys."));
	}

	return false;
}
