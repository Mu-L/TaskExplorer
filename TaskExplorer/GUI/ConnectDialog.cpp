#include "stdafx.h"
#include "ConnectDialog.h"
#include "../../MiscHelpers/Common/IPC/IPCSocket.h"	// for IsNetworkAddress
#include "TaskExplorer.h"
#include "../API/Cluster.h"
#include "../../MiscHelpers/Common/CredentialStore.h"
#include "UnlockDialog.h"

#include <QComboBox>
#include <QLineEdit>
#include <QLabel>
#include <QFormLayout>
#include <QVBoxLayout>
#include <QDialogButtonBox>
#include <QPushButton>
#include <QStandardItemModel>
#include <QCheckBox>

CConnectDialog::CConnectDialog(QWidget* parent)
	: QDialog(parent)
{
	setWindowTitle(tr("Connect to a machine"));

	m_bNameFollowsAddress = true;

	QVBoxLayout* pMainLayout = new QVBoxLayout(this);
	QFormLayout* pForm = new QFormLayout();
	pMainLayout->addLayout(pForm);

	//
	// The machines already known, so that reconnecting to one is a choice and
	// not a retyped address. Only offered when there are any; an empty combo
	// with one placeholder entry is just a control that does nothing.
	//
	//
	// Asked again on the way in, so a machine that came up a moment ago is in
	// the list by the time somebody looks at it. Costs one multicast packet and
	// only happens if discovery is switched on at all.
	//
	if (theCluster)
		theCluster->RefreshDiscovery();

	//
	// Built empty and filled afterwards, because the list is not static while
	// this is open: a discovery answer arrives milliseconds after the query, by
	// which time a dialog that had read the targets once and drawn itself would
	// already be showing a list that is out of date. It rebuilds on
	// TargetsChanged instead, which is emitted for exactly that.
	//
	m_pSaved = new QComboBox();
	connect(m_pSaved, SIGNAL(currentIndexChanged(int)), this, SLOT(OnTargetPicked(int)));
	pForm->addRow(tr("Known machines:"), m_pSaved);
	m_pSavedLabel = pForm->labelForField(m_pSaved);

	if (theCluster)
		connect(theCluster, SIGNAL(TargetsChanged()), this, SLOT(FillTargets()));

	m_pAddress = new QLineEdit();

	//
	// Both forms in one field, because they are one thing: where the daemon is.
	// Which of the two a string is can be told from the string itself, so
	// making the user say so as well would be asking a question already
	// answered.
	//
	m_pAddress->setPlaceholderText(tr("Pipe name, or host:port"));
	connect(m_pAddress, SIGNAL(textChanged(const QString&)), this, SLOT(OnAddressChanged(const QString&)));
	pForm->addRow(tr("Address:"), m_pAddress);

	m_pName = new QLineEdit();
	m_pName->setPlaceholderText(tr("As shown in the tree"));
	connect(m_pName, &QLineEdit::textEdited, this, [this]() { m_bNameFollowsAddress = false; UpdateOk(); });
	pForm->addRow(tr("Display name:"), m_pName);

	//
	// Shown only for a network address, because only a network address can use
	// them - a pipe authenticates by the token of whoever opened it. Rows that
	// cannot apply are hidden rather than disabled: a greyed-out field still
	// asks to be understood, and there is nothing here to understand until the
	// address says host:port.
	//
	//
	// Two secrets, because they answer two questions - see SCredentials. The
	// transport key is the machine's and is the same for everybody who may reach
	// it; the name and password are the person's.
	//
	m_pPsk = new QLineEdit();
	m_pPsk->setEchoMode(QLineEdit::Password);
	m_pPsk->setPlaceholderText(tr("The machine's transport key, as set on the server"));
	m_pPsk->setToolTip(tr("Shared by everyone who may reach this machine. It secures the "
	                      "connection and grants nothing on its own."));
	connect(m_pPsk, SIGNAL(textChanged(const QString&)), this, SLOT(OnCredentialsChanged()));
	pForm->addRow(tr("Transport key:"), m_pPsk);
	m_pPskRow = m_pPsk;

	m_pUser = new QLineEdit();
	m_pUser->setPlaceholderText(tr("As configured on the server, or an account on it"));
	connect(m_pUser, SIGNAL(textChanged(const QString&)), this, SLOT(OnCredentialsChanged()));
	pForm->addRow(tr("User:"), m_pUser);
	m_pUserRow = m_pUser;

	m_pPassword = new QLineEdit();
	m_pPassword->setEchoMode(QLineEdit::Password);
	connect(m_pPassword, SIGNAL(textChanged(const QString&)), this, SLOT(OnCredentialsChanged()));
	pForm->addRow(tr("Password:"), m_pPassword);
	m_pPasswordRow = m_pPassword;

	//
	// Off unless the store already holds this machine, in which case leaving it
	// off would quietly drop a key the user has already chosen to keep.
	//
	//
	// "Credentials", not "this key": there are three things now - the machine's
	// transport key, and the user name and password that go with it - and the box
	// keeps all of them. Saying "key" would have somebody type their password
	// again every time and wonder what was saved.
	//
	m_pRemember = new QCheckBox(tr("Remember credentials"));
	m_pRemember->setToolTip(tr("Keeps the transport key, the user name and the password in an "
	                           "encrypted file, so this machine can be reconnected without typing "
	                           "them again."));
	connect(m_pRemember, SIGNAL(stateChanged(int)), this, SLOT(OnRemember()));
	pForm->addRow(QString(), m_pRemember);

	m_pHint = new QLabel();
	m_pHint->setWordWrap(true);
	pMainLayout->addWidget(m_pHint);

	m_pButtonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
	connect(m_pButtonBox, SIGNAL(accepted()), this, SLOT(accept()));
	connect(m_pButtonBox, SIGNAL(rejected()), this, SLOT(reject()));
	pMainLayout->addWidget(m_pButtonBox);

	//
	// The label beside a hidden field has to go with it, or the form keeps a
	// blank row where the field was. QFormLayout knows which label belongs to
	// which field; asking it is more durable than remembering.
	//
	if (QWidget* pLabel = pForm->labelForField(m_pPsk))
		m_pPskRow = pLabel;
	if (QWidget* pLabel = pForm->labelForField(m_pUser))
		m_pUserRow = pLabel;
	if (QWidget* pLabel = pForm->labelForField(m_pPassword))
		m_pPasswordRow = pLabel;
	m_pForm = pForm;

	//
	// The store is opened only if it is already there and the platform can do
	// it without asking. Raising a password prompt merely because somebody
	// opened the connect dialog would be a prompt for nothing in the common
	// case, where they are about to type a pipe name.
	//
	CCredentialStore::Instance()->TryUnlock();

	FillTargets();

	m_pAddress->setText("TaskExplorerServer");
	m_pAddress->selectAll();
	m_pAddress->setFocus();

	resize(400, sizeHint().height());
}

QString CConnectDialog::GetName() const
{
	//
	// The address stands in for a name that was not given. It is at least
	// something the user typed themselves, and it is unique, which is what
	// CCluster keys targets by.
	//
	const QString Name = m_pName->text().trimmed();
	return Name.isEmpty() ? m_pAddress->text().trimmed() : Name;
}

QString CConnectDialog::GetAddress() const
{
	return m_pAddress->text().trimmed();
}

SCredentials CConnectDialog::GetCredentials() const
{
	SCredentials Cred;
	if (!CIPCSocket::IsNetworkAddress(GetAddress()))
		return Cred;

	//
	// Taken as typed, and not decoded.
	//
	// This used to be read as hexadecimal, because the key file held hex and a
	// key that has to be retyped is better as an unambiguous alphabet. The
	// transport secret is hashed to length now, so it can be a passphrase - and
	// fromHex would have quietly dropped every character that was not a hex
	// digit, turning a mistyped passphrase into a different key rather than an
	// error.
	//
	// Whitespace at the ends goes, because it is invisible and nobody means it.
	// Whitespace inside stays: a passphrase may contain spaces on purpose.
	//
	Cred.Psk = m_pPsk->text().trimmed().toUtf8();
	Cred.User = m_pUser->text().trimmed().toUtf8();

	//
	// Not trimmed. A password is whatever was typed, including a trailing space
	// somebody chose - and the server compares bytes, not intentions.
	//
	Cred.Password = m_pPassword->text().toUtf8();
	return Cred;
}

bool CConnectDialog::GetRemember() const
{
	//
	// Asked about the address, not about the widget.
	//
	// isVisible() reads as "the box applies here" and is not: every child of a
	// closed dialog is invisible, and this is only ever read after the dialog
	// has closed. It returned false for a box the user had plainly ticked, and
	// the key was silently not saved - no error, nothing to see, just a machine
	// that asked for its key again next time.
	//
	return CIPCSocket::IsNetworkAddress(GetAddress()) && m_pRemember->isChecked();
}

void CConnectDialog::OnCredentialsChanged()
{
	UpdateOk();
}

void CConnectDialog::OnRemember()
{
	UpdateOk();
}

//
// Fills the identity and key in from the store, when it holds this machine.
//
// The key really is put in the field rather than left as "unchanged": the
// dialog has to hand a complete set of credentials to CCluster, and a field
// that showed something it did not hold would be a lie the OK button acts on.
// It is a password field, so what is on screen is dots either way.
//
void CConnectDialog::FillFromStore()
{
	CCredentialStore* pStore = CCredentialStore::Instance();
	if (!pStore->IsUnlocked())
		return;

	SCredentials Cred;
	if (!pStore->Get(GetName(), &Cred))
		return;

	m_pPsk->setText(QString::fromUtf8(Cred.Psk));
	m_pUser->setText(QString::fromUtf8(Cred.User));
	m_pPassword->setText(QString::fromUtf8(Cred.Password));
	m_pRemember->setChecked(true);
}

//
// The machines worth offering: everything the cluster knows, saved or found.
//
// Rebuilt from scratch rather than merged, because working out what changed
// would be more code than redoing it and the list is a handful of rows. What is
// preserved is the *selection* - somebody halfway through picking a machine
// should not have it taken away because an unrelated one answered a broadcast.
//
void CConnectDialog::FillTargets()
{
	const QString Current = m_pSaved->currentIndex() > 0
		? m_pSaved->currentData().toString() : QString();

	const QList<STarget> Targets = theCluster ? theCluster->GetTargets() : QList<STarget>();

	//
	// Blocked, or rebuilding the list would fire OnTargetPicked for whatever
	// happens to land at index zero and overwrite the address being typed.
	//
	m_pSaved->blockSignals(true);
	m_pSaved->clear();
	m_pSaved->addItem(tr("<new machine>"), QString());

	foreach(const STarget& Target, Targets)
	{
		//
		// One that is already up is listed but cannot be picked: connecting to
		// it again would do nothing, and an entry that silently does nothing is
		// worse than one that says why.
		//
		const bool bUp = !Target.pSystem.isNull();

		//
		// A found machine is marked as found. It is not something the user
		// configured, it is not saved, and it will be gone again when discovery
		// is switched off - so it should not look like the entries that persist.
		//
		QString Label = Target.Name;
		if (bUp)
			Label = tr("%1 (connected)").arg(Target.Name);
		else if (Target.State == STarget::eDiscovered)
			Label = tr("%1 - found on the network").arg(Target.Name);

		m_pSaved->addItem(Label, Target.Name);

		if (bUp) {
			QStandardItemModel* pModel = qobject_cast<QStandardItemModel*>(m_pSaved->model());
			if (pModel) {
				if (QStandardItem* pItem = pModel->item(m_pSaved->count() - 1))
					pItem->setEnabled(false);
			}
		}
	}

	if (!Current.isEmpty())
	{
		const int Index = m_pSaved->findData(Current);
		if (Index > 0)
			m_pSaved->setCurrentIndex(Index);
	}
	m_pSaved->blockSignals(false);

	//
	// A combo holding only "<new machine>" is a control that does nothing, so it
	// is not shown until there is something in it.
	//
	const bool bAny = m_pSaved->count() > 1;
	m_pSaved->setVisible(bAny);
	if (m_pSavedLabel)
		m_pSavedLabel->setVisible(bAny);
}

//
// Changes a machine that is already known, without connecting to it.
//
// The same form as connecting, because the questions are the same ones and a
// second form would answer them differently within a release or two. What
// differs is only what OK means.
//
// The credentials move with the name. A saved key is filed under the machine's
// name, so renaming without moving it would leave the key behind under a name
// nothing refers to any more - and the machine, under its new name, asking to be
// told its key again.
//
bool CConnectDialog::Edit(const QString& Name, QWidget* pParent)
{
	if (!theCluster)
		return false;

	QString Address;
	bool bFound = false;
	foreach(const STarget& Target, theCluster->GetTargets())
	{
		if (Target.Name != Name)
			continue;
		Address = Target.Address;
		bFound = true;
		break;
	}
	if (!bFound)
		return false;

	CConnectDialog Dialog(pParent);
	Dialog.setWindowTitle(tr("Edit a machine"));
	Dialog.m_EditingName = Name;

	//
	// The picker goes: it exists to choose *which* machine, and that is already
	// answered. Leaving it would offer a way to overwrite these fields with
	// another machine's and then save the result under this one's name.
	//
	if (Dialog.m_pSaved)
		Dialog.m_pSaved->setVisible(false);
	if (Dialog.m_pSavedLabel)
		Dialog.m_pSavedLabel->setVisible(false);

	//
	// Filled by hand rather than through the picker, which is now hidden.
	//
	Dialog.m_pAddress->setText(Address);
	Dialog.m_pName->setText(Name);
	Dialog.m_bNameFollowsAddress = false;
	Dialog.FillFromStore();
	Dialog.UpdateOk();

	if (Dialog.exec() != QDialog::Accepted)
		return false;

	const QString NewName = Dialog.GetName();
	if (!theCluster->UpdateTarget(Name, NewName, Dialog.GetAddress()))
	{
		QMessageBox::warning(pParent, "TaskExplorer",
			tr("\"%1\" could not be changed.").arg(Name));
		return false;
	}

	CCredentialStore* pStore = CCredentialStore::Instance();
	if (pStore->IsUnlocked())
	{
		//
		// Removed under the old name whatever happens next, so that a rename
		// never leaves two entries for one machine - and so that clearing the
		// box really does forget it.
		//
		if (NewName != Name)
			pStore->Remove(Name);

		if (Dialog.GetRemember())
			pStore->Set(NewName, Dialog.GetCredentials());
		else
			pStore->Remove(NewName);
	}

	return true;
}

void CConnectDialog::OnTargetPicked(int Index)
{
	if (!m_pSaved)
		return;

	const QString Name = m_pSaved->itemData(Index).toString();
	if (Name.isEmpty())
		return;

	foreach(const STarget& Target, theCluster->GetTargets())
	{
		if (Target.Name != Name)
			continue;

		//
		// Filled in rather than remembered: the fields stay editable, so a
		// saved machine that has moved can be corrected here instead of being
		// removed and added again.
		//
		m_pAddress->setText(Target.Address);
		m_pName->setText(Target.Name);
		m_bNameFollowsAddress = false;
		break;
	}

	//
	// After the address, because whether credentials apply at all depends on
	// what kind of address it turned out to be.
	//
	if (CIPCSocket::IsNetworkAddress(GetAddress()))
	{
		//
		// Asked for here and nowhere else. This is the one moment the user has
		// said which machine they mean, which is the only point at which a
		// password prompt is about something they just did.
		//
		if (!CCredentialStore::Instance()->IsUnlocked() && CCredentialStore::Instance()->Exists())
			CUnlockDialog::Open(this);
		FillFromStore();
	}

	UpdateOk();
}

void CConnectDialog::OnAddressChanged(const QString& Text)
{
	if (m_bNameFollowsAddress)
		m_pName->setText(Text.trimmed());
	UpdateOk();
}

void CConnectDialog::UpdateOk()
{
	const QString Address = GetAddress();
	const QString Name = GetName();

	const bool bNetwork = CIPCSocket::IsNetworkAddress(Address);
	m_pPsk->setVisible(bNetwork);
	m_pUser->setVisible(bNetwork);
	m_pPassword->setVisible(bNetwork);
	m_pPskRow->setVisible(bNetwork);
	m_pUserRow->setVisible(bNetwork);
	m_pPasswordRow->setVisible(bNetwork);
	m_pRemember->setVisible(bNetwork);

	QString Problem;
	bool bBlocking = Address.isEmpty() || Name.isEmpty();

	if (bNetwork)
	{
		const SCredentials Cred = GetCredentials();
		if (!Cred.IsValid())
		{
			//
			// Refused here rather than at the daemon, which cannot tell a
			// half-filled form from a guess and counts both against the rate
			// limit - and a refused login costs the next attempt a wait.
			//
			// The password is not checked for, only the two that cannot be
			// empty: a server account may legitimately have no password, and
			// refusing to try one would be this dialog overruling the machine
			// it is connecting to about its own accounts.
			//
			Problem = tr("A machine reached over the network needs a transport key and a user name.");
			bBlocking = true;
		}
	}

	if (theCluster)
	{
		//
		// A name is the key a target is stored and looked up under, so two
		// machines cannot share one. Said here rather than after connecting,
		// where CCluster::AddTarget would quietly keep the older entry and the
		// new address would be lost.
		//
		foreach(const STarget& Target, theCluster->GetTargets())
		{
			//
			// Its own name is not a clash with itself - see Edit().
			//
			if (!m_EditingName.isEmpty()
				&& Target.Name.compare(m_EditingName, Qt::CaseInsensitive) == 0)
				continue;

			if (Target.Name.compare(Name, Qt::CaseInsensitive) != 0)
				continue;

			if (!Target.pSystem.isNull()) {
				Problem = tr("%1 is already connected.").arg(Target.Name);
				bBlocking = true;
			}
			else if (Target.Address != Address)
				Problem = tr("%1 is already known at %2; its address will be updated.").arg(Target.Name).arg(Target.Address);
			break;
		}
	}

	if (Problem.isEmpty() && bNetwork)
	{
		Problem = m_pRemember->isChecked()
			? tr("The key will be kept in an encrypted file on this machine.")
			: tr("The key is used for this connection only and is not saved.");
	}

	if (Problem.isEmpty() && Address.isEmpty())
		Problem = tr("An address is needed to reach the machine.");

	m_pHint->setText(Problem);
	m_pButtonBox->button(QDialogButtonBox::Ok)->setEnabled(!bBlocking);
}
