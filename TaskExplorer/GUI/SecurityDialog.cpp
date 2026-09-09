#include "stdafx.h"
#include "SecurityDialog.h"
#include "TaskExplorer.h"
#include "TaskStrings.h"
#include "PrincipalPicker.h"
#include "../API/SystemAPI.h"
#include "../../MiscHelpers/Common/Settings.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QHeaderView>
#include <QInputDialog>
#include <QMessageBox>

//
// The rights list shows the general rights first - the handful most people
// think in, like "Full control" - then the individual bits behind them. Both
// come from the target; nothing here knows what a process or a service can do.
//

CSecurityDialog::CSecurityDialog(const CSecurityEditablePtr& pObject, QWidget* parent)
	: QDialog(parent), m_pObject(pObject), m_bDirty(false), m_bFilling(false), m_bReadOnly(false)
{
	setWindowTitle(tr("Permissions"));
	setAttribute(Qt::WA_DeleteOnClose);

	QVBoxLayout* pLayout = new QVBoxLayout(this);

	m_pHeader = new QLabel();
	pLayout->addWidget(m_pHeader);

	//
	// The owner sits on its own row with the control that changes it, because
	// changing it is a different privilege from anything in the list below and
	// worth keeping visibly apart.
	//
	QHBoxLayout* pOwnerLayout = new QHBoxLayout();
	pOwnerLayout->setContentsMargins(0, 0, 0, 0);

	m_pOwner = new QLabel();
	m_pOwner->setTextInteractionFlags(Qt::TextSelectableByMouse);
	pOwnerLayout->addWidget(m_pOwner, 1);

	m_pOwnerChange = new QPushButton(tr("Change..."));
	connect(m_pOwnerChange, SIGNAL(clicked()), this, SLOT(OnChangeOwner()));
	pOwnerLayout->addWidget(m_pOwnerChange);

	pLayout->addLayout(pOwnerLayout);

	QSplitter* pSplitter = new QSplitter(Qt::Vertical);
	pLayout->addWidget(pSplitter, 1);

	//
	// Principals.
	//
	QWidget* pTop = new QWidget();
	QVBoxLayout* pTopLayout = new QVBoxLayout(pTop);
	pTopLayout->setContentsMargins(0, 0, 0, 0);

	//
	// The two lists are edited identically; the tab only changes which one is
	// on screen and what the checkbox columns mean.
	//
	m_pLists = new QTabBar();
	m_pLists->addTab(tr("Permissions"));
	m_pLists->addTab(tr("Auditing"));
	m_pLists->setExpanding(false);
	connect(m_pLists, SIGNAL(currentChanged(int)), this, SLOT(OnListChanged(int)));
	pTopLayout->addWidget(m_pLists);

	pTopLayout->addWidget(new QLabel(tr("Group or user names:")));

	m_pPrincipals = new QTreeWidget();
	m_pPrincipals->setRootIsDecorated(false);
	m_pPrincipals->setUniformRowHeights(true);
	m_pPrincipals->setHeaderLabels(QStringList()
		<< tr("Name") << tr("Type") << tr("Inherited") << tr("SID"));
	m_pPrincipals->setSelectionMode(QAbstractItemView::SingleSelection);
	connect(m_pPrincipals, SIGNAL(itemSelectionChanged()), this, SLOT(OnPrincipalChanged()));
	pTopLayout->addWidget(m_pPrincipals);

	QHBoxLayout* pBtns = new QHBoxLayout();
	pBtns->addStretch();
	m_pAdd = new QPushButton(tr("Add..."));
	connect(m_pAdd, SIGNAL(clicked()), this, SLOT(OnAdd()));
	pBtns->addWidget(m_pAdd);
	m_pRemove = new QPushButton(tr("Remove"));
	connect(m_pRemove, SIGNAL(clicked()), this, SLOT(OnRemove()));
	pBtns->addWidget(m_pRemove);
	pTopLayout->addLayout(pBtns);

	pSplitter->addWidget(pTop);

	//
	// Rights of whoever is selected above.
	//
	QWidget* pBottom = new QWidget();
	QVBoxLayout* pBottomLayout = new QVBoxLayout(pBottom);
	pBottomLayout->setContentsMargins(0, 0, 0, 0);

	//
	// Success and failure are properties of the audit entry as a whole - one
	// entry logs one or both - so they sit above the rows rather than in them.
	//
	m_pAuditFlags = new QWidget();
	QHBoxLayout* pAuditLayout = new QHBoxLayout(m_pAuditFlags);
	pAuditLayout->setContentsMargins(0, 0, 0, 0);
	m_pAuditSuccess = new QCheckBox(tr("Audit successful access"));
	connect(m_pAuditSuccess, SIGNAL(toggled(bool)), this, SLOT(OnAuditFlagChanged()));
	pAuditLayout->addWidget(m_pAuditSuccess);
	m_pAuditFailure = new QCheckBox(tr("Audit failed access"));
	connect(m_pAuditFailure, SIGNAL(toggled(bool)), this, SLOT(OnAuditFlagChanged()));
	pAuditLayout->addWidget(m_pAuditFailure);
	pAuditLayout->addStretch();
	m_pAuditFlags->setVisible(false);
	pBottomLayout->addWidget(m_pAuditFlags);

	pBottomLayout->addWidget(new QLabel(tr("Permissions:")));

	m_pRights = new QTreeWidget();
	m_pRights->setRootIsDecorated(false);
	m_pRights->setUniformRowHeights(true);
	m_pRights->setHeaderLabels(QStringList() << tr("Permission") << tr("Allow") << tr("Deny"));
	m_pRights->header()->setSectionResizeMode(ePermission, QHeaderView::Stretch);
	connect(m_pRights, SIGNAL(itemChanged(QTreeWidgetItem*, int)), this, SLOT(OnRightToggled(QTreeWidgetItem*, int)));
	pBottomLayout->addWidget(m_pRights);

	pSplitter->addWidget(pBottom);
	pSplitter->setStretchFactor(0, 1);
	pSplitter->setStretchFactor(1, 2);

	m_pStatus = new QLabel();
	m_pStatus->setWordWrap(true);
	pLayout->addWidget(m_pStatus);

	m_pButtons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel | QDialogButtonBox::Apply);
	connect(m_pButtons, SIGNAL(accepted()), this, SLOT(OnOk()));
	connect(m_pButtons, SIGNAL(rejected()), this, SLOT(reject()));
	connect(m_pButtons->button(QDialogButtonBox::Apply), SIGNAL(clicked()), this, SLOT(OnApply()));
	pLayout->addWidget(m_pButtons);

	//
	// The layout's own hint is far too small for two lists side by side; this
	// is only a starting size, and whatever the window is left at is restored.
	//
	resize(560, 620);
	restoreGeometry(theConf->GetBlob("SecurityDialog/Window_Geometry"));
	if (m_pPrincipals->header()->count() > 0)
		m_pPrincipals->header()->restoreState(theConf->GetBlob("SecurityDialog/Principals_Columns"));

	Load();
}

CSecurityDialog::~CSecurityDialog()
{
	theConf->SetBlob("SecurityDialog/Window_Geometry", saveGeometry());
	theConf->SetBlob("SecurityDialog/Principals_Columns", m_pPrincipals->header()->saveState());
}

void CSecurityDialog::SetStatus(const QString& Text, bool bError)
{
	m_pStatus->setText(Text);
	m_pStatus->setStyleSheet(bError ? "color: red;" : "");
}

void CSecurityDialog::Load()
{
	if (!m_pObject)
		return;

	setWindowTitle(tr("Permissions for %1").arg(::GetSecurityObjectName(m_pObject)));
	m_pHeader->setText(tr("<b>%1</b> (%2)").arg(::GetSecurityObjectName(m_pObject)).arg(::GetSecurityObjectType(m_pObject->GetTypeName())));

	m_Rights = m_pObject->GetAccessRights();

	m_Info = SSecurityInfo();
	STATUS Status = m_pObject->GetSecurity(m_Info, true);
	if (Status.IsError())
	{
		SetStatus(tr("Could not read the security descriptor: %1").arg(CTaskExplorer::FormatError(Status)), true);
		m_pButtons->button(QDialogButtonBox::Ok)->setEnabled(false);
		m_pButtons->button(QDialogButtonBox::Apply)->setEnabled(false);
		m_pAdd->setEnabled(false);
		m_pRemove->setEnabled(false);
		m_pOwnerChange->setEnabled(false);
		return;
	}

	ShowOwner();

	//
	// Entries this dialog cannot describe mean it must not write the list back,
	// so it becomes read-only rather than quietly dropping them. The backend
	// refuses too - this is the half that explains why.
	//
	bool bReadOnly = m_Info.SkippedAces > 0;
	if (bReadOnly)
	{
		SetStatus(tr("This object has %n access control entr(y/ies) of a kind this dialog does not understand - "
			"object or callback entries. They are not shown, and saving would discard them, so this is "
			"read-only.", "", m_Info.SkippedAces), true);
	}
	//
	// An absent DACL is not an empty one: it grants everyone everything. Saying
	// so is worth more than showing an empty list that looks locked down.
	//
	else if (!m_Info.bDaclPresent)
		SetStatus(tr("This object has no access control list, which grants everyone full access."));
	else if (m_Info.Dacl.isEmpty())
		SetStatus(tr("The access control list is empty, which denies everyone."));
	else
		SetStatus(QString());

	//
	// A list that cannot be rewritten does not stop the owner being changed:
	// the two are written independently, so Apply comes back the moment there
	// is an owner change to apply.
	//
	m_pButtons->button(QDialogButtonBox::Apply)->setEnabled(!bReadOnly);
	m_pAdd->setEnabled(!IsListReadOnly());
	m_pOwnerChange->setEnabled(true);
	m_bReadOnly = bReadOnly;

	FillPrincipals();
}

bool CSecurityDialog::IsAuditing() const
{
	return m_pLists->currentIndex() == 1;
}

QList<SAce>& CSecurityDialog::CurrentList()
{
	return IsAuditing() ? m_Info.Sacl : m_Info.Dacl;
}

const QList<SAce>& CSecurityDialog::CurrentList() const
{
	return IsAuditing() ? m_Info.Sacl : m_Info.Dacl;
}

bool CSecurityDialog::IsListReadOnly() const
{
	return IsAuditing() ? (m_Info.SkippedAuditAces > 0) : m_bReadOnly;
}

//
// Switching lists is a fresh start for the panels below, but not for anything
// already edited - both lists are applied together.
//
void CSecurityDialog::OnListChanged(int Index)
{
	Q_UNUSED(Index);

	m_pAuditFlags->setVisible(IsAuditing());

	//
	// An audit entry carries one mask and logs success, failure or both - the
	// choice belongs to the entry, not to each right - so the second column
	// has nothing to say there.
	//
	m_pRights->setHeaderLabels(IsAuditing()
		? (QStringList() << tr("Permission") << tr("Audit") << QString())
		: (QStringList() << tr("Permission") << tr("Allow") << tr("Deny")));
	m_pRights->setColumnHidden(eDeny, IsAuditing());

	if (IsAuditing() && !m_Info.bSaclPresent && m_Info.Sacl.isEmpty())
	{
		SetStatus(theSystem->HasCapability(CSystemAPI::eCapAuditEditor)
			? tr("Nothing is being audited on this object.")
			: tr("The audit list could not be read - that needs the audit privilege, which is only "
				 "held when running elevated."));
	}
	else
		SetStatus(QString());

	m_pAdd->setEnabled(!IsListReadOnly());
	FillPrincipals();
}

void CSecurityDialog::ShowOwner()
{
	QString Name = m_Info.OwnerName.isEmpty() ? m_Info.OwnerSid : m_Info.OwnerName;
	if (Name.isEmpty())
		Name = tr("(none)");

	//
	// A pending change is marked rather than shown as fact - it is not the
	// owner until it has been applied and read back.
	//
	m_pOwner->setText(m_Info.bSetOwner
		? tr("Owner: %1 (not yet applied)").arg(Name)
		: tr("Owner: %1").arg(Name));
}

//
// How an entry reads in the Type column: allow or deny for an access entry,
// what is being logged for an audit one.
//
static QString CSecurityDialog__TypeText(const SAce& Ace)
{
	if (Ace.Type != SAce::eAudit)
		return Ace.Type == SAce::eDeny ? CSecurityDialog::tr("Deny") : CSecurityDialog::tr("Allow");

	bool bSuccess = (Ace.Flags & SAce::eAuditSuccess) != 0;
	bool bFailure = (Ace.Flags & SAce::eAuditFailure) != 0;

	if (bSuccess && bFailure)	return CSecurityDialog::tr("Success and failure");
	if (bSuccess)				return CSecurityDialog::tr("Success");
	if (bFailure)				return CSecurityDialog::tr("Failure");
	return CSecurityDialog::tr("Nothing");
}

void CSecurityDialog::FillPrincipals()
{
	int Selected = m_pPrincipals->currentIndex().row();

	m_pPrincipals->blockSignals(true);
	m_pPrincipals->clear();
	for (int i = 0; i < CurrentList().size(); i++)
	{
		const SAce& Ace = CurrentList()[i];

		QTreeWidgetItem* pItem = new QTreeWidgetItem();
		pItem->setText(0, Ace.Name.isEmpty() ? Ace.Sid : Ace.Name);
		pItem->setText(1, CSecurityDialog__TypeText(Ace));
		pItem->setText(2, Ace.IsInherited() ? tr("Yes") : tr("No"));
		pItem->setText(3, Ace.Sid);
		pItem->setData(0, Qt::UserRole, i);

		//
		// Inherited entries come from the parent object, so they are shown but
		// cannot be edited here - changing one means changing the parent.
		//
		if (Ace.IsInherited())
			pItem->setForeground(0, QBrush(Qt::gray));

		m_pPrincipals->addTopLevelItem(pItem);
	}

	if (Selected >= 0 && Selected < m_pPrincipals->topLevelItemCount())
		m_pPrincipals->setCurrentItem(m_pPrincipals->topLevelItem(Selected));
	else if (m_pPrincipals->topLevelItemCount() > 0)
		m_pPrincipals->setCurrentItem(m_pPrincipals->topLevelItem(0));

	m_pPrincipals->blockSignals(false);
	OnPrincipalChanged();
}

int CSecurityDialog::CurrentAce() const
{
	QTreeWidgetItem* pItem = m_pPrincipals->currentItem();
	if (!pItem)
		return -1;
	int Index = pItem->data(0, Qt::UserRole).toInt();
	return (Index >= 0 && Index < CurrentList().size()) ? Index : -1;
}

void CSecurityDialog::FillRights()
{
	m_bFilling = true;
	m_pRights->clear();

	int Index = CurrentAce();
	quint32 Mask = (Index >= 0) ? CurrentList()[Index].Mask : 0;
	bool bAllow = (Index >= 0) && CurrentList()[Index].Type != SAce::eDeny;
	bool bEditable = (Index >= 0) && !IsListReadOnly() && !CurrentList()[Index].IsInherited();

	foreach(const SAccessRight& Right, m_Rights)
	{
		//
		// Aliases that are neither general nor specific describe the same bits
		// under another name; listing them would double every row.
		//
		if (!Right.bGeneral && !Right.bSpecific)
			continue;

		QTreeWidgetItem* pItem = new QTreeWidgetItem();
		pItem->setText(ePermission, ::GetAccessRightName(Right.Right));
		pItem->setData(ePermission, Qt::UserRole, Right.Access);

		//
		// A right counts as granted when every bit it stands for is present.
		// Partially present is left unchecked rather than shown as granted.
		//
		bool bHas = Right.Access != 0 && (Mask & Right.Access) == Right.Access;

		if (IsAuditing())
			pItem->setCheckState(eAllow, bHas ? Qt::Checked : Qt::Unchecked);
		else
		{
			pItem->setCheckState(eAllow, (bHas && bAllow) ? Qt::Checked : Qt::Unchecked);
			pItem->setCheckState(eDeny, (bHas && !bAllow) ? Qt::Checked : Qt::Unchecked);
		}

		if (!bEditable)
			pItem->setFlags(pItem->flags() & ~Qt::ItemIsEnabled);

		if (Right.bGeneral)
		{
			QFont Font = pItem->font(ePermission);
			Font.setBold(true);
			pItem->setFont(ePermission, Font);
		}

		m_pRights->addTopLevelItem(pItem);
	}

	m_pRights->resizeColumnToContents(eAllow);
	m_pRights->resizeColumnToContents(eDeny);
	m_bFilling = false;
}

void CSecurityDialog::OnPrincipalChanged()
{
	int Index = CurrentAce();
	bool bEditable = Index >= 0 && !IsListReadOnly() && !CurrentList()[Index].IsInherited();

	m_pRemove->setEnabled(bEditable);

	if (IsAuditing())
	{
		m_bFilling = true;
		quint32 Flags = (Index >= 0) ? CurrentList()[Index].Flags : 0;
		m_pAuditSuccess->setChecked((Flags & SAce::eAuditSuccess) != 0);
		m_pAuditFailure->setChecked((Flags & SAce::eAuditFailure) != 0);
		m_pAuditSuccess->setEnabled(bEditable);
		m_pAuditFailure->setEnabled(bEditable);
		m_bFilling = false;
	}

	FillRights();
}

void CSecurityDialog::OnRightToggled(QTreeWidgetItem* pItem, int Column)
{
	if (m_bFilling || (Column != eAllow && Column != eDeny))
		return;

	int Index = CurrentAce();
	if (Index < 0 || IsListReadOnly() || CurrentList()[Index].IsInherited())
		return;

	quint32 Bits = pItem->data(ePermission, Qt::UserRole).toUInt();
	bool bChecked = pItem->checkState(Column) == Qt::Checked;

	SAce& Ace = CurrentList()[Index];

	if (!IsAuditing())
	{
		//
		// One access entry is either an allow or a deny; ticking the other
		// column turns the whole entry around rather than creating a second
		// one. Add a second principal if both are wanted.
		//
		bool bWantAllow = (Column == eAllow);
		if (bChecked && ((Ace.Type == SAce::eDeny) == bWantAllow))
		{
			Ace.Type = bWantAllow ? SAce::eAllow : SAce::eDeny;
			Ace.Mask = 0;
		}
	}

	if (bChecked)
		Ace.Mask |= Bits;
	else
		Ace.Mask &= ~Bits;

	m_bDirty = true;

	UpdateRightChecks();
	UpdatePrincipalRow(Index);
}

//
// Re-tick the permission rows from the entry's mask without touching the items
// themselves, so nothing is destroyed while a signal from one is in flight.
//
void CSecurityDialog::UpdateRightChecks()
{
	int Index = CurrentAce();
	quint32 Mask = (Index >= 0) ? CurrentList()[Index].Mask : 0;
	bool bAllow = (Index >= 0) && CurrentList()[Index].Type != SAce::eDeny;

	m_bFilling = true;
	for (int i = 0; i < m_pRights->topLevelItemCount(); i++)
	{
		QTreeWidgetItem* pItem = m_pRights->topLevelItem(i);
		quint32 Bits = pItem->data(ePermission, Qt::UserRole).toUInt();
		bool bHas = Bits != 0 && (Mask & Bits) == Bits;

		if (IsAuditing())
			pItem->setCheckState(eAllow, bHas ? Qt::Checked : Qt::Unchecked);
		else
		{
			pItem->setCheckState(eAllow, (bHas && bAllow) ? Qt::Checked : Qt::Unchecked);
			pItem->setCheckState(eDeny, (bHas && !bAllow) ? Qt::Checked : Qt::Unchecked);
		}
	}
	m_bFilling = false;
}

void CSecurityDialog::UpdatePrincipalRow(int Index)
{
	if (Index < 0 || Index >= m_pPrincipals->topLevelItemCount())
		return;

	const SAce& Ace = CurrentList()[Index];
	m_pPrincipals->topLevelItem(Index)->setText(1,
		Ace.Type == SAce::eDeny ? tr("Deny") : tr("Allow"));
}

//
// Taking an object over needs WRITE_OWNER, which is a different and higher
// permission than editing the list - so this is applied like any other change
// and the failure, when it comes, says so.
//
//
// An audit entry that logs neither success nor failure would log nothing, so
// clearing both is treated as removing the entry's reason to exist and is
// reported rather than silently kept.
//
void CSecurityDialog::OnAuditFlagChanged()
{
	if (m_bFilling)
		return;

	int Index = CurrentAce();
	if (Index < 0 || IsListReadOnly() || CurrentList()[Index].IsInherited())
		return;

	SAce& Ace = CurrentList()[Index];
	Ace.Flags &= ~(SAce::eAuditSuccess | SAce::eAuditFailure);
	if (m_pAuditSuccess->isChecked())
		Ace.Flags |= SAce::eAuditSuccess;
	if (m_pAuditFailure->isChecked())
		Ace.Flags |= SAce::eAuditFailure;

	m_bDirty = true;
	UpdatePrincipalRow(Index);

	if (!m_pAuditSuccess->isChecked() && !m_pAuditFailure->isChecked())
		SetStatus(tr("This entry now logs nothing. Tick success or failure, or remove it."));
	else
		SetStatus(QString());
}

void CSecurityDialog::OnChangeOwner()
{
	CPrincipalPicker Picker(this);
	if (Picker.exec() != QDialog::Accepted)
		return;

	QString Sid = Picker.GetSid();
	if (Sid.isEmpty() || Sid == m_Info.OwnerSid)
		return;

	m_Info.OwnerSid = Sid;
	m_Info.OwnerName = Picker.GetName().isEmpty() ? Sid : Picker.GetName();
	m_Info.bSetOwner = true;
	m_bDirty = true;

	ShowOwner();
	m_pButtons->button(QDialogButtonBox::Apply)->setEnabled(true);
	SetStatus(tr("Owner will be set to %1 when applied.").arg(m_Info.OwnerName));
}

void CSecurityDialog::OnAdd()
{
	CPrincipalPicker Picker(this);
	if (Picker.exec() != QDialog::Accepted)
		return;

	QString Sid = Picker.GetSid();
	if (Sid.isEmpty())
		return;

	//
	// Adding someone who is already listed just selects them: a second entry
	// with the same SID and the same allow/deny sense does nothing that
	// editing the first one would not.
	//
	for (int i = 0; i < CurrentList().size(); i++)
	{
		if (CurrentList()[i].Sid == Sid && !CurrentList()[i].IsInherited()
			&& CurrentList()[i].Type == (IsAuditing() ? SAce::eAudit : SAce::eAllow))
		{
			m_pPrincipals->setCurrentItem(m_pPrincipals->topLevelItem(i));
			SetStatus(tr("%1 is already listed.").arg(CurrentList()[i].Name));
			return;
		}
	}

	//
	// A new audit entry logs successes by default; one that logs neither would
	// do nothing at all.
	//
	SAce Ace(IsAuditing() ? SAce::eAudit : SAce::eAllow, Sid, 0);
	if (IsAuditing())
		Ace.Flags |= SAce::eAuditSuccess;
	Ace.Name = Picker.GetName().isEmpty() ? Sid : Picker.GetName();
	CurrentList().append(Ace);
	if (IsAuditing()) m_Info.bSaclPresent = true; else m_Info.bDaclPresent = true;
	m_bDirty = true;

	FillPrincipals();
	m_pPrincipals->setCurrentItem(m_pPrincipals->topLevelItem(CurrentList().size() - 1));
	SetStatus(tr("%1 added with no permissions - tick what it should be allowed.").arg(Ace.Name));
}

void CSecurityDialog::OnRemove()
{
	int Index = CurrentAce();
	if (Index < 0 || CurrentList()[Index].IsInherited())
		return;

	CurrentList().removeAt(Index);
	m_bDirty = true;
	FillPrincipals();
}

//
// Everything that writes goes through here, so the confirmation for taking an
// object over is asked once and cannot be bypassed by using OK instead.
//
bool CSecurityDialog::Save()
{
	if (!m_bDirty)
		return true;

	if (m_Info.bSetOwner)
	{
		//
		// Unlike a permission change, handing an object to someone else can
		// take away the very right needed to hand it back.
		//
		if (QMessageBox::question(this, "TaskExplorer",
				tr("Make %1 the owner of %2?\n\nChanging an owner can remove your own ability to "
				   "change it back.").arg(m_Info.OwnerName).arg(::GetSecurityObjectName(m_pObject)),
				QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
			return false;
	}

	STATUS Status = m_pObject->SetSecurity(m_Info, true);
	if (Status.IsError())
	{
		SetStatus(tr("Could not apply the changes: %1").arg(CTaskExplorer::FormatError(Status)), true);
		return false;
	}

	m_bDirty = false;
	return true;
}

void CSecurityDialog::OnApply()
{
	if (!Save())
		return;

	//
	// Read it back rather than trusting what was sent: the object may have
	// canonicalised the list, and inherited entries reappear.
	//
	Load();
	SetStatus(tr("Changes applied."));
}

void CSecurityDialog::OnOk()
{
	if (!Save())
		return;			// stay open so the message can be read
	accept();
}
