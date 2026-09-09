#include "stdafx.h"
#include "PrincipalPicker.h"
#include "TaskExplorer.h"
#include "../API/SystemAPI.h"
#include "../../MiscHelpers/Common/Settings.h"

#include <QVBoxLayout>
#include <QHeaderView>

//
// The accounts every Windows machine has, by SID.
//
// Only the SIDs are constant; every name here is asked of the target, so a
// German machine says "Jeder" and an English one says "Everyone" - and a remote
// target says whatever it calls them, not whatever this machine would.
//
// These are listed because they are the ones people actually reach for and they
// are not in any of the enumerations below: Everyone and the logon-type groups
// are not accounts the SAM knows about.
//
static const char* g_WellKnownSids[] =
{
	"S-1-1-0",			// Everyone
	"S-1-5-18",			// SYSTEM
	"S-1-5-19",			// LOCAL SERVICE
	"S-1-5-20",			// NETWORK SERVICE
	"S-1-5-32-544",		// Administrators
	"S-1-5-32-545",		// Users
	"S-1-5-32-546",		// Guests
	"S-1-5-32-547",		// Power Users
	"S-1-5-11",			// Authenticated Users
	"S-1-5-4",			// INTERACTIVE
	"S-1-5-6",			// SERVICE
	"S-1-5-2",			// NETWORK
	"S-1-3-0",			// CREATOR OWNER
	"S-1-5-113",		// Local account
	"S-1-16-12288",		// High Mandatory Level
};

CPrincipalPicker::CPrincipalPicker(QWidget* parent)
	: QDialog(parent)
{
	setWindowTitle(tr("Select account"));

	QVBoxLayout* pLayout = new QVBoxLayout(this);

	m_pFilter = new QLineEdit();
	m_pFilter->setPlaceholderText(tr("Filter"));
	m_pFilter->setClearButtonEnabled(true);
	connect(m_pFilter, SIGNAL(textChanged(const QString&)), this, SLOT(OnFilter(const QString&)));
	pLayout->addWidget(m_pFilter);

	m_pList = new QTreeWidget();
	m_pList->setRootIsDecorated(false);
	m_pList->setUniformRowHeights(true);
	m_pList->setSelectionMode(QAbstractItemView::SingleSelection);
	m_pList->setHeaderLabels(QStringList() << tr("Name") << tr("Type") << tr("SID") << tr("Comment"));
	m_pList->setSortingEnabled(true);
	m_pList->sortByColumn(eName, Qt::AscendingOrder);
	connect(m_pList, SIGNAL(itemSelectionChanged()), this, SLOT(OnSelectionChanged()));
	connect(m_pList, SIGNAL(itemDoubleClicked(QTreeWidgetItem*, int)), this, SLOT(OnDoubleClicked()));
	pLayout->addWidget(m_pList, 1);

	pLayout->addWidget(new QLabel(tr("Or type a name the target will recognise, or a SID:")));
	m_pManual = new QLineEdit();
	m_pManual->setPlaceholderText(tr("DOMAIN\\user, or S-1-5-..."));
	connect(m_pManual, SIGNAL(textChanged(const QString&)), this, SLOT(OnSelectionChanged()));
	pLayout->addWidget(m_pManual);

	m_pStatus = new QLabel();
	m_pStatus->setWordWrap(true);
	pLayout->addWidget(m_pStatus);

	m_pButtons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
	connect(m_pButtons, SIGNAL(accepted()), this, SLOT(OnAccept()));
	connect(m_pButtons, SIGNAL(rejected()), this, SLOT(reject()));
	pLayout->addWidget(m_pButtons);

	resize(640, 520);
	restoreGeometry(theConf->GetBlob("PrincipalPicker/Window_Geometry"));
	m_pList->header()->restoreState(theConf->GetBlob("PrincipalPicker/Columns"));

	Load();
	OnSelectionChanged();
	m_pFilter->setFocus();
}

void CPrincipalPicker::Add(const QString& Name, const QString& Sid, const QString& Kind, const QString& Comment)
{
	if (Sid.isEmpty() || m_Seen.contains(Sid))
		return;
	m_Seen.insert(Sid);

	QTreeWidgetItem* pItem = new QTreeWidgetItem();
	pItem->setText(eName, Name.isEmpty() ? Sid : Name);
	pItem->setText(eKind, Kind);
	pItem->setText(eSid, Sid);
	pItem->setText(eComment, Comment);
	m_pList->addTopLevelItem(pItem);
}

void CPrincipalPicker::Load()
{
	m_pList->setSortingEnabled(false);

	for (size_t i = 0; i < sizeof(g_WellKnownSids) / sizeof(g_WellKnownSids[0]); i++)
	{
		QString Sid = QString::fromLatin1(g_WellKnownSids[i]);
		QString Name = theSystem->LookupNameBySid(Sid);

		//
		// A SID the target does not know is left out rather than shown as a
		// bare number: not every Windows build has every one of these.
		//
		if (!Name.isEmpty())
			Add(Name, Sid, tr("Well-known"));
	}

	foreach(const CSystemAPI::SPrincipal& P, theSystem->EnumSamUsers())
		Add(P.Name, P.SidString, tr("User"), P.Comment);

	foreach(const CSystemAPI::SPrincipal& P, theSystem->EnumSamGroups())
		Add(P.Name, P.SidString, tr("Group"), P.Comment);

	//
	// Accounts the security authority holds privileges for. Overlaps the two
	// above, which Add() takes care of.
	//
	foreach(const CSystemAPI::SPrincipal& P, theSystem->EnumLsaAccounts())
		Add(P.Name, P.SidString, tr("Account"), P.Comment);

	m_pList->setSortingEnabled(true);
	m_pList->resizeColumnToContents(eName);
	m_pList->resizeColumnToContents(eKind);
}

void CPrincipalPicker::OnFilter(const QString& Text)
{
	for (int i = 0; i < m_pList->topLevelItemCount(); i++)
	{
		QTreeWidgetItem* pItem = m_pList->topLevelItem(i);
		bool bMatch = Text.isEmpty()
			|| pItem->text(eName).contains(Text, Qt::CaseInsensitive)
			|| pItem->text(eSid).contains(Text, Qt::CaseInsensitive);
		pItem->setHidden(!bMatch);
	}
}

void CPrincipalPicker::OnSelectionChanged()
{
	//
	// What is typed wins over what is selected: someone who has started typing
	// a domain account does not mean the row still highlighted behind it.
	//
	QString Typed = m_pManual->text().trimmed();
	bool bHave = !Typed.isEmpty() || m_pList->currentItem() != NULL;

	m_pButtons->button(QDialogButtonBox::Ok)->setEnabled(bHave);
	m_pStatus->setText(QString());
}

void CPrincipalPicker::OnDoubleClicked()
{
	m_pManual->clear();
	OnAccept();
}

void CPrincipalPicker::OnAccept()
{
	QString Typed = m_pManual->text().trimmed();
	if (!Typed.isEmpty())
	{
		if (Typed.startsWith("S-1-", Qt::CaseInsensitive))
		{
			m_Sid = Typed;
			m_Name = theSystem->LookupNameBySid(m_Sid);

			//
			// A SID that resolves to nothing is still usable - an account can
			// be deleted and its entries left behind - so this is not an error.
			//
			if (m_Name.isEmpty())
				m_Name = m_Sid;
		}
		else
		{
			m_Sid = theSystem->LookupSidByName(Typed);
			if (m_Sid.isEmpty())
			{
				m_pStatus->setText(tr("<font color='red'>No account called '%1' could be found.</font>").arg(Typed));
				return;			// stay open so it can be corrected
			}
			m_Name = Typed;
		}
	}
	else
	{
		QTreeWidgetItem* pItem = m_pList->currentItem();
		if (!pItem)
			return;
		m_Sid = pItem->text(eSid);
		m_Name = pItem->text(eName);
	}

	theConf->SetBlob("PrincipalPicker/Window_Geometry", saveGeometry());
	theConf->SetBlob("PrincipalPicker/Columns", m_pList->header()->saveState());
	accept();
}
