#include "stdafx.h"
#include "SecurityExplorer.h"
#include "TaskExplorer.h"
#include "../API/SystemAPI.h"
#include "../../MiscHelpers/Common/Settings.h"

CSecurityExplorer::CSecurityExplorer(QWidget *parent)
	: QMainWindow(parent)
{
	this->setWindowTitle(tr("Security Explorer"));

	QWidget* centralWidget = new QWidget();
	ui.setupUi(centralWidget);
	this->setCentralWidget(centralWidget);

	connect(ui.btnEditPolSec, SIGNAL(pressed()), this, SLOT(OnSecPolEdit()));
	connect(ui.accounts, SIGNAL(itemDoubleClicked(QTreeWidgetItem*, int)), this, SLOT(OnAccount(QTreeWidgetItem*)));
	connect(ui.users, SIGNAL(itemDoubleClicked(QTreeWidgetItem*, int)), this, SLOT(OnUser(QTreeWidgetItem*)));
	connect(ui.groups, SIGNAL(itemDoubleClicked(QTreeWidgetItem*, int)), this, SLOT(OnGroupe(QTreeWidgetItem*)));

	
	//connect(ui.buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
	connect(ui.buttonBox, SIGNAL(rejected()), this, SLOT(reject()));

	restoreGeometry(theConf->GetBlob("SecExplorerWindow/Window_Geometry"));

	LoadAccounts();
	LoadPriviledges();
	LoadSessions();
	LoadUsers();
	LoadGroups();
	LoadCredentials();
}

CSecurityExplorer::~CSecurityExplorer()
{
	theConf->SetBlob("SecExplorerWindow/Window_Geometry",saveGeometry());
}

void CSecurityExplorer::closeEvent(QCloseEvent *e)
{
	this->deleteLater();
}

/*void CSecurityExplorer::accept()
{
	this->close();
}*/

void CSecurityExplorer::reject()
{
	this->close();
}

//
// Everything below fills tree widgets from lists the system hands over; the
// native enumeration is in API/Windows/WinSecurity.cpp so that these can one
// day describe a machine other than this one.
//
static QTreeWidgetItem* AddPrincipal(QTreeWidget* pTree, const CSystemAPI::SPrincipal& Principal, const QString& Unknown)
{
	QTreeWidgetItem* pItem = new QTreeWidgetItem();
	pItem->setData(0, Qt::UserRole, (quint64)Principal.RelativeId);
	pItem->setText(0, Principal.Name.isEmpty() ? Unknown : Principal.Name);
	pItem->setText(1, Principal.SidString.isEmpty() ? Unknown : Principal.SidString);
	pItem->setData(1, Qt::UserRole, Principal.Sid);
	pTree->addTopLevelItem(pItem);
	return pItem;
}

void CSecurityExplorer::LoadAccounts()
{
	ui.accounts->clear();

	foreach(const CSystemAPI::SPrincipal& Principal, theSystem->EnumLsaAccounts())
		AddPrincipal(ui.accounts, Principal, tr("unknown"));
}

void CSecurityExplorer::LoadPriviledges()
{
	// the privilege list was never wired up; see EnumLsaAccounts for the shape
}

void CSecurityExplorer::LoadSessions()
{
	ui.sessions->clear();

	foreach(const CSystemAPI::SPrincipal& Principal, theSystem->EnumLogonSessions())
	{
		QTreeWidgetItem* pItem = AddPrincipal(ui.sessions, Principal, tr("unknown"));
		pItem->setText(2, tr("0x%1").arg(Principal.LogonId, 0, 16));
	}
}

void CSecurityExplorer::LoadUsers()
{
	ui.users->clear();

	foreach(const CSystemAPI::SPrincipal& Principal, theSystem->EnumSamUsers())
		AddPrincipal(ui.users, Principal, tr("unknown"));
}

void CSecurityExplorer::LoadGroups()
{
	ui.groups->clear();

	foreach(const CSystemAPI::SPrincipal& Principal, theSystem->EnumSamGroups())
	{
		QTreeWidgetItem* pItem = AddPrincipal(ui.groups, Principal, tr("unknown"));
		pItem->setText(2, Principal.Comment);
	}
}

void CSecurityExplorer::LoadCredentials()
{
	ui.credential->clear();

	foreach(const CSystemAPI::SCredential& Credential, theSystem->EnumCredentials())
	{
		QTreeWidgetItem* pItem = new QTreeWidgetItem();
		pItem->setText(0, Credential.Target);
		pItem->setText(1, Credential.User);
		pItem->setText(2, Credential.Comment);
		pItem->setText(3, QDateTime::fromSecsSinceEpoch(Credential.LastWritten).toString("dd.MM.yyyy hh:mm:ss"));
		ui.credential->addTopLevelItem(pItem);
	}
}

void CSecurityExplorer::OnSecPolEdit()
{
	CTaskExplorer::ShowSecurity(theSystem->GetSecurityObject(CSystemAPI::eSecLsaPolicy, tr("Local LSA Policy")), this);
}

void CSecurityExplorer::OnAccount(QTreeWidgetItem* pItem)
{
	CTaskExplorer::ShowSecurity(theSystem->GetSecurityObject(CSystemAPI::eSecLsaAccount, pItem->text(0),
		pItem->data(1, Qt::UserRole).toByteArray()), this);
}

void CSecurityExplorer::OnUser(QTreeWidgetItem* pItem)
{
	CTaskExplorer::ShowSecurity(theSystem->GetSecurityObject(CSystemAPI::eSecSamUser, pItem->text(0),
		QByteArray(), pItem->data(0, Qt::UserRole).toUInt()), this);
}

void CSecurityExplorer::OnGroupe(QTreeWidgetItem* pItem)
{
	CTaskExplorer::ShowSecurity(theSystem->GetSecurityObject(CSystemAPI::eSecSamGroup, pItem->text(0),
		QByteArray(), pItem->data(0, Qt::UserRole).toUInt()), this);
}
