#include "stdafx.h"
#include "../TaskExplorer.h"
#include "../TaskStrings.h"
#include "SecurityView.h"
#include "../../API/Linux/ProcFs.h"
#include "../../API/Linux/LinuxHelper.h"
#include "../../../MiscHelpers/Common/Common.h"

CSecurityView::CSecurityView(QWidget *parent)
	:CPanelView(parent)
{
	//
	// Laid out as the Token view is, down to the nesting: an outer box holding
	// a header widget and the tabs, each keeping its own default margins. The
	// two panels are read side by side and this is the one modelled on that
	// one, so it should not sit differently on the page - a grid of labelled
	// fields flush against the panel edge reads as clipped.
	//
	QVBoxLayout* pOuterLayout = new QVBoxLayout();
	this->setLayout(pOuterLayout);

	QWidget* pHeaderWidget = new QWidget();
	pOuterLayout->addWidget(pHeaderWidget);

	m_pHeaderLayout = new QGridLayout();
	pHeaderWidget->setLayout(m_pHeaderLayout);

	//
	// A header, then the lists - the shape of the Token view, for the same
	// reason: four or five facts answer "how privileged is this thing" at a
	// glance, and the rest is detail somebody goes looking for.
	//
	// Read-only line edits rather than labels for the strings: an AppArmor
	// profile name or a container id is long and worth being able to select
	// and copy, exactly like the control group path next door.
	//
	int row = 0;

	m_pHeaderLayout->addWidget(new QLabel(tr("User:")), row, 0);
	m_pUser = new QLineEdit();
	m_pUser->setReadOnly(true);
	m_pHeaderLayout->addWidget(m_pUser, row, 1);

	m_pHeaderLayout->addWidget(new QLabel(tr("Group id:")), row, 2);
	m_pGroup = new QLineEdit();
	m_pGroup->setReadOnly(true);
	m_pHeaderLayout->addWidget(m_pGroup, row++, 3);

	m_pHeaderLayout->addWidget(new QLabel(tr("Profile:")), row, 0);
	m_pProfile = new QLineEdit();
	m_pProfile->setReadOnly(true);
	m_pHeaderLayout->addWidget(m_pProfile, row, 1);

	m_pHeaderLayout->addWidget(new QLabel(tr("Container:")), row, 2);
	m_pContainer = new QLineEdit();
	m_pContainer->setReadOnly(true);
	m_pHeaderLayout->addWidget(m_pContainer, row++, 3);

	m_pHeaderLayout->addWidget(new QLabel(tr("Seccomp:")), row, 0);
	m_pSeccomp = new QLabel();
	m_pHeaderLayout->addWidget(m_pSeccomp, row, 1);

	m_pHeaderLayout->addWidget(new QLabel(tr("No new privileges:")), row, 2);
	m_pNoNewPrivs = new QLabel();
	m_pHeaderLayout->addWidget(m_pNoNewPrivs, row++, 3);

	m_pTabs = new QTabWidget();
	pOuterLayout->addWidget(m_pTabs);

	m_pList = new CPanelWidgetEx();
	m_pList->GetView()->setItemDelegate(theGUI->GetItemDelegate());
	((QTreeWidgetEx*)m_pList->GetView())->setHeaderLabels(tr("Property|Value").split("|"));
	m_pList->GetView()->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_pList->GetView()->setSortingEnabled(false);
	m_pTabs->addTab(m_pList, tr("General"));

	//
	// One row per capability the process has anywhere, with a mark in each set
	// that holds it. A set it is not in is left blank rather than marked no:
	// what a reader is looking for is the few that are there.
	//
	m_pCaps = new CPanelWidgetEx();
	m_pCaps->GetView()->setItemDelegate(theGUI->GetItemDelegate());
	((QTreeWidgetEx*)m_pCaps->GetView())->setHeaderLabels(
		tr("Capability|Effective|Permitted|Inheritable|Ambient|Bounding").split("|"));
	m_pCaps->GetView()->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_pCaps->GetView()->setSortingEnabled(false);
	m_pTabs->addTab(m_pCaps, tr("Capabilities"));

	m_pNamespaces = new CPanelWidgetEx();
	m_pNamespaces->GetView()->setItemDelegate(theGUI->GetItemDelegate());
	((QTreeWidgetEx*)m_pNamespaces->GetView())->setHeaderLabels(tr("Namespace|Value").split("|"));
	m_pNamespaces->GetView()->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_pNamespaces->GetView()->setSortingEnabled(false);
	m_pTabs->addTab(m_pNamespaces, tr("Namespaces"));

	AddPanelItemsToMenu();

	m_pList->GetView()->header()->restoreState(theConf->GetBlob(objectName() + "/SecurityView_Columns"));
	//
	// Before the saved state, so a first run shows the names in full rather
	// than truncating every one of them to CAP_SYS_A... - and a saved width
	// still wins where there is one.
	//
	m_pCaps->GetView()->setColumnWidth(0, 200);
	m_pCaps->GetView()->header()->restoreState(theConf->GetBlob(objectName() + "/SecurityCaps_Columns"));
	m_pNamespaces->GetView()->header()->restoreState(theConf->GetBlob(objectName() + "/SecurityNs_Columns"));
}

CSecurityView::~CSecurityView()
{
	theConf->SetBlob(objectName() + "/SecurityView_Columns", m_pList->GetView()->header()->saveState());
	theConf->SetBlob(objectName() + "/SecurityCaps_Columns", m_pCaps->GetView()->header()->saveState());
	theConf->SetBlob(objectName() + "/SecurityNs_Columns", m_pNamespaces->GetView()->header()->saveState());
}

void CSecurityView::OnMenu(const QPoint& Point)
{
	CPanelView::OnMenu(Point);
}

void CSecurityView::SetValue(const QString& Group, const QString& Name, const QString& Value)
{
	QTreeWidgetItem* pGroup = m_Groups.value(Group);
	if (!pGroup)
	{
		pGroup = new QTreeWidgetItem();
		pGroup->setText(0, Group);
		pGroup->setFirstColumnSpanned(true);
		m_pList->GetTree()->addTopLevelItem(pGroup);
		pGroup->setExpanded(true);
		m_Groups.insert(Group, pGroup);
	}

	const QString Key = Group + "/" + Name;
	m_LiveKeys.insert(Key);

	QTreeWidgetItem* pItem = m_Items.value(Key);
	if (!pItem)
	{
		pItem = new QTreeWidgetItem();
		pItem->setText(0, Name);
		pGroup->addChild(pItem);
		m_Items.insert(Key, pItem);
	}

	if (pItem->text(1) != Value)
		pItem->setText(1, Value);
}

void CSecurityView::PruneStale()
{
	for (auto I = m_Items.begin(); I != m_Items.end(); )
	{
		if (m_LiveKeys.contains(I.key())) { ++I; continue; }
		delete I.value();
		I = m_Items.erase(I);
	}

	for (auto I = m_Groups.begin(); I != m_Groups.end(); )
	{
		if (I.value()->childCount() > 0) { ++I; continue; }
		delete I.value();
		I = m_Groups.erase(I);
	}
}

//
// A row per capability the process holds anywhere, marked in each set that
// holds it.
//
// The five sets answer different questions and the old summary put each of
// them on one line, which for an unconfined root process meant either the word
// "all" or forty names run together - true, and unreadable either way. Turned
// on its side it reads the way the Windows privilege list does: the name is
// what somebody is looking for, and the marks say how far it reaches.
//
//   Effective   - usable right now
//   Permitted   - may be re-enabled at will, so effectively the same power
//   Inheritable - survives an execve into a file with no capabilities set
//   Ambient     - survives an execve outright
//   Bounding    - the ceiling; nothing outside it can ever be acquired
//
void CSecurityView::ShowCapabilities(const SProcessSecurity& Security)
{
	const quint64 Sets[] = { Security.CapEff, Security.CapPrm, Security.CapInh,
				  Security.CapAmb, Security.CapBnd };
	const int Count = (int)(sizeof(Sets) / sizeof(Sets[0]));

	//
	// Anywhere at all, which for an ordinary process is the bounding set and
	// nothing else. A capability in none of the five is not a row: there are
	// forty of them and the ones that are absent everywhere say nothing.
	//
	quint64 Any = 0;
	for (int i = 0; i < Count; i++)
		Any |= Sets[i];

	QSet<int> Live;
	for (int Bit = 0; Bit < 64; Bit++)
	{
		if (!(Any & (1ULL << Bit)))
			continue;
		Live.insert(Bit);

		QTreeWidgetItem* pItem = m_CapItems.value(Bit);
		if (!pItem)
		{
			pItem = new QTreeWidgetItem();
			pItem->setText(0, GetCapabilityName(Bit));
			m_pCaps->GetTree()->addTopLevelItem(pItem);
			m_CapItems.insert(Bit, pItem);
		}

		for (int i = 0; i < Count; i++)
		{
			const QString Mark = (Sets[i] & (1ULL << Bit)) ? tr("x") : QString();
			if (pItem->text(1 + i) != Mark)
				pItem->setText(1 + i, Mark);
		}
	}

	for (auto I = m_CapItems.begin(); I != m_CapItems.end(); )
	{
		if (Live.contains(I.key())) { ++I; continue; }
		delete I.value();
		I = m_CapItems.erase(I);
	}
}

//
// Which namespaces this process shares with the machine and which are its own.
//
// Shown against pid 1's, because the inode numbers themselves mean nothing to a
// reader - what matters is whether this process is in the host's namespace or
// in one of its own. The host is the machine the process is on, which is not
// necessarily this one, so its system is asked rather than pid 1 read here.
//
void CSecurityView::ShowNamespaces()
{
	const SProcessNamespaces Host = m_pCurProcess->GetSystem()
		? m_pCurProcess->GetSystem()->GetHostNamespaces() : SProcessNamespaces();
	const SProcessNamespaces Namespaces = m_pCurProcess->GetNamespaces();

	auto Show = [this](const QString& Name, quint64 Value, quint64 HostValue) {
		QString Text;
		if (!Value)
			Text = tr("not readable");
		else if (!HostValue || Value == HostValue)
			Text = tr("host");
		else
			Text = tr("private (%1)").arg(Value);

		QTreeWidgetItem* pItem = m_NsItems.value(Name);
		if (!pItem)
		{
			pItem = new QTreeWidgetItem();
			pItem->setText(0, Name);
			m_pNamespaces->GetTree()->addTopLevelItem(pItem);
			m_NsItems.insert(Name, pItem);
		}
		if (pItem->text(1) != Text)
			pItem->setText(1, Text);
	};

	Show(tr("pid"), Namespaces.Pid, Host.Pid);
	Show(tr("net"), Namespaces.Net, Host.Net);
	Show(tr("mnt"), Namespaces.Mnt, Host.Mnt);
	Show(tr("user"), Namespaces.User, Host.User);
	Show(tr("uts"), Namespaces.Uts, Host.Uts);
	Show(tr("ipc"), Namespaces.Ipc, Host.Ipc);
	Show(tr("cgroup"), Namespaces.CGroup, Host.CGroup);
}

void CSecurityView::ShowProcesses(const QList<CProcessPtr>& Processes)
{
	CProcessPtr pProcess;
	if (Processes.count() == 1)
	{
		setEnabled(true);
		pProcess = Processes.first();
	}
	else
		setEnabled(false);

	m_pCurProcess = pProcess;

	Refresh();
}

//
// Everything the header and the two side lists hold, emptied.
//
// Called wherever this view has nothing to say - no selection, or a machine
// that does not report confinement at all. Without it the last process's
// capabilities stayed on screen under the next one's name, which is worse than
// a blank page: it reads as an answer.
//
void CSecurityView::Clear()
{
	m_pUser->clear();
	m_pGroup->clear();
	m_pProfile->clear();
	m_pContainer->clear();
	m_pSeccomp->clear();
	m_pNoNewPrivs->clear();

	foreach(QTreeWidgetItem* pItem, m_CapItems)
		delete pItem;
	m_CapItems.clear();

	foreach(QTreeWidgetItem* pItem, m_NsItems)
		delete pItem;
	m_NsItems.clear();
}

void CSecurityView::Refresh()
{
	m_LiveKeys.clear();

	if (m_pCurProcess.isNull())
	{
		Clear();
		PruneStale();
		return;
	}

	const quint64 Pid = m_pCurProcess->GetProcessId();
	const SProcessSecurity Security = m_pCurProcess->GetProcessSecurity();

	if (!Security.Valid)
	{
		//
		// This used to say the process had exited, which it had not. Valid is
		// false whenever nothing was read - and the commonest reason by far is
		// that the machine being watched does not report confinement at all,
		// which is a statement about the machine, not about the process.
		//
		SetValue(tr("Identity"), tr("Status"),
			tr("This machine does not report process confinement."));
		Clear();
		PruneStale();
		return;
	}

	// ---- identity ----

	const QString User = tr("%1 (uid %2)")
		.arg(::LocalizeName(m_pCurProcess->GetUserName())).arg(m_pCurProcess->GetUid());
	SetValue(tr("Identity"), tr("User"), User);
	SetValue(tr("Identity"), tr("Group id"), QString::number(m_pCurProcess->GetGid()));

	const QString Container = m_pCurProcess->GetContainer();
	SetValue(tr("Identity"), tr("Container"), Container.isEmpty() ? tr("none (host)") : Container);

	//
	// And in the header. The list keeps them too - it is the one that can be
	// selected and copied, and a reader following a group down it should not
	// find a hole where the identity was.
	//
	m_pUser->setText(User);
	m_pGroup->setText(QString::number(m_pCurProcess->GetGid()));
	m_pContainer->setText(Container.isEmpty() ? tr("none (host)") : Container);

	// ---- confinement ----

	//
	// An absent label means no LSM is active at all, which is materially
	// different from an active LSM that has decided not to confine this
	// process - so the two are worded differently rather than both blank.
	//
	const QString Confinement = Security.Confinement;
	const QString Profile = Confinement.isEmpty() ? tr("no LSM active")
			: (Confinement == "unconfined" ? tr("unconfined") : Confinement);
	SetValue(tr("Confinement"), tr("Profile"), Profile);
	m_pProfile->setText(Profile);

	const QString Seccomp = Security.SeccompFilters
		? tr("%1 (%2 filters)").arg(::GetSeccompModeString(Security.Seccomp)).arg(Security.SeccompFilters)
		: ::GetSeccompModeString(Security.Seccomp);
	SetValue(tr("Confinement"), tr("Seccomp"), Seccomp);
	m_pSeccomp->setText(Seccomp);

	//
	// no_new_privs means the process can never gain privileges through execve,
	// so a setuid binary it runs stays unprivileged. It is what makes a sandbox
	// hold across exec.
	//
	const QString NoNewPrivs = Security.NoNewPrivs ? tr("Yes") : tr("No");
	SetValue(tr("Confinement"), tr("No new privileges"), NoNewPrivs);
	m_pNoNewPrivs->setText(NoNewPrivs);

	// ---- capabilities ----

	ShowCapabilities(Security);

	// ---- namespaces ----

	ShowNamespaces();

	// ---- out of memory killer ----

	SetValue(tr("Out of memory killer"), tr("Score"), QString::number(m_pCurProcess->GetOomScore()));
	SetValue(tr("Out of memory killer"), tr("Adjustment"), QString::number(m_pCurProcess->GetOomScoreAdj()));

	// ---- resources ----

	SetValue(tr("Resources"), tr("inotify watches"), FormatNumber(m_pCurProcess->GetInotifyWatches()));

	PruneStale();
}
