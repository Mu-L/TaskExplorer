#include "stdafx.h"
#include <QFile>
#include "TaskInfoView.h"
#include "../../API/RemoteApi.h"
#include "../TaskExplorer.h"
#include "../../API/Cluster.h"
#include "ProcessView.h"
#include "HandlesView.h"
#include "SocketsView.h"
#include "ThreadsView.h"
#include "ModulesView.h"
#include "MemoryView.h"
#include "HeapView.h"
#include "JobView.h"
#include "TokenView.h"
#include "DotNetView.h"
#include "GDIView.h"
#include "CGroupView.h"
#include "SecurityView.h"
#include "WindowsView.h"
#include "DebugView.h"
//#include "EnvironmentView.h"
#include "SbieView.h"
//#include "../SystemInfo/ServicesView.h"
//#include "../SystemInfo/DnsCacheView.h"


CTaskInfoView::CTaskInfoView(bool bAsWindow, QWidget* patent)
: CTabPanel(patent)
{
	m_bAsWindow = bAsWindow;

	setObjectName(m_bAsWindow ? "TaskWindow" : "TaskPanel");

	InitializeTabs();

	if (!m_bAsWindow)
	{
		int ActiveTab = theConf->GetValue(objectName() + "/Tabs_Active").toInt();
		QStringList VisibleTabs = theConf->GetStringList(objectName() + "/Tabs_Visible");
		RebuildTabs(ActiveTab, VisibleTabs);
	}

	connect(m_pTabs, SIGNAL(currentChanged(int)), this, SLOT(OnTab(int)));
}


CTaskInfoView::~CTaskInfoView()
{
	if (!m_bAsWindow)
	{
		int ActiveTab = 0;
		QStringList VisibleTabs;
		SaveTabs(ActiveTab, VisibleTabs);
		theConf->SetValue(objectName() + "/Tabs_Active", ActiveTab);
		theConf->SetValue(objectName() + "/Tabs_Visible", VisibleTabs);
	}
}

void CTaskInfoView::InitializeTabs()
{
	m_pProcessView = new CProcessView(this);
	AddTab(m_pProcessView, tr("General"));

	//
	// The tabs that are a per-process list record which request fills them, so
	// a machine that cannot answer it says so rather than showing nothing.
	//
	m_pFilesView = new CHandlesView(3, this);
	m_TabFeature.insert(AddTab(m_pFilesView, tr("Files")), CSystemAPI::eFeatHandles);

	m_pHandlesView = new CHandlesView(0, this);
	m_TabFeature.insert(AddTab(m_pHandlesView, tr("Handles")), CSystemAPI::eFeatHandles);

	m_pSocketsView = new CSocketsView(false, this);
	m_TabFeature.insert(AddTab(m_pSocketsView, tr("Sockets")), CSystemAPI::eFeatSockets);

	m_pThreadsView = new CThreadsView(this);
	m_TabFeature.insert(AddTab(m_pThreadsView, tr("Threads")), CSystemAPI::eFeatThreads);

	m_pModulesView = new CModulesView(false, this);
	m_TabFeature.insert(AddTab(m_pModulesView, tr("Modules")), CSystemAPI::eFeatModules);

	m_pWindowsView = new CWindowsView(this);
	m_TabFeature.insert(AddTab(m_pWindowsView, tr("Windows")), CSystemAPI::eFeatWindows);

	m_pMemoryView = new CMemoryView(this);
	m_TabFeature.insert(AddTab(m_pMemoryView, tr("Memory")), CSystemAPI::eFeatMemory);

	//
	// ---- the tabs that belong to one platform or the other ----
	//
	// Every one of them is built, on both platforms. Which of them *starts*
	// shown is decided from the target's operating system, and the user's own
	// choice in View - Task Tabs overrides that and is remembered.
	//
	// The guard used to be an #ifdef, which meant a Windows viewer could never
	// show a Linux machine's control group or security tab however hard it
	// tried - the class was not in the binary. That is the same mistake the
	// per-process actions had, and it is fixed the same way: the guard moves
	// from build time to the target's GetOsType().
	//
	// A tab that is shown but cannot be answered greys itself out with the
	// reason on it - see SetTabEnabled and the EFeature map below - so
	// somebody who turns one on for a machine that has nothing to put in it is
	// told why rather than shown a blank page.
	//
	const bool bWindows = theSystem->GetOsType() == CSystemAPI::eOsWindows;

	// The heap view enumerates Windows heap manager structures; glibc exposes
	// no equivalent to an outside observer.
	m_pHeapView = new CHeapView(this);
	const int HeapTab = AddTab(m_pHeapView, tr("Heap"), bWindows, CSystemAPI::eOsWindows);
	m_TabFeature.insert(HeapTab, CSystemAPI::eFeatHeaps);

	m_pTokenView = new CTokenView(this);
	const int TokenTab = AddTab(m_pTokenView, tr("Token"), bWindows, CSystemAPI::eOsWindows);

	//
	// The one Windows tab a Wine process can fill: wineserver keeps a real
	// token per process and the helper reads it - see CWineToken. It is Wine's
	// answer rather than a Windows security context, which is the right thing
	// to show because it is exactly what the program running there acts on.
	//
	m_WineTabs.insert(TokenTab);

	m_pJobView = new CJobView(this);
	AddTab(m_pJobView, tr("Job"), bWindows, CSystemAPI::eOsWindows);

	//m_pServiceView = new CServicesView(false, this);
	//AddTab(m_pServiceView, tr("Service"));

	m_pDotNetView = new CDotNetView(this);
	AddTab(m_pDotNetView, tr(".NET"), bWindows, CSystemAPI::eOsWindows);

	m_pGDIView = new CGDIView(this);
	const int GdiTab = AddTab(m_pGDIView, tr("GDI"), bWindows, CSystemAPI::eOsWindows);
	m_TabFeature.insert(GdiTab, CSystemAPI::eFeatGdi);

	//
	// The Linux counterparts of the two above them: a cgroup is what a job
	// object is, and capabilities plus LSM confinement are what a token is.
	//
	m_pCGroupView = new CCGroupView(this);
	AddTab(m_pCGroupView, tr("Control Group"), !bWindows, CSystemAPI::eOsLinux);

	m_pSecurityView = new CSecurityView(this);
	AddTab(m_pSecurityView, tr("Security"), !bWindows, CSystemAPI::eOsLinux);

	//m_pDnsCacheView = new CDnsCacheView(false, this);
	//AddTab(m_pDnsCacheView, tr("Dns Cache"));

	//
	// Fed by the OutputDebugString monitor, which is a Windows facility - and a
	// stream rather than an answer.
	//
	// Local only for now. The monitor delivers messages as they happen, and the
	// protocol here is a question and an answer; there is no subscription for
	// an event feed to ride on, so for any machine reached through a daemon
	// this page would fill with nothing and never say why. Marked rather than
	// left to disappoint - see m_LocalOnlyTabs.
	//
	m_pDebugView = new CDebugView(this);
	const int DebugTab = AddTab(m_pDebugView, tr("Debug"), bWindows, CSystemAPI::eOsWindows);
	m_LocalOnlyTabs.insert(DebugTab);

	//m_pEnvironmentView = new CEnvironmentView(this);
	//AddTab(m_pEnvironmentView, tr("Environment"));

#ifdef WIN32
	if (theConf->GetBool("Options/UseSandboxie", false))
	{
		m_pSbieView = new CSbieView(this);
		AddTab(m_pSbieView, tr("Sandboxie"), true, CSystemAPI::eOsWindows);
	}
#endif
}

/*void CTaskInfoView::ShowProcess(const CProcessPtr& pProcess)
{

}*/

void CTaskInfoView::ShowProcesses(const QList<CProcessPtr>& Processes)
{
	if (m_Processes == Processes)
		return;

	m_Processes = Processes;

	OnTab(m_pTabs->currentIndex());
}

//
// Drops the processes that were collected on a machine that has gone.
//
// Compared against the system the object remembers, not against the selection
// as a whole: a selection can span machines, and one of them going should not
// clear the rest.
//
// A process whose system has already been released answers null and is dropped
// too. That is the same condition arriving by a different route - this signal
// races the destruction it is reporting - and either way the object is one
// nothing can ask about any more.
//
void CTaskInfoView::DropSystem(const CSystemPtr& pSystem)
{
	QList<CProcessPtr> Kept;
	foreach(const CProcessPtr& pProcess, m_Processes)
	{
		if (pProcess.isNull())
			continue;
		const CSystemPtr pOwner = pProcess->GetSystem();
		if (pOwner.isNull() || pOwner == pSystem)
			continue;
		Kept.append(pProcess);
	}

	if (Kept.count() == m_Processes.count())
		return;

	ShowProcesses(Kept);
}

void CTaskInfoView::SelectThread(quint64 ThreadId)
{
	m_pTabs->setCurrentWidget(m_pThreadsView);
	m_pThreadsView->SelectThread(ThreadId);
}

//
// What the machine the selected process lives on can answer.
//
// The same question the system panel asks, about the same feature list - see
// CSystemInfoView::UpdateTabAvailability. Here it follows the *selection*: a
// process on one machine and a process on another can offer different tabs, and
// the panel is rebuilt for each.
//
void CTaskInfoView::UpdateTabAvailability()
{
	const CSystemPtr pSystem = m_Processes.isEmpty() ? CCluster::GetViewSystem()
	                                                : m_Processes.first()->GetSystem();

	const QString NotOffered = tr("The Task Server on this machine does not offer this.");
	for (QMap<int, quint32>::const_iterator I = m_TabFeature.begin(); I != m_TabFeature.end(); ++I)
	{
		const bool bCan = CCluster::CanAnswer(pSystem.data(), I.value());
		SetTabEnabled(I.key(), bCan, bCan ? QString() : NotOffered);
	}

	//
	// And the ones that are a property of the operating system rather than of
	// what the server offers.
	//
	// Every tab is built on both platforms so that a viewer can show either kind
	// of machine, which means a Windows target now has a Control Group tab it can
	// never fill and a Linux target has Token, Job, .NET and GDI. Left enabled
	// they look like panels that failed; greyed out with the reason on them they
	// say what they are.
	//
	// Only the tabs the user has actually turned on are affected - the defaults
	// already hide these, and SetTabEnabled ignores a tab that is not shown.
	//
	const CSystemAPI::EOsType OsType = pSystem ? pSystem->GetOsType() : CSystemAPI::eOsWindows;

	//
	// And whether the process is a Windows one as well.
	//
	// A process under Wine is both at once, and that is not a figure of speech:
	// it has a token, handles and windows that only wineserver knows about, and
	// at the same time a pid, a control group and an LSM profile that only
	// /proc does. So it adds the Windows tabs rather than replacing the Linux
	// ones - putty.exe offers Token *and* Control Group, where the ELF beside it
	// offers only the second. See NEXT.md 5.16.
	//
	// Only for a single selection: a selection spanning both kinds has no one
	// answer, and the machine's is the safer of the two.
	//
	const bool bWine = (m_Processes.count() == 1) && !m_Processes.first().isNull()
					&& m_Processes.first()->GetWineInfo().Valid;

	//
	// And whether this viewer is on the machine being shown, for the few tabs
	// that need it to be - see m_LocalOnlyTabs.
	//
	const bool bLocal = !pSystem.isNull() && pSystem->IsLocal();
	const QString OnlyHere = tr("This is only available for the machine this viewer runs on.");

	for (int i = 0; i < GetTabCount(); i++)
	{
		//
		// Checked before the platform question and not after it, so that a tab
		// which is wrong for the target's platform keeps that reason - it is
		// the more specific of the two, and true whichever machine is asking.
		//
		if (GetTabPlatform(i) == eAnyPlatform)
		{
			if (m_LocalOnlyTabs.contains(i) && !bLocal)
				SetTabEnabled(i, false, OnlyHere);
			continue;
		}

		const CSystemAPI::EOsType TabOs = (CSystemAPI::EOsType)GetTabPlatform(i);
		//
		// And only the Windows tabs Wine can answer, not all of them. Being a
		// Windows process is not the same as being one this can read: what is
		// reachable is what the helper inside the prefix reports, and the rest
		// used to open as pages that stayed blank for good.
		//
		const bool bWineTab = bWine && TabOs == CSystemAPI::eOsWindows
						&& m_WineTabs.contains(i);
		bool bFits = (TabOs == OsType) || bWineTab;

		QString Reason;
		if (!bFits)
		{
			if (bWine && TabOs == CSystemAPI::eOsWindows)
				Reason = tr("This is a Windows process under Wine, and Wine cannot answer this.");
			else if (OsType == CSystemAPI::eOsWindows)
				Reason = tr("This machine runs Windows, which has no such notion.");
			else
				Reason = tr("This machine does not run Windows, which is where this comes from.");
		}
		if (bFits && m_LocalOnlyTabs.contains(i) && !bLocal)
		{
			bFits = false;
			Reason = OnlyHere;
		}

		SetTabEnabled(i, bFits, Reason);
	}
}

void CTaskInfoView::OnTab(int tabIndex)
{
	//
	// Also here, because RebuildTabs recreates every tab when the user changes
	// which are shown, and the enabled state does not survive that.
	//
	UpdateTabAvailability();

	//
	// Before the tab is handed the selection, not after: a panel that reads the
	// detail in ShowProcesses would otherwise draw once from whatever the last
	// round left behind.
	//
	if (!m_Processes.isEmpty())
		UpdateDetails();

	//
	// Handed over even when it is empty, which it did not used to be.
	//
	// An empty selection is a thing to say, not a reason to say nothing: a tab
	// that is never told keeps drawing the last process it was given, and after a
	// machine disconnects that is a page of numbers about somewhere nobody is
	// connected to.
	//
	QMetaObject::invokeMethod(m_pTabs->currentWidget(), "ShowProcesses", Qt::AutoConnection, Q_ARG(const QList<CProcessPtr>&, m_Processes));
}

void CTaskInfoView::UpdateDetails()
{
	//
	// Only what is on screen. A selection of eight processes with the panel
	// closed is eight round trips nobody asked for; CRemoteProcess throttles the
	// rest.
	//
	if (!isVisible())
		return;

	//
	// Registered with each machine rather than called on each process.
	//
	// What goes here is the *set* of processes worth the extra round trip, and
	// the machine fetches them inside its own refresh round - one place that
	// knows what is on screen, instead of every panel asking on its own tick.
	//
	// Grouped by machine because a selection may span several, and each keeps
	// its own list - a process selected on one must not stop another fetching
	// its own.
	//
	QMap<CSystemAPI*, QSet<quint64> > Wanted;
	foreach(const CProcessPtr& pProcess, m_Processes)
	{
		if (!pProcess.isNull())
			Wanted[pProcess->GetSystem().data()].insert(pProcess->GetProcessId());
	}

	foreach(const CSystemPtr& pNode, CCluster::GetSystems())
	{
		if (IRemoteSystem* pRemote = pNode->GetRemote())
			pRemote->SetDetailWanted(Wanted.value(pNode.data()));
	}
}

void CTaskInfoView::Refresh()
{
	//
	// Re-asked every round, not only when the selection moves.
	//
	// Most of what decides a tab's availability is known the moment a process is
	// picked, but not all of it: whether a process is running under Wine arrives
	// with its detail, which is fetched *after* the selection. Asked once at
	// selection time the answer would be "not Wine" for every process, for ever.
	//
	UpdateTabAvailability();

	UpdateDetails();

	QMetaObject::invokeMethod(m_pTabs->currentWidget(), "Refresh", Qt::AutoConnection);
}
