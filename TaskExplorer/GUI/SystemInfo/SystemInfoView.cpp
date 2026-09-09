#include "stdafx.h"
#include "SystemInfoView.h"
#include "../TaskExplorer.h"
#include "../TaskStrings.h"
#include "../../API/Cluster.h"

#include "SystemView.h"
//#include "DriversView.h"
#include "../TaskInfo/HandlesView.h"
#include "../TaskInfo/SocketsView.h"
#include "ServicesView.h"
#include "CPUView.h"
#include "RAMView.h"
#include "DiskView.h"
#include "NetworkView.h"
#include "GPUView.h"
#include "DnsCacheView.h"

CSystemInfoView::CSystemInfoView(bool bAsWindow, QWidget* patent) 
	: CTabPanel(patent)
{
	m_bAsWindow = bAsWindow;

	setObjectName(m_bAsWindow ? "SystemWindow" : "SystemPanel");

	InitializeTabs();

	//
	// Above the tabs, and hidden outright while it has nothing to say - so with
	// one machine in view the panel looks exactly as it did before, with no
	// space given up for a label that would only ever be blank.
	//
	// Not the tab strip's corner widget, which is where this started: the tab
	// bar is qextwidgets' multi-row one and it lays its rows out across the full
	// width, so a corner widget is drawn over the last tab rather than beside
	// it.
	//
	//m_pMachineLabel = new QLabel();
	//m_pMachineLabel->setContentsMargins(4, 2, 4, 2);
	//m_pMachineLabel->setVisible(false);
	//m_pMainLayout->insertWidget(0, m_pMachineLabel);

	if (!m_bAsWindow)
	{
		int ActiveTab = theConf->GetValue(objectName() + "/Tabs_Active").toInt();
		QStringList VisibleTabs = theConf->GetStringList(objectName() + "/Tabs_Visible");
		RebuildTabs(ActiveTab, VisibleTabs);
	}

	connect(m_pTabs, SIGNAL(currentChanged(int)), this, SLOT(OnTab(int)));

	connect(theGUI, SIGNAL(ViewSystemChanged()), this, SLOT(OnViewSystemChanged()));
	OnViewSystemChanged();
}


CSystemInfoView::~CSystemInfoView()
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

void CSystemInfoView::InitializeTabs()
{
	//
	// Each tab records what the machine has to be able to answer for it to be
	// worth offering; see UpdateTabAvailability.
	//
	m_pSystemView = new CSystemView(this);
	m_TabFeature.insert(AddTab(m_pSystemView, tr("System")), CSystemAPI::eFeatSysInfo);

	m_pCPUView = new CCPUView(this);
	m_TabFeature.insert(AddTab(m_pCPUView, tr("CPU")), CSystemAPI::eFeatSysInfo);

	m_pRAMView = new CRAMView(this);
	m_TabFeature.insert(AddTab(m_pRAMView, tr("Memory")), CSystemAPI::eFeatSysInfo);

	m_pGPUView = new CGPUView(this);
	m_GpuTab = AddTab(m_pGPUView, tr("GPU"));
	m_TabFeature.insert(m_GpuTab, CSystemAPI::eFeatDevices);

	m_pDiskView = new CDiskView(this);
	m_DiskTab = AddTab(m_pDiskView, tr("Disk"));
	m_TabFeature.insert(m_DiskTab, CSystemAPI::eFeatDevices);

	m_pAllFilesView = new CHandlesView(1, this);
	m_TabFeature.insert(AddTab(m_pAllFilesView, tr("Files")), CSystemAPI::eFeatOpenFiles);

	m_pNetworkView = new CNetworkView(this);
	m_NetworkTab = AddTab(m_pNetworkView, tr("Network"));
	m_TabFeature.insert(m_NetworkTab, CSystemAPI::eFeatDevices);

	m_pAllSocketsView = new CSocketsView(true, this);
	m_TabFeature.insert(AddTab(m_pAllSocketsView, tr("Sockets")), CSystemAPI::eFeatSockets);

	//
	// A Windows notion, and marked as one.
	//
	// There is no resolver cache to read on Linux: name resolution goes through
	// whatever the machine has - systemd-resolved, nscd, dnsmasq, or nothing at
	// all - and each keeps its own or keeps none. So the tab was simply empty
	// there, which reads as "this machine has resolved nothing" rather than
	// "this question does not apply here".
	//
	// Nothing serves it remotely either - CSystemAPI::eFeatDnsCache is reserved
	// and unimplemented - so the feature marker stays as well. The two say
	// different things: one is about the machine, the other about what its
	// daemon can be asked.
	//
	m_pDnsCacheView = new CDnsCacheView(true, this);
	m_TabFeature.insert(AddTab(m_pDnsCacheView, tr("Dns Cache"),
		theSystem->GetOsType() == CSystemAPI::eOsWindows, CSystemAPI::eOsWindows),
		CSystemAPI::eFeatDnsCache);

	//m_pDriversView = new CDriversView(this);
	//AddTab(m_pDriversView, tr("Drivers"));

	//
	// One view and one model for both kinds of machine; only the word differs.
	// "Service" on Linux means a systemd unit type and this list holds several
	// of them, so "Daemons" names what the entries actually are.
	//
	// The name is set here from this machine only so that the tab has one before
	// anything is selected; UpdateTabAvailability re-reads it from the machine
	// being looked at. Deciding it once from theSystem was wrong in the way that
	// is easy to miss - a Windows viewer watching a Linux box labelled the tab
	// "Services", over a list of daemons.
	//
	m_pServicesView = new CServicesView(true, this);
	//m_ServicesTab = AddTab(m_pServicesView, ServiceTabLabel(theSystem.data()));
	m_ServicesTab = AddTab(m_pServicesView, tr("Services"));
	m_TabFeature.insert(m_ServicesTab, CSystemAPI::eFeatServices);
}

void CSystemInfoView::OnTab(int tabIndex)
{
	//
	// Also here, because RebuildTabs recreates every tab from scratch when the
	// user changes which are shown, and the enabled state does not survive that.
	//
	UpdateTabAvailability();
	Refresh();
}

//
// Which machine is being shown, and what it can be asked.
//
void CSystemInfoView::UpdateMachineLabel()
{
	CSystemPtr pSystem = CCluster::GetViewSystem();

	//
	// Named only in cluster mode, and only when there is more than one machine
	// to confuse it with. There the graph bar and the status line below report
	// the local machine whatever the panels show, so without this the two halves
	// of the window would disagree with nothing on screen saying why.
	//
	// With the machine layer off the whole window is one machine and the title
	// bar names it, so a label here would only repeat what the window is called.
	//
	//QString Label;
	//if (CCluster::IsClusterMode() && CCluster::GetSystems().count() > 1)
	//	Label = tr("Showing: %1").arg(::GetMachineDisplayName(pSystem.data()));
	//m_pMachineLabel->setText(Label);
	//m_pMachineLabel->setVisible(!Label.isEmpty());

	UpdateTabAvailability();
}

void CSystemInfoView::OnViewSystemChanged()
{
	UpdateMachineLabel();

	//
	// Everything plotted was measured on the machine that is no longer being
	// shown. Carried over it would read as this one's history, which is worse
	// than a gap.
	//
	m_pCPUView->ResetPlots();
	m_pRAMView->ResetPlots();
	m_pDiskView->ResetPlots();
	m_pNetworkView->ResetPlots();
	m_pGPUView->ResetPlots();

	Refresh();
}

//
// The tabs that cannot follow the selection.
//
// The kernel sub-tabs inside the System tab reach into the Windows collector
// directly - they downcast theSystem to CWindowsAPI and read tables no wire
// format carries - so pointing them at a remote machine would be a crash rather
// than an empty list. They are greyed with the reason instead of silently
// showing the local machine's data under another machine's name. The System tab
// greys its own; see CSystemView::UpdateAvailability, which is now where the
// RPC endpoints are too.
//
// This is the narrow, safe case of the general "a view the target cannot
// answer" work: it is driven by what the code can survive, not yet by what the
// target reported it can do. See NEXT.md.
//
//
// A Windows service and a Linux daemon are the same list of the same things
// under two words, so there is one view and one model - see CServicesView. Only
// the label differs, and "Service" on Linux names a systemd unit *type* while
// this list holds several of them, which is why the other word is used there.
//
//QString CSystemInfoView::ServiceTabLabel(CSystemAPI* pSystem)
//{
//	return (!pSystem || pSystem->GetOsType() == CSystemAPI::eOsWindows)
//		? tr("Services") : tr("Daemons");
//}

void CSystemInfoView::UpdateTabAvailability()
{
	CSystemPtr pSystem = CCluster::GetViewSystem();

	//
	// GPU, Disk and Network draw a list of devices, and that list comes from a
	// monitor object which only exists on a machine this process is collecting
	// from - what crosses the wire today is the aggregate counters the graph bar
	// uses, not per-adapter or per-disk detail. Asked of the system rather than
	// assumed from "is it remote", so these come back on their own the day the
	// wire carries them.
	//
	const QString NoDetail = tr("This machine does not report per-device detail.");
	SetTabEnabled(m_GpuTab, pSystem->GetGpuMonitor() != NULL, pSystem->GetGpuMonitor() ? QString() : NoDetail);
	SetTabEnabled(m_DiskTab, pSystem->GetDiskMonitor() != NULL, pSystem->GetDiskMonitor() ? QString() : NoDetail);
	SetTabEnabled(m_NetworkTab, pSystem->GetNetMonitor() != NULL, pSystem->GetNetMonitor() ? QString() : NoDetail);

	//
	// And everything the target itself said whether it can answer.
	//
	// This is the difference between an empty tab and an honest one: a list that
	// was never asked for looks exactly like a list that came back empty, and
	// only one of the two means "there is nothing here".
	//
	//
	// And the one tab whose *name* belongs to the target rather than to us.
	// The View menu lists the same words, so it is told when this changes.
	//
	//if (SetTabLabel(m_ServicesTab, ServiceTabLabel(pSystem.data())))
	//	emit TabLabelsChanged();

	const QString NotOffered = tr("The Task Server on this machine does not offer this.");
	for (QMap<int, quint32>::const_iterator I = m_TabFeature.begin(); I != m_TabFeature.end(); ++I)
	{
		const bool bCan = CCluster::CanAnswer(pSystem.data(), I.value());
		SetTabEnabled(I.key(), bCan, bCan ? QString() : NotOffered);
	}

	//
	// And whether the tab is about this kind of machine at all.
	//
	// The same rule the task panel applies - see CTaskInfoView::UpdateTabAvailability -
	// and for the same reason: a tab that cannot apply here should say so rather
	// than show an empty list, which reads as "nothing found" instead of "wrong
	// question".
	//
	// Applied after the feature loop, so that a tab which fails both tests ends
	// up with the reason that is actually true of it: a Windows-only tab on a
	// Linux machine is not a daemon that declined to answer.
	//
	const CSystemAPI::EOsType OsType = pSystem ? pSystem->GetOsType() : CSystemAPI::eOsWindows;
	for (int i = 0; i < GetTabCount(); i++)
	{
		if (GetTabPlatform(i) == eAnyPlatform)
			continue;

		const bool bFits = ((CSystemAPI::EOsType)GetTabPlatform(i) == OsType);
		SetTabEnabled(i, bFits, bFits ? QString()
			: (OsType == CSystemAPI::eOsWindows
				? tr("This machine runs Windows, which has no such notion.")
				: tr("This machine does not run Windows, which is where this comes from.")));
	}
}

void CSystemInfoView::Refresh()
{
	QTimer::singleShot(0, m_pTabs->currentWidget(), SLOT(Refresh()));
}

void CSystemInfoView::UpdateGraphs()
{
	// todo: dont update hidden tabs
	m_pCPUView->UpdateGraphs();
	m_pRAMView->UpdateGraphs();
	m_pDiskView->UpdateGraphs();
	m_pNetworkView->UpdateGraphs();
	m_pGPUView->UpdateGraphs();
}
