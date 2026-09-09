#include "stdafx.h"
#include "../../API/Cluster.h"
#include "../TaskExplorer.h"
#include "../DesktopActions.h"
#include "ServicesView.h"
#include "../../../MiscHelpers/Common/Common.h"
#include "../../API/SystemAPI.h"
#ifdef WIN32
#include "../../API/Windows/WinService.h"
#include "WinSvcWindow.h"
#endif
#include "../../../MiscHelpers/Common/SortFilterProxyModel.h"
#include "../../../MiscHelpers/Common/Finder.h"
#include "../TaskInfo/TaskInfoWindow.h"

CServicesView::CServicesView(bool bAll, QWidget *parent)
	:CPanelView(parent)
{
	m_bAll = bAll;

	m_pMainLayout = new QVBoxLayout();
	m_pMainLayout->setContentsMargins(0, 0, 0, 0);
	this->setLayout(m_pMainLayout);

	m_pServiceModel = new CServiceModel();
	
	m_pSortProxy = new CSortFilterProxyModel(this);
	m_pSortProxy->setSortRole(Qt::EditRole);
    m_pSortProxy->setSourceModel(m_pServiceModel);
	m_pSortProxy->setDynamicSortFilter(true);


	// Service List
	m_pServiceList = new QTreeViewEx();
	m_pServiceList->setItemDelegate(theGUI->GetItemDelegate());

	m_pServiceList->setModel(m_pSortProxy);

	m_pServiceList->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_pServiceList->setSortingEnabled(true);

	m_pServiceList->setContextMenuPolicy(Qt::CustomContextMenu);
	connect(m_pServiceList, SIGNAL(customContextMenuRequested( const QPoint& )), this, SLOT(OnMenu(const QPoint &)));

	connect(theGUI, SIGNAL(ReloadPanels()), m_pServiceModel, SLOT(Clear()));

	m_pServiceList->setColumnReset(2);
	connect(m_pServiceList, SIGNAL(ResetColumns()), this, SLOT(OnResetColumns()));
	//connect(m_pServiceList, SIGNAL(ColumnChanged(int, bool)), this, SLOT(OnColumnsChanged()));

	m_pMainLayout->addWidget(m_pServiceList);
	// 

	m_pMainLayout->addWidget(new CFinder(m_pSortProxy, this));

	if (!bAll)
	{
		//m_pServiceList->SetColumnHidden(CServiceModel::ePID, true, true);
		m_pServiceList->SetColumnHidden(CServiceModel::eGroupe, true, true);
		m_pServiceList->SetColumnHidden(CServiceModel::eFileName, true, true);
		m_pServiceList->SetColumnHidden(CServiceModel::eDescription, true, true);
		m_pServiceList->SetColumnHidden(CServiceModel::eCompanyName, true, true);
		m_pServiceList->SetColumnHidden(CServiceModel::eVersion, true, true);
		//m_pServiceList->setColumnHidden(CServiceModel::eBinaryPath, true, true);
	}

	//connect(m_pServiceList, SIGNAL(clicked(const QModelIndex&)), this, SLOT(OnClicked(const QModelIndex&)));
	connect(m_pServiceList, SIGNAL(doubleClicked(const QModelIndex&)), this, SLOT(OnDoubleClicked()));

	QByteArray Columns = theConf->GetBlob(objectName() + "/ServicesView_Columns");
	if (Columns.isEmpty())
		OnResetColumns();
	else
		m_pServiceList->restoreState(Columns);

	//m_pMenu = new QMenu();
	m_pMenuOpen = m_pMenu->addAction(tr("Open"), this, SLOT(OnDoubleClicked()));
	m_pMenu->addSeparator();
	m_pMenuStart = m_pMenu->addAction(tr("Start"), this, SLOT(OnServiceAction()));
	m_pMenuContinue = m_pMenu->addAction(tr("Continue"), this, SLOT(OnServiceAction()));
	m_pMenuPause = m_pMenu->addAction(tr("Pause"), this, SLOT(OnServiceAction()));
	m_pMenuStop = m_pMenu->addAction(tr("Stop"), this, SLOT(OnServiceAction()));
	//m_MenuRestart = m_pMenu->addAction(tr("Restart"), this, SLOT(OnServiceAction()));
	m_pMenu->addSeparator();
	m_pMenuDelete = m_pMenu->addAction(tr("Delete"), this, SLOT(OnServiceAction()));
	m_pMenu->addSeparator();
	//
	// Where a service's configuration and output live differs by system: a
	// registry key on Windows, the journal under systemd. Both entries exist
	// and the one the target cannot serve stays hidden.
	//
	m_pMenuOpenKey = m_pMenu->addAction(tr("Open Key"), this, SLOT(OnServiceAction()));
	m_pMenuViewLog = m_pMenu->addAction(tr("View Log"), this, SLOT(OnServiceAction()));
	m_pMenuOpenProcess = m_pMenu->addAction(tr("Open Process"), this, SLOT(OnServiceAction()));
	if (bAll)
	{
		m_pMenu->addSeparator();
		m_pMenuKernelServices = m_pMenu->addAction(tr("Show Kernel Services"), this, SLOT(Refresh()));
		m_pMenuKernelServices->setCheckable(true);
		m_pMenuKernelServices->setChecked(theConf->GetValue(objectName() + "/ShowKernelServices", true).toBool());
	}
	else
		m_pMenuKernelServices = NULL;
	AddPanelItemsToMenu();

	// must be after m_pMenuKernelServices
	connect(m_pServiceList, SIGNAL(ColumnChanged(int, bool)), this, SLOT(OnColumnsChanged()));

	if(bAll)
		{
		new CViewSystemLink(this, SIGNAL(ServiceListUpdated(QSet<QString>, QSet<QString>, QSet<QString>)), SLOT(OnServiceListUpdated(QSet<QString>, QSet<QString>, QSet<QString>)));
		connect(theGUI, SIGNAL(ViewSystemChanged()), this, SLOT(OnViewSystemChanged()));
	}
}

CServicesView::~CServicesView()
{
	theConf->SetBlob(objectName() + "/ServicesView_Columns", m_pServiceList->saveState());
	if (m_pMenuKernelServices)
		theConf->SetValue(objectName() + "/ShowKernelServices", m_pMenuKernelServices->isChecked());
}

void CServicesView::OnResetColumns()
{
	for (int i = 0; i < m_pServiceModel->columnCount(); i++)
		m_pServiceList->SetColumnHidden(i, true);

	m_pServiceList->SetColumnHidden(CServiceModel::eService, false);
	// Both are meaningful on Linux too: the unit Description and the unit type.
	m_pServiceList->SetColumnHidden(CServiceModel::eDisplayName, false);
	m_pServiceList->SetColumnHidden(CServiceModel::eType, false);
	m_pServiceList->SetColumnHidden(CServiceModel::eStatus, false);
	m_pServiceList->SetColumnHidden(CServiceModel::eStartType, false);
	if (m_bAll) {
		m_pServiceList->SetColumnHidden(CServiceModel::ePID, false);
		m_pServiceList->SetColumnHidden(CServiceModel::eBinaryPath, false);
	}
}

void CServicesView::OnColumnsChanged()
{
	Refresh();
}

void CServicesView::OnViewSystemChanged()
{
	m_ServiceList.clear();
	m_pServiceModel->Clear();
}

void CServicesView::OnServiceListUpdated(QSet<QString> Added, QSet<QString> Changed, QSet<QString> Removed)
{
	m_ServiceList = CCluster::GetViewSystem()->GetServiceList();
}

void CServicesView::Refresh()
{
	if (m_pMenuKernelServices)
		m_pServiceModel->SetShowKernelServices(m_pMenuKernelServices->isChecked());
	else
		m_pServiceModel->SetShowKernelServices(false);
	m_pServiceModel->Sync(m_ServiceList);
}

void CServicesView::ShowProcesses(const QList<CProcessPtr>& Processes)
{
	m_ServiceList.clear();

	// one service list per system rather than per process - with several systems
	// in view a name alone no longer identifies a service
	QMap<CSystemAPI*, QMap<QString, CServicePtr> > ServiceLists;
	foreach(const CProcessPtr& pProcess, Processes)
	{
		//
		// The strong reference is held for the body of the loop; the map is keyed
		// by the bare pointer, which is only ever compared and never followed.
		//
		const CSystemPtr pSystem = pProcess->GetSystem();
		if (pSystem.isNull())
			continue;
		if (!ServiceLists.contains(pSystem.data()))
			ServiceLists.insert(pSystem.data(), pSystem->GetServiceList());
		const QMap<QString, CServicePtr>& AllServices = ServiceLists[pSystem.data()];

		foreach(const QString& ServiceName, pProcess->GetServiceList())
		{
			CServicePtr pService = AllServices.value(ServiceName.toLower());
			if (!pService)
				pService = pSystem->GetService(ServiceName);
			if (!pService)
				continue;
			m_ServiceList.insert(ServiceName.toLower(), pService);
		}
	}

	m_pServiceModel->Sync(m_ServiceList);
}

void CServicesView::OnMenu(const QPoint &point)
{
	QModelIndexList selectedRows = m_pServiceList->selectedRows();

	int CanStart = 0;
	int CanStop = 0;
	int CanPause = 0;
	int CanContinue = 0;
	int IsDriver = 0;
	foreach(const QModelIndex& Index, selectedRows)
	{
		QModelIndex ModelIndex = m_pSortProxy->mapToSource(Index);
		CServicePtr pService = m_pServiceModel->GetService(ModelIndex);
		if (pService.isNull())
			continue;

		if (pService->IsDriver())
			IsDriver ++;

		switch (pService->GetState())
        {
			case CServiceInfo::eSvcRunning:
				if (pService->GetControlsAccepted() & CServiceInfo::eSvcAcceptPauseContinue)
					CanPause++;
				if (pService->GetControlsAccepted() & CServiceInfo::eSvcAcceptStop)
					CanStop++;
            break;
			case CServiceInfo::eSvcPaused:
				if (pService->GetControlsAccepted() & CServiceInfo::eSvcAcceptPauseContinue)
					CanContinue++;
				if (pService->GetControlsAccepted() & CServiceInfo::eSvcAcceptStop)
					CanStop++;
            break;
			case CServiceInfo::eSvcStopped:
				CanStart++;
            break;
			case CServiceInfo::eSvcStartPending:
			case CServiceInfo::eSvcContinuePending:
			case CServiceInfo::eSvcPausePending:
			case CServiceInfo::eSvcStopPending:
            break;
        }
	}

	m_pMenuOpen->setEnabled(CanStart > 0);
	m_pMenuStart->setEnabled(CanStart > 0);
	m_pMenuContinue->setEnabled(CanContinue > 0);
	m_pMenuPause->setEnabled(CanPause > 0);
	m_pMenuStop->setEnabled(CanStop > 0);

	m_pMenuDelete->setEnabled(selectedRows.count() >= 1);
	m_pMenuOpenKey->setEnabled(selectedRows.count() == 1);
	m_pMenuOpenProcess->setEnabled(selectedRows.count() == 1 && IsDriver == 0);
	CPanelView::OnMenu(point);
}

void CServicesView::OnServiceAction()
{
	QList<STATUS> Errors;
	int Force = -1;
	foreach(const QModelIndex& Index, m_pServiceList->selectedRows())
	{
		QModelIndex ModelIndex = m_pSortProxy->mapToSource(Index);
		CServicePtr pService = m_pServiceModel->GetService(ModelIndex);
		if (!pService.isNull())
		{
retry:
			STATUS Status = OK;
			if (sender() == m_pMenuStart)
				Status = pService->Start();
			else if (sender() == m_pMenuStop)
				Status = pService->Stop();
			else if (sender() == m_pMenuPause)
				Status = pService->Pause();
			else if (sender() == m_pMenuContinue)
				Status = pService->Continue();
			else if (sender() == m_pMenuDelete)
				Status = pService->Delete(Force == 1);
			else if (sender() == m_pMenuOpenKey)
				Status = ::OpenRegistryKey(pService->GetSystem().data(), pService->GetRegistryKey());
			else if (sender() == m_pMenuViewLog)
				Status = pService->ViewLog();
			else if (sender() == m_pMenuOpenProcess)
			{
				//
				// Portable: the pid comes from the service object either way.
				// Units with no process - a timer that is not firing, a socket
				// that has not been connected to - report 0.
				//
				const quint64 Pid = pService->GetPID();
				if (!Pid)
					Status = ERR(TE_Message, QVariantList() << tr("This unit has no running process."));
				else
				{
					CProcessPtr pProcess;
					if (CSystemPtr pSvcSystem = pService->GetSystem())
						pProcess = pSvcSystem->GetProcessByID(Pid);
					if (pProcess.isNull())
						Status = ERR(TE_Message, QVariantList() << tr("The process of this unit is no longer running."));
					else
					{
						CTaskInfoWindow* pTaskInfoWindow = new CTaskInfoWindow(QList<CProcessPtr>() << pProcess);
						pTaskInfoWindow->show();
					}
				}
			}

			if (Status.IsError())
			{
				if (Status.GetStatus() == ERROR_CONFIRM)
				{
					if (Force == -1)
					{
						switch (QMessageBox("TaskExplorer", CTaskExplorer::FormatError(Status), QMessageBox::Question, QMessageBox::Yes, QMessageBox::No, QMessageBox::Cancel | QMessageBox::Default | QMessageBox::Escape).exec())
						{
						case QMessageBox::Yes:
							Force = 1;
							goto retry;
							break;
						case QMessageBox::No:
							Force = 0;
							break;
						case QMessageBox::Cancel:
							return;
						}
					}
				}
				else
					Errors.append(Status);
			}
		}
	}

	CTaskExplorer::CheckErrors(Errors);
}


void CServicesView::OnDoubleClicked()
{
	QModelIndex Index = m_pServiceList->currentIndex();
	QModelIndex ModelIndex = m_pSortProxy->mapToSource(Index);
	CServicePtr pService = m_pServiceModel->GetService(ModelIndex);

	//
	// Still compile-time gated: CWinSvcWindow is a Windows-only dialog that is
	// not built on Linux yet. It needs the same treatment as the views before
	// this can become a runtime check.
	//
#ifdef WIN32
	CWinSvcWindow* pWnd = new CWinSvcWindow(pService);
	connect(pWnd, SIGNAL(ServicesChanged()), theGUI, SLOT(OnReloadService()));
	pWnd->show();
#endif
}
