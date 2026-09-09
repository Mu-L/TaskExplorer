#include "stdafx.h"
#include "../TaskExplorer.h"
#include "GDIView.h"
#include "../../../MiscHelpers/Common/KeyValueInputDialog.h"
#include "../../../MiscHelpers/Common/Finder.h"
#include "../../API/Windows/WinProcess.h"


CGDIView::CGDIView(QWidget *parent)
	:CPanelView(parent)
{
	m_pMainLayout = new QVBoxLayout();
	m_pMainLayout->setContentsMargins(0, 0, 0, 0);
	this->setLayout(m_pMainLayout);

	// GDI List
	m_pGDIModel = new CGDIModel();

	m_pSortProxy = new CSortFilterProxyModel(this);
	m_pSortProxy->setSortRole(Qt::EditRole);
    m_pSortProxy->setSourceModel(m_pGDIModel);
	m_pSortProxy->setDynamicSortFilter(true);

	m_pGDIList = new QTreeViewEx();
	m_pGDIList->setItemDelegate(theGUI->GetItemDelegate());
	
	m_pGDIList->setModel(m_pSortProxy);

	m_pGDIList->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_pGDIList->setSortingEnabled(true);

	m_pGDIList->setContextMenuPolicy(Qt::CustomContextMenu);
	connect(m_pGDIList, SIGNAL(customContextMenuRequested( const QPoint& )), this, SLOT(OnMenu(const QPoint &)));

	m_pGDIList->setColumnReset(2);
	connect(m_pGDIList, SIGNAL(ResetColumns()), this, SLOT(OnResetColumns()));
	connect(m_pGDIList, SIGNAL(ColumnChanged(int, bool)), this, SLOT(OnColumnsChanged()));

	//connect(m_pGDIList, SIGNAL(doubleClicked(const QModelIndex&)), this, SLOT(OnItemDoubleClicked(const QModelIndex&)));
	m_pMainLayout->addWidget(m_pGDIList);
	// 

	m_pMainLayout->addWidget(new CFinder(m_pSortProxy, this));

	AddPanelItemsToMenu();

	m_ViewMode = eNone;
	setObjectName(parent->objectName());
	SwitchView(eSingle);
}

CGDIView::~CGDIView()
{
	SwitchView(eNone);
}

void CGDIView::SwitchView(EView ViewMode)
{
	switch (m_ViewMode)
	{
		case eSingle:	theConf->SetBlob(objectName() + "/GDIView_Columns", m_pGDIList->saveState()); break;
		case eMulti:	theConf->SetBlob(objectName() + "/GDIMultiView_Columns", m_pGDIList->saveState()); break;
	}

	m_ViewMode = ViewMode;

	QByteArray Columns;
	switch (m_ViewMode)
	{
		case eSingle:	Columns = theConf->GetBlob(objectName() + "/GDIView_Columns"); break;
		case eMulti:	Columns = theConf->GetBlob(objectName() + "/GDIMultiView_Columns"); break;
		default:
			return;
	}
	
	if (Columns.isEmpty())
		OnResetColumns();
	else
		m_pGDIList->restoreState(Columns);
}

void CGDIView::OnResetColumns()
{
	for (int i = 0; i < m_pGDIModel->columnCount(); i++)
		m_pGDIList->SetColumnHidden(i, false);

	if(m_ViewMode == eSingle)
		m_pGDIList->SetColumnHidden(CGDIModel::eProcess, true);
}

void CGDIView::OnColumnsChanged()
{
	m_pGDIModel->Sync(m_GDIList);
}

void CGDIView::ShowProcesses(const QList<CProcessPtr>& Processes)
{
	if (m_Processes == Processes)
		return;

	m_Processes = Processes;

	SwitchView(m_Processes.size() > 1 ? eMulti : eSingle);

	m_GDIList.clear();

	Refresh();
}

void CGDIView::Refresh()
{
	bool bInitTimeStamp = !m_GDIList.isEmpty();

	QMap<quint64, CGdiPtr> OldList = m_GDIList;

	foreach(const CProcessPtr& pProcess, m_Processes)
	{
		QMap<quint64, CGdiPtr> Current = pProcess->GetGdiList();

		for (QMap<quint64, CGdiPtr>::const_iterator I = Current.constBegin(); I != Current.constEnd(); ++I)
		{
			if (!OldList.take(I.key()).isNull())
				continue; // already listed - keep the existing entry and its timestamp

			CGdiPtr pWinGDI = I.value();
			if (bInitTimeStamp)
				pWinGDI->InitTimeStamp();
			m_GDIList.insert(pWinGDI->GetHandleId(), pWinGDI);
		}
	}

	foreach(quint64 HandleId, OldList.keys())
	{
		CGdiPtr pWinGDI = m_GDIList.value(HandleId);
		if (pWinGDI->CanBeRemoved())
			m_GDIList.remove(HandleId);
		else if (!pWinGDI->IsMarkedForRemoval())
			pWinGDI->MarkForRemoval();
	}


	m_pGDIModel->Sync(m_GDIList);
}

void CGDIView::OnMenu(const QPoint &point)
{
	CPanelView::OnMenu(point);
}
