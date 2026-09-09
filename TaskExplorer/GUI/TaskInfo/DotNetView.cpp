#include "stdafx.h"
#include "DotNetView.h"
#include "../../../MiscHelpers/Common/Finder.h"
#include "../TaskExplorer.h"
#include "../DesktopActions.h"
CDotNetView::CDotNetView(QWidget *parent)
	:CPanelView(parent)
{
	m_pMainLayout = new QVBoxLayout();
	m_pMainLayout->setContentsMargins(0, 0, 0, 0);
	this->setLayout(m_pMainLayout);

	m_pFilterWidget = new QWidget();
	m_pMainLayout->addWidget(m_pFilterWidget);

	m_pFilterLayout = new QHBoxLayout();
	m_pFilterLayout->setContentsMargins(3, 3, 3, 3);
	m_pFilterWidget->setLayout(m_pFilterLayout);


	m_pRefresh = new QPushButton(tr("Refresh"));
	connect(m_pRefresh, SIGNAL(pressed()), this, SLOT(OnRefresh()));
	m_pFilterLayout->addWidget(m_pRefresh);
	m_pFilterLayout->addItem(new QSpacerItem(0, 0, QSizePolicy::Expanding, QSizePolicy::Minimum));

	m_pSplitter = new QSplitter();
	m_pSplitter->setOrientation(Qt::Vertical);
	m_pMainLayout->addWidget(m_pSplitter);

	// Assembly List
	m_pAssemblyModel = new CSimpleTreeModel();
	m_pAssemblyModel->AddColumn(tr("Structure"), "Structure");
	m_pAssemblyModel->AddColumn(tr("File Name"), "FileName");
	m_pAssemblyModel->AddColumn(tr("Flags"), "Flags");
	m_pAssemblyModel->AddColumn(tr("ID"), "ID");
	m_pAssemblyModel->AddColumn(tr("Native Path"), "NativePath");

	m_pSortProxy = new CSortFilterProxyModel(this);
	m_pSortProxy->setSortRole(Qt::EditRole);
    m_pSortProxy->setSourceModel(m_pAssemblyModel);
	m_pSortProxy->setDynamicSortFilter(true);

	m_pAssemblyList = new QTreeViewEx();
	m_pAssemblyList->setItemDelegate(theGUI->GetItemDelegate());
	
	m_pAssemblyList->setModel(m_pSortProxy);

	m_pAssemblyList->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_pAssemblyList->setSortingEnabled(true);

	m_pAssemblyList->setContextMenuPolicy(Qt::CustomContextMenu);
	connect(m_pAssemblyList, SIGNAL(customContextMenuRequested( const QPoint& )), this, SLOT(OnMenu(const QPoint &)));

	connect(m_pAssemblyList, SIGNAL(doubleClicked(const QModelIndex&)), this, SLOT(OnDoubleClicked()));

	m_pAssemblyList->setColumnReset(2);
	connect(m_pAssemblyList, SIGNAL(ResetColumns()), this, SLOT(OnResetColumns()));
	connect(m_pAssemblyList, SIGNAL(ColumnChanged(int, bool)), this, SLOT(OnColumnsChanged()));

	m_pSplitter->addWidget(CFinder::AddFinder(m_pAssemblyList, m_pSortProxy));
	m_pSplitter->setCollapsible(0, false);
	// 

	// Performance Details
	m_pPerfStats = new CPanelWidgetEx();

	m_pPerfStats->GetView()->setItemDelegate(theGUI->GetItemDelegate());
	((QTreeWidgetEx*)m_pPerfStats->GetView())->setHeaderLabels(tr("Counter|Value").split("|"));

	m_pPerfStats->GetView()->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_pPerfStats->GetView()->setSortingEnabled(false);

	m_pSplitter->addWidget(m_pPerfStats);
	//

	CreatePerfTree();


	//m_pMenu = new QMenu();
	
	m_pOpen = m_pMenu->addAction(tr("Open File"), this, SLOT(OnDoubleClicked()));

	AddPanelItemsToMenu();

	setObjectName(parent->objectName());
	QByteArray Columns = theConf->GetBlob(objectName() + "/DotNetView_Columns");
	if (Columns.isEmpty())
		OnResetColumns();
	else
		m_pAssemblyList->restoreState(Columns);
	m_pPerfStats->GetView()->header()->restoreState(theConf->GetBlob(objectName() + "/PerfStats_Columns"));
	m_pSplitter->restoreState(theConf->GetBlob(objectName() + "/DotNetView_Splitter"));
}

CDotNetView::~CDotNetView()
{
	theConf->SetBlob(objectName() + "/DotNetView_Columns", m_pAssemblyList->saveState());
	theConf->SetBlob(objectName() + "/DotNetView_Splitter",m_pSplitter->saveState());
	if(m_pPerfStats)
		theConf->SetBlob(objectName() + "/PerfStats_Columns", m_pPerfStats->GetView()->header()->saveState());
}

void CDotNetView::OnResetColumns()
{
	for (int i = 0; i < m_pAssemblyModel->columnCount(); i++)
		m_pAssemblyList->SetColumnHidden(i, true);

	m_pAssemblyList->SetColumnHidden(eStructure, false);
	m_pAssemblyList->SetColumnHidden(eFileName, false);
	m_pAssemblyList->SetColumnHidden(eFlags, false);
}

void CDotNetView::OnColumnsChanged()
{
	m_pAssemblyModel->Sync(m_Assemblies);
}

void CDotNetView::ShowProcesses(const QList<CProcessPtr>& Processes)
{
	CProcessPtr pProcess;
	if (Processes.count() > 1)
	{
		setEnabled(false);
	}
	else if(!Processes.isEmpty())
	{
		setEnabled(true);
		pProcess = Processes.first();
	}

	if (m_pCurProcess != pProcess)
	{
		m_pCurProcess = pProcess;

		m_pAssemblyModel->Clear();
	}

	OnRefresh();
	Refresh();
}

void CDotNetView::OnRefresh()
{
	QObject::disconnect(this, SLOT(OnAssemblies(const CAssemblyListPtr&)));

	if (!m_pCurProcess || !m_pCurProcess->IsNetProcess()) {
		m_Assemblies.clear();
		return;
	}

	CAssemblyEnumerator* pEnum = m_pCurProcess->GetAssemblyEnumerator(this);
	if (!pEnum) {
		m_Assemblies.clear();
		return;
	}

	QObject::connect(pEnum, SIGNAL(Assemblies(const CAssemblyListPtr&)), this, SLOT(OnAssemblies(const CAssemblyListPtr&)));
	QObject::connect(pEnum, SIGNAL(Finished()), pEnum, SLOT(deleteLater()));

	pEnum->start();
}

void CDotNetView::OnAssemblies(const CAssemblyListPtr& Assemblies)
{
	m_Assemblies.clear();

	for (int i = 0; i < Assemblies->GetCount(); i++)
	{
		auto& Assembly = Assemblies->GetAssembly(i);

		QVariantMap Item;
		Item["ID"] = Assembly.ID;
		Item["ParentID"] = Assembly.ParentID;

		Item["Structure"] = Assembly.Structure;
		Item["FileName"] = Assembly.FileName;
		Item["Flags"] = Assembly.Flags;
		Item["ID"] = Assembly.ID;
		Item["NativePath"] = Assembly.NativePath;

		ASSERT(!m_Assemblies.contains(Assembly.ID));
		m_Assemblies.insert(Assembly.ID, Item);
	}

	m_pAssemblyModel->Sync(m_Assemblies);

	m_pAssemblyList->expandAll();
}

void CDotNetView::Refresh()
{
	if (!m_pCurProcess)
		return;

	if (m_pSplitter->sizes()[1] > 0)
	{
		UpdatePerfTree();
	}
}

void CDotNetView::OnMenu(const QPoint &point)
{
	QModelIndex Index = m_pAssemblyList->currentIndex();
	QModelIndex ModelIndex = m_pSortProxy->mapToSource(Index);
	QString FileName = ModelIndex.isValid() ? m_pAssemblyModel->Data(ModelIndex, Qt::EditRole, eFileName).toString() : "";

	m_pOpen->setEnabled(!FileName.isEmpty());

	CPanelView::OnMenu(point);
}

void CDotNetView::OnDoubleClicked()
{
	QModelIndex Index = m_pAssemblyList->currentIndex();
	QModelIndex ModelIndex = m_pSortProxy->mapToSource(Index);
	QString FileName = ModelIndex.isValid() ? m_pAssemblyModel->Data(ModelIndex, Qt::EditRole, eFileName).toString() : "";

	if (!FileName.isEmpty())
	{
		::ExploreFile(theSystem.data(), FileName);
	}
}