#include "stdafx.h"
#include "../../TaskExplorer.h"
#include "DriversView.h"
#include "../../../API/Cluster.h"
#include "../../../../MiscHelpers/Common/Common.h"
#include "../../../../MiscHelpers/Common/SortFilterProxyModel.h"
#include "../../../../MiscHelpers/Common/Finder.h"

CDriversView::CDriversView(QWidget *parent)
	:CPanelView(parent)
{
	m_pMainLayout = new QVBoxLayout();
	m_pMainLayout->setContentsMargins(0, 0, 0, 0);
	this->setLayout(m_pMainLayout);

	m_pDriverModel = new CDriverModel();
	
	m_pSortProxy = new CSortFilterProxyModel(this);
	m_pSortProxy->setSortRole(Qt::EditRole);
    m_pSortProxy->setSourceModel(m_pDriverModel);
	m_pSortProxy->setDynamicSortFilter(true);


	// Driver List
	m_pDriverList = new QTreeViewEx();
	m_pDriverList->setItemDelegate(theGUI->GetItemDelegate());

	m_pDriverList->setModel(m_pSortProxy);

	m_pDriverList->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_pDriverList->setSortingEnabled(true);

	m_pDriverList->setContextMenuPolicy(Qt::CustomContextMenu);
	connect(m_pDriverList, SIGNAL(customContextMenuRequested( const QPoint& )), this, SLOT(OnMenu(const QPoint &)));

	connect(theGUI, SIGNAL(ReloadPanels()), m_pDriverModel, SLOT(Clear()));

	m_pDriverList->setColumnReset(2);
	connect(m_pDriverList, SIGNAL(ResetColumns()), this, SLOT(OnResetColumns()));
	connect(m_pDriverList, SIGNAL(ColumnChanged(int, bool)), this, SLOT(OnColumnsChanged()));

	m_pMainLayout->addWidget(m_pDriverList);
	// 

	m_pMainLayout->addWidget(new CFinder(m_pSortProxy, this));

	QByteArray Columns = theConf->GetBlob(objectName() + "/DriversView_Columns");
	if (Columns.isEmpty())
		OnResetColumns();
	else
		m_pDriverList->restoreState(Columns);

	//m_pMenu = new QMenu();
	AddPanelItemsToMenu();

	//
	// Through the link rather than straight at theSystem, which is this machine
	// and not necessarily the one being looked at. The other kernel tabs may
	// only ever show the local machine because they reach into Windows kernel
	// tables directly, but this list is one both collectors fill and the wire
	// carries, so it follows the selection like the rest of the panel.
	//
	new CViewSystemLink(this, SIGNAL(DriverListUpdated(QSet<QString>, QSet<QString>, QSet<QString>)),
		SLOT(OnDriverListUpdated(QSet<QString>, QSet<QString>, QSet<QString>)));
}


CDriversView::~CDriversView()
{
	theConf->SetBlob(objectName() + "/DriversView_Columns", m_pDriverList->saveState());
}

void CDriversView::OnResetColumns()
{
	for (int i = 0; i < m_pDriverModel->columnCount(); i++)
		m_pDriverList->SetColumnHidden(i, true);

	//
	// The same list either way, but the two kinds of machine describe their
	// kernel modules differently: Windows has a signed binary with a version
	// resource, Linux has a refcount and the modules holding it. Asked of the
	// machine being looked at, not the one doing the looking.
	//
	CSystemPtr pSystem = CCluster::GetViewSystem();
	const bool bWindows = pSystem.isNull()
		|| pSystem->GetOsType() == CSystemAPI::eOsWindows;

	m_pDriverList->SetColumnHidden(CDriverModel::eDriver, false);
	if (bWindows)
		m_pDriverList->SetColumnHidden(CDriverModel::eDescription, false);
	else
	{
		m_pDriverList->SetColumnHidden(CDriverModel::eImageSize, false);
		m_pDriverList->SetColumnHidden(CDriverModel::eRefCount, false);
		m_pDriverList->SetColumnHidden(CDriverModel::eUsedBy, false);
		m_pDriverList->SetColumnHidden(CDriverModel::eState, false);
	}
	m_pDriverList->SetColumnHidden(CDriverModel::eBinaryPath, false);
}

void CDriversView::OnColumnsChanged()
{
	m_pDriverModel->Sync(m_DriverList);
}

void CDriversView::Refresh()
{
	CSystemPtr pSystem = CCluster::GetViewSystem();
	if (pSystem.isNull())
		return;

	QTimer::singleShot(0, pSystem.data(), SLOT(UpdateDriverList()));
}

void CDriversView::OnDriverListUpdated(QSet<QString> Added, QSet<QString> Changed, QSet<QString> Removed)
{
	CSystemPtr pSystem = CCluster::GetViewSystem();
	if (pSystem.isNull())
		return;

	m_DriverList = pSystem->GetDriverList();

	m_pDriverModel->Sync(m_DriverList);
}
