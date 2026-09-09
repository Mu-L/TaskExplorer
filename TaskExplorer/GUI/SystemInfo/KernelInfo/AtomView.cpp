/*
 * Task Explorer -
 *   qt port of the NT Atom Table Plugin
 *
 * Copyright (C) 2015 dmex
 * Copyright (C) 2019 David Xanatos
 *
 * This file is part of Task Explorer and contains System Informer code.
 * 
 */

#include "stdafx.h"
#include "../../TaskExplorer.h"
#include "AtomView.h"
#include "../../../../MiscHelpers/Common/KeyValueInputDialog.h"
#include "../../../../MiscHelpers/Common/Finder.h"


CAtomView::CAtomView(QWidget *parent)
	:CPanelView(parent)
{
	m_pMainLayout = new QVBoxLayout();
	m_pMainLayout->setContentsMargins(0, 0, 0, 0);
	this->setLayout(m_pMainLayout);

	// Atom List
	m_pAtomModel = new CSimpleListModel();
	m_pAtomModel->setHeaderLabels(tr("Atom name|Ref. count").split("|"));

	m_pSortProxy = new CSortFilterProxyModel(this);
	m_pSortProxy->setSortRole(Qt::EditRole);
    m_pSortProxy->setSourceModel(m_pAtomModel);
	m_pSortProxy->setDynamicSortFilter(true);

	m_pAtomList = new QTreeViewEx();
	m_pAtomList->setItemDelegate(theGUI->GetItemDelegate());
	
	m_pAtomList->setModel(m_pSortProxy);

	m_pAtomList->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_pAtomList->setSortingEnabled(true);

	m_pAtomList->setContextMenuPolicy(Qt::CustomContextMenu);
	connect(m_pAtomList, SIGNAL(customContextMenuRequested( const QPoint& )), this, SLOT(OnMenu(const QPoint &)));

	//m_pAtomList->setColumnReset(2);
	//connect(m_pAtomList, SIGNAL(ResetColumns()), this, SLOT(OnResetColumns()));
	//connect(m_pAtomList, SIGNAL(ColumnChanged(int, bool)), this, SLOT(OnColumnsChanged()));

	//connect(m_pAtomList, SIGNAL(doubleClicked(const QModelIndex&)), this, SLOT(OnItemDoubleClicked(const QModelIndex&)));
	m_pMainLayout->addWidget(m_pAtomList);
	// 

	m_pMainLayout->addWidget(new CFinder(m_pSortProxy, this));

	//m_pMenu = new QMenu();
	m_pDelete = m_pMenu->addAction(tr("Delete"), this, SLOT(OnDelete()));
	
	AddPanelItemsToMenu();

	setObjectName(parent->objectName());
	QByteArray Columns = theConf->GetBlob(objectName() + "/AtomView_Columns");
	if (Columns.isEmpty())
		m_pAtomList->OnResetColumns();
	else
		m_pAtomList->restoreState(Columns);
}

CAtomView::~CAtomView()
{
	theConf->SetBlob(objectName() + "/AtomView_Columns", m_pAtomList->saveState());
}

void CAtomView::Refresh()
{
	m_Atoms.clear();

	foreach(const CSystemAPI::SAtom& Atom, theSystem->GetAtomTable())
	{
		//
		// The backend reports flags; the wording is decided here, so it is in the
		// reader's language and not the collector's.
		//
		QString Name;
		if (Atom.Unreadable)
			Name = tr("(Error) #%1").arg(Atom.Id);
		else if (Atom.Pinned)
			Name = tr("%1 (Pinned)").arg(Atom.Name);
		else
			Name = Atom.Name;

		QVariantMap Values;
		Values.insert(QString::number(eName), Name);
		Values.insert(QString::number(eRefCount), FormatNumber(Atom.RefCount));

		QVariantMap Item;
		Item["ID"] = Atom.Id;
		Item["Values"] = Values;
		m_Atoms.append(Item);
	}

	m_pAtomModel->Sync(m_Atoms);
}

void CAtomView::OnMenu(const QPoint &point)
{
	QModelIndex Index = m_pAtomList->currentIndex();
	QModelIndex ModelIndex = m_pSortProxy->mapToSource(Index);
	QString Name = ModelIndex.isValid() ? m_pAtomModel->Data(ModelIndex, Qt::EditRole, eName).toString() : "";

	m_pDelete->setEnabled(!Name.isEmpty());

	CPanelView::OnMenu(point);
}

void CAtomView::OnDelete()
{
	QModelIndex Index = m_pAtomList->currentIndex();
	QModelIndex ModelIndex = m_pSortProxy->mapToSource(Index);
	if (!ModelIndex.isValid())
		return;

	QString Name = m_pAtomModel->Data(ModelIndex, Qt::EditRole, eName).toString();
	quint32 AtomId = m_pAtomModel->GetItemID(ModelIndex).toUInt();

	if (QMessageBox("TaskExplorer", tr("Do you want to delete the atom: %1").arg(Name), QMessageBox::Question, QMessageBox::Yes, QMessageBox::No | QMessageBox::Default | QMessageBox::Escape, QMessageBox::NoButton).exec() != QMessageBox::Yes)
		return;

	STATUS Status = theSystem->DeleteAtom(AtomId);
	CTaskExplorer::CheckErrors(QList<STATUS>() << Status);

	Refresh();
}
