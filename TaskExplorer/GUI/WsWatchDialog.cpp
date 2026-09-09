/*
 * Task Explorer -
 *   qt port of "working set watch" from the ExtendedTools Plugin
 *
 * Copyright (C) 2011 wj32
 * Copyright (C) 2018 dmex
 * Copyright (C) 2019 David Xanatos
 *
 * This file is part of Task Explorer and contains System Informer code.
 *
 */

#include "stdafx.h"
#include "WsWatchDialog.h"
#include "TaskExplorer.h"
#include "../../MiscHelpers/Common/Settings.h"

class CSWorkingSetItem : public QTreeWidgetItem
{
public:
	CSWorkingSetItem(QTreeWidget* parent = NULL) : QTreeWidgetItem(parent) {}

private:
	virtual bool operator< (const QTreeWidgetItem &other) const
	{
		int column = treeWidget()->sortColumn();
		return data(column, Qt::UserRole).toUInt() < other.data(column, Qt::UserRole).toUInt();
	}
};

CWsWatchDialog::CWsWatchDialog(const CProcessPtr& pProcess, QWidget *parent)
	: QMainWindow(parent)
{
	m_pProcess = pProcess;

	this->setWindowTitle(tr("Working Set Watch"));

	m_pMainWidget = new QWidget();
    m_pMainWidget->setMinimumSize(QSize(430, 210));

    m_pMainLayout = new QGridLayout();
	m_pMainWidget->setLayout(m_pMainLayout);

	m_pInfoLabel = new QLabel();
    m_pInfoLabel->setWordWrap(true);
	m_pInfoLabel->setText(tr("Working set watch allows you to monitor page faults that occur in a process. "
		"You must enable WS watch for the process to start the monitoring. Once WS watch is enabled, it cannot be disabled."));
    m_pMainLayout->addWidget(m_pInfoLabel, 0, 0, 1, 4);

	m_pEnableBtn = new QPushButton();
	m_pEnableBtn->setText(tr("Enable"));
    m_pMainLayout->addWidget(m_pEnableBtn, 1, 0, 1, 1);

	m_pEnabledLbl = new QLabel();
	m_pEnabledLbl->setText(tr("WS watch is enabled."));
    m_pMainLayout->addWidget(m_pEnabledLbl, 1, 1, 1, 1);

	m_pMainLayout->addItem(new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum), 1, 2, 1, 1);

	m_pMainLayout->addWidget(new QLabel(tr("Page faults:")), 2, 0, 1, 4);

	m_pFaultList = new CPanelWidgetEx();
	m_pFaultList->GetTree()->setHeaderLabels(tr("Count|Instruction").split("|"));
	m_pFaultList->GetTree()->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_pFaultList->GetTree()->setSortingEnabled(true);
    m_pMainLayout->addWidget(m_pFaultList, 3, 0, 1, 4);

    m_pButtonBox = new QDialogButtonBox();
    m_pButtonBox->setStandardButtons(QDialogButtonBox::Close);
    m_pMainLayout->addWidget(m_pButtonBox, 4, 0, 1, 4);

	this->setCentralWidget(m_pMainWidget);

	connect(m_pEnableBtn, SIGNAL(pressed()), this, SLOT(OnEnable()));
	//connect(m_pButtonBox, SIGNAL(accepted()), this, SLOT(accept()));
	connect(m_pButtonBox, SIGNAL(rejected()), this, SLOT(reject()));

	restoreGeometry(theConf->GetBlob("WsWatchWindow/Window_Geometry"));
	m_pFaultList->GetTree()->header()->restoreState(theConf->GetBlob("WsWatchWindow/FaultList_Columns"));

	m_TimerId = -1;

	if (Refresh())
	{
		m_TimerId = startTimer(1000);
		m_pEnableBtn->setEnabled(false);
	}
	else
		m_pEnabledLbl->setVisible(false);
}

CWsWatchDialog::~CWsWatchDialog()
{
	theConf->SetBlob("WsWatchWindow/Window_Geometry", saveGeometry());
	theConf->SetBlob("WsWatchWindow/FaultList_Columns", m_pFaultList->GetTree()->header()->saveState());

	if(m_TimerId != -1)
		killTimer(m_TimerId);
}

void CWsWatchDialog::closeEvent(QCloseEvent *e)
{
	this->deleteLater();
}

/*void CWsWatchDialog::accept()
{

}*/

void CWsWatchDialog::reject()
{
	this->close();
}

void CWsWatchDialog::OnEnable()
{
	STATUS Status = m_pProcess->EnableWsWatch();

	m_pEnableBtn->setEnabled(false);
	m_pEnabledLbl->setVisible(true);

	if (!Status.IsError())
		m_TimerId = startTimer(1000);
	else
		m_pEnabledLbl->setText(tr("Unable to enable WS watch, error: %1").arg(CTaskExplorer::FormatError(Status)));
}

void CWsWatchDialog::timerEvent(QTimerEvent *e)
{
	if (e->timerId() != m_TimerId)
	{
		QMainWindow::timerEvent(e);
		return;
	}

	Refresh();
}

bool CWsWatchDialog::Refresh()
{
	//
	// One entry per fault, so a repeated address means repeated faults - the
	// tally is kept here rather than by the collector.
	//
	QList<quint64> Faults;
	bool bEnabled = false;
	if (m_pProcess->GetWsWatchFaults(Faults, bEnabled).IsError())
		return bEnabled;

	foreach(quint64 FaultingPc, Faults)
	{
		QTreeWidgetItem* &pItem = m_FailtList[FaultingPc];

		quint32 newCount;
        if (pItem)
        {
            newCount = pItem->data(1, Qt::UserRole).toUInt() + 1;
        }
        else
        {
			pItem = new CSWorkingSetItem();
			m_pFaultList->GetTree()->addTopLevelItem(pItem);

			pItem->setData(0, Qt::UserRole, FaultingPc);
			pItem->setText(0, FormatAddress(FaultingPc));

			if (CSystemPtr pSystem = m_pProcess->GetSystem())
			{
				pSystem->GetSymbolFromAddress(m_pProcess->GetProcessId(), FaultingPc, this,
					SLOT(OnSymbolFromAddress(quint64, quint64, int, const QString&, const QString&, const QString&)));
			}

			newCount = 1;
        }

        pItem->setData(1, Qt::UserRole, newCount);
		pItem->setText(1, FormatNumber(newCount));
	}

	return bEnabled;
}

void CWsWatchDialog::OnSymbolFromAddress(quint64 ProcessId, quint64 Address, int ResolveLevel, const QString& StartAddressString, const QString& FileName, const QString& SymbolName)
{
	// the row may be gone by the time a lookup comes back
	QTreeWidgetItem* pItem = m_FailtList.value(Address);
	if (pItem)
		pItem->setText(0, StartAddressString);
}
