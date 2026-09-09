#include "stdafx.h"
#include "../../MiscHelpers/Common/Settings.h"
#include "MultiErrorDialog.h"
#include "../API/SystemAPI.h"
#include "TaskExplorer.h"


CMultiErrorDialog::CMultiErrorDialog(const QString& Message, QList<STATUS> Errors, QWidget* parent)
	: QDialog(parent)
{
	this->setWindowTitle(tr("TaskExplorer - Error"));
	m_pMainLayout = new QGridLayout(this);

	int Row = 0;
	m_pMainLayout->addWidget(new QLabel(Message), Row++, 0, 1, 4);

	m_pErrors = new CPanelWidgetEx();
	
	m_pErrors->GetTree()->setHeaderLabels(tr("Message|Status|Error").split("|"));

	m_pErrors->GetView()->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_pErrors->GetView()->setSortingEnabled(false);

	m_pMainLayout->addWidget(m_pErrors, Row++, 0, 1, 4);

	m_pButtonBox = new QDialogButtonBox();
	m_pButtonBox->setOrientation(Qt::Horizontal);
	m_pButtonBox->setStandardButtons(QDialogButtonBox::Ok|QDialogButtonBox::Cancel);
	m_pMainLayout->addWidget(m_pButtonBox, Row++, 0, 1, 4);
 
	connect(m_pButtonBox,SIGNAL(accepted()),this,SLOT(accept()));
	connect(m_pButtonBox,SIGNAL(rejected()),this,SLOT(reject()));

	//
	// Wide enough to read a sentence in, the first time it is opened. After
	// that whatever size it was left at is what it opens as.
	//
	if (!restoreGeometry(theConf->GetBlob("ErrorWindow/Window_Geometry")))
		resize(700, 300);
	

	foreach(const STATUS& Error, Errors)
	{
		QTreeWidgetItem* pItem = new QTreeWidgetItem();
		//
		// The whole of it as a tooltip as well. A cell longer than its column is
		// elided, and a truncated explanation is worse than none: this is where
		// the rest of it can be got at without resizing anything.
		//
		const QString Message = CTaskExplorer::FormatError(Error);
		pItem->setText(eMessage, Message);
		pItem->setToolTip(eMessage, Message);

		//
		// The two native columns only when there is a native status.
		//
		// ERROR_UNDEFINED is the marker for "nothing underneath this" - it is
		// what CStatus uses when the failure was decided by us rather than
		// reported by the platform, which is every TE_NotSupported. Rendering it
		// showed "0x00000001" and asked Windows what that meant, which is
		// STATUS_WAIT_1: a real status, about nothing that happened.
		//
		if (Error.GetStatus() != ERROR_UNDEFINED)
		{
			pItem->setText(eErrorCode, tr("0x%1").arg((quint32)Error.GetStatus(), 8, 16, QChar('0')));
			const QString Native = theSystem->GetStatusMessage(Error.GetStatus());
			pItem->setText(eErrorText, Native);
			pItem->setToolTip(eErrorText, Native);
		}
		m_pErrors->GetTree()->addTopLevelItem(pItem);
	}

	//
	// Each column as wide as what is in it, the message included - which is the
	// one that has to be readable without touching anything. Where that adds up
	// to more than the window, the columns to the right of it run off the end
	// and there is a scrollbar; a wider window or a dragged divider fixes that,
	// and both are one gesture. Nothing here tries to be cleverer than that.
	//
	for (int i = 0; i < m_pErrors->GetTree()->columnCount(); i++)
		m_pErrors->GetTree()->resizeColumnToContents(i);
}

CMultiErrorDialog::~CMultiErrorDialog()
{
	theConf->SetBlob("ErrorWindow/Window_Geometry", saveGeometry());
}
