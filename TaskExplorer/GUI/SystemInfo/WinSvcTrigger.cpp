/*
 * Task Explorer -
 *   qt port of the Service Trigger editor from the ExtendedServices plugin
 *
 * Copyright (C) 2015 wj32
 * Copyright (C) 2019 David Xanatos
 *
 * This file is part of Task Explorer and contains System Informer code.
 *
 */

#include "stdafx.h"
#include "WinSvcTrigger.h"
#include "../TaskExplorer.h"
#include "../../../MiscHelpers/Common/ComboInputDialog.h"
#include "../../../MiscHelpers/Common/MultiLineInputDialog.h"

//
// Windows SDK only: the SERVICE_TRIGGER_* constants the API reports values
// from. phlib is not involved. They should become portable enums when the
// platform constants generally do - see the note on the decoders.
//
#include <windows.h>
#include <winsvc.h>

#include <QUuid>

//
// A trigger's subtype is either one of the names the target knows, or a GUID
// typed in by hand. The combo carries true in its item data for the entries
// that mean "custom", which is what enables the text box beside it.
//
static const int TriggerCustomRole = Qt::UserRole;

CWinSvcTrigger::CWinSvcTrigger(const CServicePtr& pService, QWidget *parent)
	: QDialog(parent)
{
	ui.setupUi(this);

	m_pService = pService;

	m_LastSelectedType = 0;
	m_NoFixServiceTriggerControls = false;

	ui.datas->setHeaderLabels(tr("Data").split("|"));

	typedef QPair<QString, quint32> SLabeledValue;
	foreach(const SLabeledValue& Type, m_pService->GetTriggerTypes())
		ui.type->addItem(Type.first, Type.second);

	ui.action->addItem(tr("Start"), SERVICE_TRIGGER_ACTION_SERVICE_START);
	ui.action->addItem(tr("Stop"), SERVICE_TRIGGER_ACTION_SERVICE_STOP);

	connect(ui.type, SIGNAL(currentIndexChanged(int)), this, SLOT(FixServiceTriggerControls()));
	connect(ui.subType, SIGNAL(currentIndexChanged(int)), this, SLOT(FixServiceTriggerControls()));

	connect(ui.datas, SIGNAL(itemDoubleClicked(QTreeWidgetItem*, int)), this, SLOT(OnData(QTreeWidgetItem*, int)));
	connect(ui.newBtn, SIGNAL(pressed()), this, SLOT(OnNewTrigger()));
	connect(ui.editBtn, SIGNAL(pressed()), this, SLOT(OnEditTrigger()));
	connect(ui.deleteBtn, SIGNAL(pressed()), this, SLOT(OnDeleteTrigger()));

	connect(ui.buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
	connect(ui.buttonBox, SIGNAL(rejected()), this, SLOT(reject()));

	//
	// A new trigger starts on the first subtype the target offers for the first
	// type, which is what the old code hard-coded to "first IP address arrival".
	//
	m_Trigger.Type = ui.type->count() > 0 ? ui.type->itemData(0).toUInt() : 0;
	m_Trigger.Action = SERVICE_TRIGGER_ACTION_SERVICE_START;
	ShowTrigger();
}

CWinSvcTrigger::~CWinSvcTrigger()
{
}

void CWinSvcTrigger::SetTrigger(const CServiceInfo::STrigger& Trigger)
{
	m_Trigger = Trigger;
	ui.datas->clear();
	ShowTrigger();
}

void CWinSvcTrigger::FixServiceTriggerControls()
{
	if (m_NoFixServiceTriggerControls)
		return;
	m_NoFixServiceTriggerControls = true;

	const quint32 Type = ui.type->currentData().toUInt();

	if (m_LastSelectedType != Type)
	{
		//
		// The subtype list depends on the type: some types accept only a GUID,
		// the custom ETW type lists the publishers the target knows, and the
		// rest have named subtypes.
		//
		ui.subType->clear();

		switch (Type)
		{
		case SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL:
		case SERVICE_TRIGGER_TYPE_CUSTOM_SYSTEM_STATE_CHANGE:
			ui.subType->addItem(tr("Custom"), true);
			break;

		case SERVICE_TRIGGER_TYPE_CUSTOM:
			ui.subType->addItem(tr("Custom"), true);
			foreach(const QString& Publisher, m_pService->GetEtwPublishers())
				ui.subType->addItem(Publisher);
			break;

		default:
			foreach(const CServiceInfo::STriggerSubtype& Subtype, m_pService->GetTriggerSubtypes())
			{
				if (Subtype.TriggerType == Type)
					ui.subType->addItem(Subtype.Name);
			}
			ui.subType->addItem(tr("Custom"), true);
			break;
		}

		m_LastSelectedType = Type;
	}

	if (ui.subType->currentData(TriggerCustomRole).toBool())
	{
		ui.custom->setEnabled(true);
		ui.custom->setText(m_LastCustomSubType);
	}
	else if (ui.custom->isEnabled())
	{
		ui.custom->setEnabled(false);
		m_LastCustomSubType = ui.custom->text();
		ui.custom->setText("");
	}

	m_NoFixServiceTriggerControls = false;
}

QString CWinSvcTrigger::FormatData(const CServiceInfo::STriggerData& Data, bool bForDisplay)
{
	switch (Data.Type)
	{
	case SERVICE_TRIGGER_DATA_TYPE_STRING:
		if (!Data.String.isEmpty())
			return Data.String;
		return bForDisplay ? tr("(empty string)") : QString();

	case SERVICE_TRIGGER_DATA_TYPE_BINARY:
		return (bForDisplay ? tr("(binary data) ") : QString()) + QString::fromLatin1(Data.Binary.toHex());

	case SERVICE_TRIGGER_DATA_TYPE_LEVEL:
		return (bForDisplay ? tr("(level) ") : QString()) + QString::number(Data.Number);

	case SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY:
		return (bForDisplay ? tr("(keyword any) ") : QString()) + QString::number(Data.Number);

	case SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ALL:
		return (bForDisplay ? tr("(keyword all) ") : QString()) + QString::number(Data.Number);
	}

	return bForDisplay ? tr("(unknown type)") : QString();
}

void CWinSvcTrigger::ParseData(const QString& Value, CServiceInfo::STriggerData& Data)
{
	switch (Data.Type)
	{
	case SERVICE_TRIGGER_DATA_TYPE_STRING:
		Data.String = Value;
		break;
	case SERVICE_TRIGGER_DATA_TYPE_BINARY:
		Data.Binary = QByteArray::fromHex(Value.toLatin1());
		break;
	case SERVICE_TRIGGER_DATA_TYPE_LEVEL:
	case SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY:
	case SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ALL:
		Data.Number = Value.toULongLong();
		break;
	}
}

void CWinSvcTrigger::ShowData(QTreeWidgetItem* pItem, const CServiceInfo::STriggerData& Data)
{
	pItem->setText(0, FormatData(Data));
}

void CWinSvcTrigger::ShowTrigger()
{
	m_LastSelectedType = 0;
	m_LastCustomSubType = m_Trigger.Subtype;

	ui.type->setCurrentIndex(ui.type->findData(m_Trigger.Type));
	ui.action->setCurrentIndex(ui.action->findData(m_Trigger.Action));

	FixServiceTriggerControls();

	//
	// Select the subtype by name where the target knows one for this GUID, and
	// fall back to showing the GUID itself in the custom box.
	//
	QString Name;
	if (m_Trigger.Type == SERVICE_TRIGGER_TYPE_CUSTOM)
	{
		Name = m_pService->GetEtwPublisherName(m_Trigger.Subtype);
	}
	else
	{
		foreach(const CServiceInfo::STriggerSubtype& Subtype, m_pService->GetTriggerSubtypes())
		{
			if (Subtype.TriggerType == m_Trigger.Type && Subtype.Guid.compare(m_Trigger.Subtype, Qt::CaseInsensitive) == 0)
			{
				Name = Subtype.Name;
				break;
			}
		}
	}

	int iSubtype = Name.isEmpty() ? -1 : ui.subType->findText(Name);
	if (iSubtype != -1)
		ui.subType->setCurrentIndex(iSubtype);

	// the custom box may have just been enabled, so settle the controls again
	FixServiceTriggerControls();

	ui.datas->clear();
	foreach(const CServiceInfo::STriggerData& Data, m_Trigger.Data)
	{
		QTreeWidgetItem* pItem = new QTreeWidgetItem();
		pItem->setData(0, Qt::UserRole, ui.datas->topLevelItemCount());
		ui.datas->addTopLevelItem(pItem);
		ShowData(pItem, Data);
	}
}

void CWinSvcTrigger::closeEvent(QCloseEvent *e)
{
	this->deleteLater();
}

void CWinSvcTrigger::accept()
{
	m_Trigger.Type = ui.type->currentData().toUInt();
	m_Trigger.Action = ui.action->currentData().toUInt();

	if (!ui.subType->currentData(TriggerCustomRole).toBool())
	{
		//
		// A named subtype: look the GUID back up from the name the target gave.
		//
		QString Guid;
		if (m_Trigger.Type == SERVICE_TRIGGER_TYPE_CUSTOM)
		{
			Guid = m_pService->GetEtwPublisherGuid(ui.subType->currentText());
			if (Guid.isEmpty())
			{
				QMessageBox::warning(NULL, "TaskExplorer", tr("Unable to find the ETW publisher GUID."));
				return;
			}
		}
		else
		{
			foreach(const CServiceInfo::STriggerSubtype& Subtype, m_pService->GetTriggerSubtypes())
			{
				if (Subtype.TriggerType == m_Trigger.Type && Subtype.Name.compare(ui.subType->currentText(), Qt::CaseInsensitive) == 0)
				{
					Guid = Subtype.Guid;
					break;
				}
			}
		}

		m_Trigger.Subtype = Guid;
	}
	else
	{
		const QUuid Uuid(ui.custom->text().trimmed());
		if (Uuid.isNull())
		{
			QMessageBox::warning(NULL, "TaskExplorer", tr("The custom subtype is invalid. Please ensure that the string is a valid GUID: \"{x-x-x-x-x}\"."));
			return;
		}

		m_Trigger.Subtype = Uuid.toString(QUuid::WithBraces);
	}

	//
	// Not every trigger type accepts data items; dropping them is destructive,
	// so it is asked for rather than done quietly.
	//
	if (!m_Trigger.Data.isEmpty()
		&& m_Trigger.Type != SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL
		&& m_Trigger.Type != SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT
		&& m_Trigger.Type != SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT
		&& m_Trigger.Type != SERVICE_TRIGGER_TYPE_CUSTOM)
	{
		if (QMessageBox("TaskExplorer", tr("The trigger type \"%1\" does not allow data items to be configured. If you continue, they will be removed.").arg(ui.type->currentText()), QMessageBox::Question, QMessageBox::Ok, QMessageBox::Cancel | QMessageBox::Default | QMessageBox::Escape, QMessageBox::NoButton).exec() != QMessageBox::Ok)
			return;

		m_Trigger.Data.clear();
	}

	QDialog::accept();
}

void CWinSvcTrigger::reject()
{
	QDialog::reject();
}

void CWinSvcTrigger::OnData(QTreeWidgetItem *item, int column)
{
	const int index = item->data(0, Qt::UserRole).toInt();
	if (index < 0 || index >= m_Trigger.Data.count())
		return;

	CMultiLineInputDialog valueDialog(this);
	valueDialog.setText(tr("Enter value"));
	valueDialog.setValue(FormatData(m_Trigger.Data[index], false));

	if (!valueDialog.exec())
		return;

	ParseData(valueDialog.value(), m_Trigger.Data[index]);
	ShowData(item, m_Trigger.Data[index]);
}

void CWinSvcTrigger::OnNewTrigger()
{
	CComboInputDialog typeDialog(this);
	typeDialog.setText(tr("Sellect data type:"));
	typeDialog.addItem(tr("String"), SERVICE_TRIGGER_DATA_TYPE_STRING);
	typeDialog.addItem(tr("Binary data"), SERVICE_TRIGGER_DATA_TYPE_BINARY);
	typeDialog.addItem(tr("Level"), SERVICE_TRIGGER_DATA_TYPE_LEVEL);
	typeDialog.addItem(tr("Keyword any"), SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY);
	typeDialog.addItem(tr("Keyword all"), SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ALL);

	if (!typeDialog.exec())
		return;

	CMultiLineInputDialog valueDialog(this);
	valueDialog.setText(tr("Enter value"));

	if (!valueDialog.exec())
		return;

	CServiceInfo::STriggerData Data;
	Data.Type = typeDialog.data().toUInt();
	ParseData(valueDialog.value(), Data);

	QTreeWidgetItem* pItem = new QTreeWidgetItem();
	pItem->setData(0, Qt::UserRole, m_Trigger.Data.count());
	m_Trigger.Data.append(Data);
	ui.datas->addTopLevelItem(pItem);
	ShowData(pItem, Data);
}

void CWinSvcTrigger::OnEditTrigger()
{
	QTreeWidgetItem *item = ui.datas->currentItem();
	if (!item)
		return;
	OnData(item, 0);
}

void CWinSvcTrigger::OnDeleteTrigger()
{
	QTreeWidgetItem *item = ui.datas->currentItem();
	if (!item)
		return;

	const int index = item->data(0, Qt::UserRole).toInt();
	if (index < 0 || index >= m_Trigger.Data.count())
		return;

	if (QMessageBox("TaskExplorer", tr("Do you want to delete the selected data"), QMessageBox::Question, QMessageBox::Yes, QMessageBox::No | QMessageBox::Default | QMessageBox::Escape, QMessageBox::NoButton).exec() != QMessageBox::Yes)
		return;

	m_Trigger.Data.removeAt(index);
	delete item;

	// the rows carry their index, so renumber what is left
	for (int i = 0; i < ui.datas->topLevelItemCount(); i++)
		ui.datas->topLevelItem(i)->setData(0, Qt::UserRole, i);
}
