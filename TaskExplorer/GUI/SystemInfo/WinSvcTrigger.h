#pragma once

#include <QtWidgets/QDialog>
#include "ui_WinSvcTrigger.h"
#include "../../API/ServiceInfo.h"

//
// Editor for one service trigger.
//
// It works on a CServiceInfo::STrigger by value: what the platform calls a
// trigger subtype, an ETW publisher or a data item all arrive as text and
// numbers, so the dialog itself knows nothing about Windows.
//
class CWinSvcTrigger : public QDialog
{
	Q_OBJECT

public:
	CWinSvcTrigger(const CServicePtr& pService, QWidget *parent = Q_NULLPTR);
	~CWinSvcTrigger();

	void SetTrigger(const CServiceInfo::STrigger& Trigger);
	const CServiceInfo::STrigger& GetTrigger() const	{ return m_Trigger; }

public slots:
	void accept();
	void reject();

	void OnData(QTreeWidgetItem *item, int column);
	void OnNewTrigger();
	void OnEditTrigger();
	void OnDeleteTrigger();

	void FixServiceTriggerControls();

protected:
	void ShowTrigger();
	void ShowData(QTreeWidgetItem* pItem, const CServiceInfo::STriggerData& Data);
	static QString FormatData(const CServiceInfo::STriggerData& Data, bool bForDisplay = true);
	static void ParseData(const QString& Value, CServiceInfo::STriggerData& Data);

	void closeEvent(QCloseEvent *e);

	CServicePtr					m_pService;
	CServiceInfo::STrigger		m_Trigger;

	QString	m_LastCustomSubType;
	quint32	m_LastSelectedType;
	bool	m_NoFixServiceTriggerControls;

private:

	Ui::WinSvcTrigger ui;
};
