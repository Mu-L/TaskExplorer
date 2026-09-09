#pragma once
#include <qwidget.h>
#include "../../../../MiscHelpers/Common/TreeViewEx.h"
#include "../../../../MiscHelpers/Common/PanelView.h"
#include "../../../API/ProcessInfo.h"
#include "../../../API/DriverInfo.h"
#include "../../Models/DriverModel.h"

class CDriverModel;
class QSortFilterProxyModel;

class CDriversView : public CPanelView
{
	Q_OBJECT

public:
	CDriversView(QWidget *parent = 0);
	virtual ~CDriversView();

	//void					OnMenu(const QPoint &point);

public slots:
	void					Refresh();

protected:
	//virtual void				OnMenu(const QPoint& Point);
	virtual QTreeView*			GetView()	{ return m_pDriverList; }
	virtual QAbstractItemModel* GetModel()	{ return m_pSortProxy; }

	QMap<QString, CDriverPtr> m_DriverList;

public slots:
	//
	// Public because the panel re-applies it when the viewed machine changes:
	// which columns are worth showing depends on which kind of machine is being
	// looked at, and a layout saved from the other kind is not it.
	//
	void					OnResetColumns();

private slots:
	void					OnColumnsChanged();

	void					OnDriverListUpdated(QSet<QString> Added, QSet<QString> Changed, QSet<QString> Removed);

private:

	QVBoxLayout*			m_pMainLayout;

	QTreeViewEx*			m_pDriverList;
	CDriverModel*			m_pDriverModel;
	QSortFilterProxyModel*	m_pSortProxy;
};

