#pragma once
#include <qwidget.h>

#include "../guihelpers_global.h"

class GUIHELPERS_EXPORT CSmartGridWidget : public QWidget
{
	Q_OBJECT

public:
	CSmartGridWidget(QWidget* parent = NULL);
	virtual ~CSmartGridWidget() {}

	virtual void			SetBackground(const QColor& BackColor);

	virtual void			AddWidget(QWidget* pWidget);

	//
	// Deletes what is in the grid. For a grid whose size is a property of
	// something outside it - one plot per CPU, say - and that something
	// changed.
	//
	virtual void			Clear();

	virtual int				GetCount()				{ return m_Widgets.count(); }
	virtual QWidget*		GetWidget(int Index)	{ return m_Widgets.at(Index); }

public slots:
	virtual void			ReArange();

protected:
	QGridLayout*			m_pMainLayout;

	QList<QPointer<QWidget>>m_Widgets;

	bool					m_bReArangePending;
};
