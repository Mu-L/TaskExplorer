#pragma once
#include <qwidget.h>
#include "../../API/ProcessInfo.h"
#include "../../../MiscHelpers/Common/PanelView.h"
#include "../../../MiscHelpers/Common/TreeWidgetEx.h"
#include "../../../MiscHelpers/Common/SmartGridWidget.h"
#include "../../../MiscHelpers/Common/IncrementalPlot.h"

class CCPUView : public QWidget //CPanelView
{
	Q_OBJECT
public:
	CCPUView(QWidget *parent = 0);
	virtual ~CCPUView();

public slots:
	void					Refresh();
	void					UpdateGraphs();
	void					ReConfigurePlots();

	//
	// Throw the plotted history away. The points belong to whichever machine
	// was being shown when they were taken, so they cannot be carried over to
	// the next one.
	//
	void					ResetPlots();

private slots:
	void					OnMultiPlot(int State);
protected:
	//virtual void				OnMenu(const QPoint& Point);
	//virtual QTreeView*			GetView()	{ return m_pStatsList; }
	//virtual QAbstractItemModel* GetModel()	{ return m_pStatsList->model(); }

private:
	//
	// One plot per CPU, so the grid has to be rebuilt when the machine being
	// shown has a different number of them. Cheap to call - it returns at once
	// unless the count actually changed.
	//
	void					BuildCpuPlots();

	int						m_CpuCount;

	int						m_PlotLimit;

	QGridLayout*			m_pMainLayout;

	QWidget*				m_pScrollWidget;
	QScrollArea*			m_pScrollArea;
	QGridLayout*			m_pScrollLayout;

	QLabel*					m_pCPUModel;

	QWidget*				m_pStackedWidget;
	QStackedLayout*			m_pStackedLayout;

	CIncrementalPlot*		m_pCPUPlot;

	CSmartGridWidget*		m_pCPUGrid;

	QCheckBox*				m_pMultiGraph;

	QWidget*				m_pInfoWidget;
	QHBoxLayout*			m_pInfoLayout;

	QWidget*				m_pInfoWidget1;
	QVBoxLayout*			m_pInfoLayout1;

	QWidget*				m_pInfoWidget2;
	QVBoxLayout*			m_pInfoLayout2;

	QGroupBox*				m_pCPUBox;
	QGridLayout*			m_pCPULayout;
	QLabel*					m_pCPUUsage;
	QLabel*					m_pCPUSpeed;
	QLabel*					m_pCPUNumaCount;
	QLabel*					m_pCPUCoreCount;

	QGroupBox*				m_pOtherBox;
	QGridLayout*			m_pOtherLayout;
	QLabel*					m_pSwitches;
	QLabel*					m_pInterrupts;
	QLabel*					m_pDPCs;
	QLabel*					m_pSysCalls;
};

