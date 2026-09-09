#pragma once
#include <qwidget.h>
#include "../../API/ProcessInfo.h"
#include "../../../MiscHelpers/Common/PanelView.h"
#include "../../../MiscHelpers/Common/TreeWidgetEx.h"
#include "../../../MiscHelpers/Common/PanelView.h"
#include "../../../MiscHelpers/Common/SmartGridWidget.h"
#include "../../../MiscHelpers/Common/IncrementalPlot.h"

class CGPUView : public QWidget //CPanelView
{
	Q_OBJECT
public:
	CGPUView(QWidget *parent = 0);
	virtual ~CGPUView();

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
	void					OnResetColumns();

	void					OnMultiPlot(int State);

protected:
	//virtual void				OnMenu(const QPoint& Point);
	//virtual QTreeView*			GetView()	{ return m_pStatsList; }
	//virtual QAbstractItemModel* GetModel()	{ return m_pStatsList->model(); }

	QSet<QString>			m_Adapters;

private:
	int						m_PlotLimit;

	enum EColumns
	{
		eModelName = 0,
		eLocation,
		eDriverVersion,
		eHwID,

		eDedicatedUsage,
		eDedicatedLimit,
		eSharedUsage,
		eSharedLimit,

		eDeviceInterface,

		eCount
	};

	QGridLayout*			m_pMainLayout;

	QWidget*				m_pScrollWidget;
	QScrollArea*			m_pScrollArea;
	QGridLayout*			m_pScrollLayout;

	QTabWidget*				m_pGraphTabs;

	QWidget*				m_pPlotWidget;
	QVBoxLayout*			m_pPlotLayout;

	//QLabel*					m_pGPUModel;
	CIncrementalPlot*		m_pGPUPlot;
	CIncrementalPlot*		m_pVRAMPlot;

	QCheckBox*				m_pMultiGraph;	

	struct SNodePlots
	{
		SNodePlots() : pStackedWidget(NULL), pStackedLayout(NULL), pPlot(NULL), pGrid(NULL) {}

		QWidget*				pStackedWidget;
		QStackedLayout*			pStackedLayout;
		CIncrementalPlot*		pPlot;
		CSmartGridWidget*		pGrid;
	};

	QMap<QString, SNodePlots>m_NodePlots;
	
	CPanelWidgetEx* m_pGPUList;
};

