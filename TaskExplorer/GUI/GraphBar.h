#pragma once
#include <qwidget.h>
#include "../../MiscHelpers/Common/IncrementalPlot.h"
#include "../API/AbstractInfo.h"


class CGraphBar : public QWidget
{
	Q_OBJECT

public:
	CGraphBar();
	virtual ~CGraphBar();

public slots:
	void					UpdateGraphs();
	void					CustomizeGraphs();

	// Rebuilds the graph bar from the platform's default set; see
	// GetDefaultGraphs() for why this needs to be reachable.
	void					RestoreDefaultGraphs();

	void					ReConfigurePlots();
	void					SetDarkMode(bool bDark);

private slots:	
	void					OnMenu(const QPoint& Point);

	void					ClearGraphs();

	//
	// Clears only where the machine the graphs read from has actually changed.
	//
	// The view can move between machines without moving what the bar plots -
	// see CCluster::GetActiveSystem - and a reset in that case throws away the
	// history of the very machine still being shown.
	//
	void					OnViewSystemChanged();

	//void					OnEntered();
	//void					OnMoveed(QMouseEvent* event);
	//void					OnExited();
	void					OnToolTipRequested(QEvent* event);

signals:
	void					Resized(int Size);

private:
	void					FixPlotScale(CIncrementalPlot* pPlot);

	enum EGraph
	{
		eMemoryPlot = 0,
		eGpuMemPlot,
		eObjectPlot,
		eWindowsPlot,
		eHandledPlot,
		eDiskIoPlot,
		eMMapIoPlot,
		eFileIoPlot,
		eSambaPlot,
		eClientPlot,
		eServerPlot,
		eRasPlot,
		eNetworkPlot,
		eGpuPlot,
		eCpuPlot,
		// Pressure Stall Information; Linux only, there is no Windows analogue.
		ePressurePlot,
		eCount
	};


	/*struct SGraph
	{
		CIncrementalPlot*	pGraph;
		EGraphType			Type;
	};*/

	// The plots shown when nothing has been configured. Platform dependent.
	static QList<EGraph>	GetDefaultGraphs();

	// Persists the current layout to the settings.
	void					SaveGraphs();

	void					AddGraphs(QList<EGraph> Graphs, int Rows);
	void					AddGraph(EGraph Graph, int row, int column);
	void					DeleteGraphs();

	int						m_Rows;

	int						m_PlotLimit;

	QWeakPointer<CSystemAPI>	m_pPlotted;

	struct SGraph
	{
		SGraph()
		{
			Type = eCount;
			pPlot = NULL;
		}

		EGraph Type;
		CIncrementalPlot* pPlot;
		QVariantMap Params;
	};
	QList<SGraph>			m_Graphs;

	QGridLayout*			m_pMainLayout;

	QPointer<CIncrementalPlot> m_pCurPlot;

	QMenu*					m_pMenu;
	QAction*				m_pResetPlot;
	QAction*				m_pResetAll;
	QAction*				m_pCustomize;
	QAction*				m_pRestoreDefaults;

	QWidget*				m_pLastTipGraph;
};
