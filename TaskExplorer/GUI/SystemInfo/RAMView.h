#pragma once
#include <qwidget.h>
#include "../../API/ProcessInfo.h"
#include "../../../MiscHelpers/Common/PanelView.h"
#include "../../../MiscHelpers/Common/TreeWidgetEx.h"
#include "../../../MiscHelpers/Common/IncrementalPlot.h"

class CRAMView : public QWidget //CPanelView
{
	Q_OBJECT
public:
	CRAMView(QWidget *parent = 0);
	virtual ~CRAMView();

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

protected:
	//virtual void				OnMenu(const QPoint& Point);
	//virtual QTreeView*			GetView()	{ return m_pStatsList; }
	//virtual QAbstractItemModel* GetModel()	{ return m_pStatsList->model(); }

private:
	int						m_PlotLimit;

	enum EColumns
	{
		eFileName = 0,
		eUsage,
		ePeakUsage,
		eTotalSize,
		eCount
	};

	QGridLayout*			m_pMainLayout;

	QWidget*				m_pScrollWidget;
	QScrollArea*			m_pScrollArea;
	QGridLayout*			m_pScrollLayout;

	QLabel*					m_pRAMSize;
	CIncrementalPlot*		m_pRAMPlot;

	QTabWidget*				m_pInfoTabs;

	QWidget*				m_pMemoryWidget;
	QGridLayout*			m_pMemoryLayout;

	QGroupBox*				m_pVMemBox;
	QGridLayout*			m_pVMemLayout;
	QLabel*					m_pVMemCurrent;
	QLabel*					m_pVMemPeak;
	QLabel*					m_pVMemLimit;
	QLabel*					m_pSwapSize;

	QGroupBox*				m_pRAMBox;
	QGridLayout*			m_pRAMLayout;
	QLabel*					m_pRAMUsed;
	QLabel*					m_pRAMTotal;
	QLabel*					m_pRAMReserved;
	QLabel*					m_pRAMCacheWS;
	QLabel*					m_pRAMKernelWS;
	QLabel*					m_pRAMDriverWS;


	QWidget*				m_pPageWidget;
	QGridLayout*			m_pPageLayout;

	QGroupBox*				m_pPagingBox;
	QGridLayout*			m_pPagingLayout;
	QLabel*					m_pPagingFault;
	QLabel*					m_pPagingReads;
	QLabel*					m_pPagingFileWrites;
	QLabel*					m_pMappedWrites;

	QGroupBox*				m_pSwapBox;
	QGridLayout*			m_pSwapLayout;

	CPanelWidgetEx*			m_pSwapList;

	//
	// Only populated where the target reports page lists; see GetMemoryList().
	//
	QWidget*				m_pListsWidget = nullptr;
	QGridLayout*			m_pListsLayout = nullptr;

	QGroupBox*				m_pListBox = nullptr;
	QGridLayout*			m_pListLayout = nullptr;
	QLabel*					m_pZeroed = nullptr;
	QLabel*					m_pFree = nullptr;
	QLabel*					m_pModified = nullptr;
	QLabel*					m_pModifiedNoWrite = nullptr;
	QLabel*					m_pModifiedPaged = nullptr;

	QGroupBox*				m_pStanbyBox = nullptr;
	QGridLayout*			m_pStanbyLayout = nullptr;
	QLabel*					m_pStandby = nullptr;
	QLabel*					m_pPriority0 = nullptr;
	QLabel*					m_pPriority1 = nullptr;
	QLabel*					m_pPriority2 = nullptr;
	QLabel*					m_pPriority3 = nullptr;
	QLabel*					m_pPriority4 = nullptr;
	QLabel*					m_pPriority5 = nullptr;
	QLabel*					m_pPriority6 = nullptr;
	QLabel*					m_pPriority7 = nullptr;
};

