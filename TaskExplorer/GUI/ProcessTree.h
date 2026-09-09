#pragma once
#include <qwidget.h>
#include "../../MiscHelpers/Common/SplitTreeView.h"
#include "../../MiscHelpers/Common/HistoryGraph.h"
#include "../API/ProcessInfo.h"
#include "TaskView.h"
#include "./Models/ProcessModel.h"

class CProcessFilterModel;

class CProcessTree : public CTaskView
{
	Q_OBJECT
public:
	CProcessTree(QWidget *parent = 0);
	virtual ~CProcessTree();

	virtual bool			IsTree() const { return m_pProcessList->IsTree(); }

	virtual void			OnMenu(const QPoint& Point);
	virtual QTreeView*		GetView() 				{ return m_pProcessList->GetView(); }
	virtual QAbstractItemModel* GetModel()				{ return m_pSortProxy; }
	//virtual QAbstractItemModel* GetModel()				{ return m_pHandleModel; }
	//virtual QModelIndex	MapToSource(const QModelIndex& Model) { return m_pSortProxy->mapToSource(Model); }

signals:
	void					ProcessClicked(const CProcessPtr& pProcess);
	void					ProcessesSelected(const QList<CProcessPtr>& Processes);

public slots:
	void					OnExpandAll();
	void					SetTree(bool bSet);

	//
	// Group by the account each process runs as. Independent of tree/list -
	// see CProcessModel::SetMultiUser.
	//
	void					SetMultiUser(bool bSet);
	bool					IsMultiUser() const;

	//
	// Show a branch per machine. Independent of the other two switches; see
	// CProcessModel::SetMultiMachine.
	//
	void					SetMultiMachine(bool bSet);
	bool					IsMultiMachine() const;

private slots:
	//
	// The branch menus. A machine or an account is not a process, so clicking
	// one offers what can be done to *it* rather than a process menu with most
	// of its entries greyed out.
	//
	void					OnMachineDisconnect();
	void					OnMachineForget();
	void					OnMachineRefresh();
	void					OnMachineRun();
	void					OnMachineRunAs();
	void					OnUserRunAs();

public:

private slots:
	void					OnTreeEnabled(bool bEnabled);

	void					OnClear();

	void					OnProcessListUpdated(QSet<quint64> Added, QSet<quint64> Changed, QSet<quint64> Removed);

	void					OnUpdateHistory();

	void					OnResetColumns();

	//void					OnClicked(const QModelIndex& Index);
	//void					OnDoubleClicked(const QModelIndex& Index);
	void					OnCurrentChanged(const QModelIndex &current, const QModelIndex &previous);
	void					OnSelectionChanged(const QItemSelection& Selected, const QItemSelection& Deselected);

	void					OnColumnsChanged();

	void					OnQuickRefresh();

	void					OnShowProperties();

	void					OnHeaderMenu(const QPoint& Point);
	void					OnHeaderMenu();
	
	void					OnToolTipCallback(const QVariant& ID, QString& ToolTip);

	//void					OnMenu(const QPoint& Point);

	void					OnPresetAction();

	void					OnCrashDump();
	void					OnProcessAction();
	void					OnWsWatch();
	void					OnWCT();
	void					OnRunAsThis();

	void					OnPermissions();

protected:
	template <class T>
	QList<T>					GetSelectedProcesses()
	{
		QList<T> List;
		foreach(const QModelIndex& Index, m_pProcessList->selectedRows())
		{
			QModelIndex ModelIndex = m_pSortProxy->mapToSource(Index);
			CProcessPtr pProcess = m_pProcessModel->GetProcess(ModelIndex);
			if(!pProcess.isNull())
				List.append(pProcess);
		}
		return List;
	}
	virtual QList<CTaskPtr>		GetSelectedTasks();

	void						UpdateIndexWidget(int HistoryColumn, int CellHeight, QMap<quint64, CHistoryGraph*>& Graphs, QMap<quint64, QPair<QPointer<CHistoryWidget>, QPersistentModelIndex> >& History);

	QMap<SProcessUID, CProcessPtr> m_Processes;

	QMenu*					m_pMachineMenu;
	QAction*				m_pMachineRefresh;
	QAction*				m_pMachineRun;
	QAction*				m_pMachineRunAs;
	QAction*				m_pMachineSeparator;
	QAction*				m_pMachineDisconnect;
	QAction*				m_pMachineForget;
	QMenu*					m_pUserMenu;
	QAction*				m_pUserRunAs;

	//
	// What the menu that is currently up was opened on. Read by the slots,
	// because by the time one fires the selection may have moved.
	//
	QString					m_MenuUserKey;
	QString					m_MenuUserName;
	CSystemAPI*				m_pMenuSystem;

private:
	static void				SetRemoteTodo(QAction* pAction, bool bEnabled);

	void					AddHeaderSubMenu(QMenu* m_pHeaderMenu, const QString& Label, int from, int to);

	void					QuickRefresh();

	bool					m_bQuickRefreshPending;

	//
	// The wire fields the visible columns need, recomputed when the columns
	// change and handed to every machine on each refresh - a machine that
	// connects later has to be told too, and this is the one place that runs
	// for all of them.
	//
	QSet<quint32>			m_WantedFields;

	QVBoxLayout*			m_pMainLayout;

	CProcessModel*			m_pProcessModel;
	QSortFilterProxyModel*	m_pSortProxy;
	CSplitTreeView*			m_pProcessList;

	QMap<quint64, CHistoryGraph*> m_CPU_Graphs;
	QMap<quint64, QPair<QPointer<CHistoryWidget>, QPersistentModelIndex> > m_CPU_History;
	QMap<quint64, CHistoryGraph*> m_MEM_Graphs;
	QMap<quint64, QPair<QPointer<CHistoryWidget>, QPersistentModelIndex> > m_MEM_History;
	QMap<quint64, CHistoryGraph*> m_IO_Graphs;
	QMap<quint64, QPair<QPointer<CHistoryWidget>, QPersistentModelIndex> > m_IO_History;
	QMap<quint64, CHistoryGraph*> m_NET_Graphs;
	QMap<quint64, QPair<QPointer<CHistoryWidget>, QPersistentModelIndex> > m_NET_History;
	QMap<quint64, CHistoryGraph*> m_GPU_Graphs;
	QMap<quint64, QPair<QPointer<CHistoryWidget>, QPersistentModelIndex> > m_GPU_History;
	QMap<quint64, CHistoryGraph*> m_VMEM_Graphs;
	QMap<quint64, QPair<QPointer<CHistoryWidget>, QPersistentModelIndex> > m_VMEM_History;

	QMenu*					m_pHeaderMenu;
	QMap<QCheckBox*,int>	m_Columns;
	bool					m_ExpandAll;

	//
	// Whether the local machine's branch still has to be opened.
	//
	// Once, when it first appears. Starting in cluster mode otherwise puts a
	// row per machine on screen and nothing else, and the machine somebody is
	// most likely to be looking at is the one in front of them.
	//
	bool					m_ExpandLocal;

	//QMenu*					m_pMenu;

	//QAction*				m_pTerminateTree;
	QAction*				m_pShowProperties;
	QAction*				m_pOpenPath;
	QAction*				m_pViewPE;
	QAction*				m_pStop;
	QAction*				m_pFreeze;
	QAction*				m_pUnFreeze;
	QMenu*					m_pWindowMenu;
	QAction*				m_pBringInFront;
	QAction*				m_pRestore;
	QAction*				m_pMinimize;
	QAction*				m_pMaximize;
	QAction*				m_pClose;
	QAction*				m_pPreset;
	QMenu*					m_pMiscMenu;
	QAction*				m_pQuit;
	QAction*				m_pRunAsThis;
	QMenu*					m_pDumpMenu;
	QAction*				m_pMinimalDump;
	QAction*				m_pLimitedDump;
	QAction*				m_pNormalDump;
	QAction*				m_pFullDump;
	//QAction*				m_pCustomDump;
	QAction*				m_pDebug; // []

	//
	// Actions only a Windows target supports.
	//
	// Built on every platform even so. What decides whether they are offered is
	// the *target's* operating system, not the viewer's - a Linux viewer
	// watching a Windows machine must be able to set its efficiency mode, and a
	// Windows viewer watching Linux must not offer to. All of them go through
	// portable CProcessInfo virtuals that answer TE_NotSupported where the
	// notion does not exist, so there is nothing platform-shaped left here.
	//
	QAction*				m_pEfficiency;
	QAction*				m_pExecRequired;
	//QAction*				m_pVirtualization; // []
	QAction*				m_pCritical; // []
	QAction*				m_pProtected; // []
	QAction*				m_pReduceWS;
	QAction*				m_pPermissions;
#ifdef WIN32
	//
	// These two are different: the action is not the problem, the *dialog* is.
	// CWsWatchDialog and CWaitChainDialog are not portable yet, so a viewer that
	// cannot open them must not offer them whatever the target is.
	//
	QAction*				m_pWatchWS;
	QAction*				m_pWCT;
#endif

	QColor					m_PlotBackground;
};
