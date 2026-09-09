#pragma once
#include <qwidget.h>
#include "../../../MiscHelpers/Common/TabPanel.h"
#include "../../API/SystemAPI.h"

class CSystemView;
class CHandlesView;
class CSocketsView;
class CServicesView;
#ifdef WIN32
#endif
//class CDriversView;
class CDnsCacheView;
class CCPUView;
class CRAMView;
class CDiskView;
class CNetworkView;
class CGPUView;

class CSystemInfoView : public CTabPanel
{
	Q_OBJECT
public:
	CSystemInfoView(bool bAsWindow = false, QWidget* patent = 0);
	virtual ~CSystemInfoView();

	enum ETabs
	{
		eSystemView = 0,
		eCPUView,
		eRAMView,
		eGPUView,
		eDiskView,
		eAllFilesView,
		eNetworkView,
		eAllSocketsView,
		eDnsCacheView,
		//eDriversView,
		eKernelView,
		eServicesView,
		eTabCount
	};

signals:
	//
	// A tab has been renamed. The View menu lists the tab names, so it has to
	// follow - see CTaskExplorer::UpdateTabMenus.
	//
	void				TabLabelsChanged();

public slots:
	void				OnTab(int tabIndex);
	void				Refresh();
	void				UpdateGraphs();

	//
	// The panels are now showing a different machine: throw away what is held,
	// say whose data this is, and re-check which tabs that machine can answer
	// for at all.
	//
	void				OnViewSystemChanged();

	//
	// Say whose data this is and which tabs that machine can answer for,
	// without throwing anything away. Also needed when a machine merely joins
	// or leaves the view - the panel is still showing the same one, but whether
	// it has to be named has changed.
	//
	void				UpdateMachineLabel();

protected:
	virtual void		InitializeTabs();

	//
	// Which tabs the machine now being shown can answer for. See the note in
	// the implementation about the ones that cannot.
	//
	void				UpdateTabAvailability();

	//
	// What to call the service list on a given machine. A Windows service and a
	// Linux daemon are the same list; only the word differs, and the word
	// belongs to the machine being looked at.
	//
	//static QString		ServiceTabLabel(CSystemAPI* pSystem);

	int					m_ServicesTab = -1;

	bool				m_bAsWindow;

	//
	// Whose data this is, in the corner of the tab strip. Only carries text
	// while more than one machine is in view - with one there is nothing to
	// confuse it with and a label would just be furniture.
	//
	//QLabel*				m_pMachineLabel;

	//
	// Which command each tab needs the target to be able to answer. Filled as
	// the tabs are built, because the index a tab ends up at is what AddTab
	// returns and nothing else knows it.
	//
	QMap<int, quint32>	m_TabFeature;

	//
	// The three that draw a per-device list from a monitor object. Recorded by
	// the index AddTab returns, which is the only reliable one: the ETabs enum
	// above does not match the order InitializeTabs adds them in.
	//
	int					m_GpuTab;
	int					m_DiskTab;
	int					m_NetworkTab;

private:
	CSystemView*		m_pSystemView;
	CHandlesView*		m_pAllFilesView;
	CSocketsView*		m_pAllSocketsView;
	CDnsCacheView*		m_pDnsCacheView;
	CServicesView*		m_pServicesView;
	//CDriversView*		m_pDriversView;
	CCPUView*			m_pCPUView;
	CRAMView*			m_pRAMView;
	CDiskView*			m_pDiskView;
	CNetworkView*		m_pNetworkView;
	CGPUView*			m_pGPUView;
};

