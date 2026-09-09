#pragma once

class QFrame;
#include <qwidget.h>
#include "../../API/ProcessInfo.h"
#include "../../../MiscHelpers/Common/PanelView.h"
#include "../../../MiscHelpers/Common/TreeWidgetEx.h"

class CStatsView;
class CDriversView;	// every machine has kernel modules; the five below are Windows tables
#ifdef WIN32
class CPoolView;
class CNtObjectView;
class CAtomView;
class CRunObjView;
class CRpcView;
#endif

class CSystemView : public QWidget //CPanelView
{
	Q_OBJECT
public:
	CSystemView(QWidget *parent = 0);
	virtual ~CSystemView();

public slots:
	void					Refresh();

	//
	// The kernel sub-tabs read the Windows collector directly and cannot follow
	// the selection; they are greyed while another machine is being shown.
	//
	void					UpdateAvailability();

private:
	void					ShowServer(class IRemoteSystem* pRemote);

public slots:

protected:
	//virtual void				OnMenu(const QPoint& Point);
	//virtual QTreeView*			GetView()	{ return m_pStatsList; }
	//virtual QAbstractItemModel* GetModel()	{ return m_pStatsList->model(); }

private:
	QVBoxLayout*			m_pMainLayout;

	QScrollArea*			m_pScrollArea;

	QWidget*				m_pInfoWidget;
	QVBoxLayout*			m_pInfoLayout;

	QGroupBox*				m_pSystemBox;
	QGridLayout*			m_pSystemLayout;
	QLabel*					m_pIcon;
	QLabel*					m_pSystemName;
	QLabel*					m_pSystemType;
	QLabel*					m_pSystemVersion;
	QLabel*					m_pSystemBuild;

	//
	// Who is answering for this machine, when the answer is not "this process".
	// Hidden outright while looking at a machine read directly, where there is
	// no server in the picture and an empty section would only take up room.
	//
	QWidget*				m_pServerWidget;

	//
	// The rule between the operating system and the daemon. Shown and hidden
	// with the block it separates - a line down the middle of a box with
	// nothing on the other side of it is worse than no line.
	//
	QFrame*					m_pServerLine;
	QLabel*					m_pServerVersion;
	QLabel*					m_pServerVersionRow = NULL;	// the caption, for the protocol tooltip
	QLabel*					m_pServerAddress;
	QLabel*					m_pServerMachineId;
	QLabel*					m_pServerUptime;
	QLabel*					m_pServerUptimeRow = NULL;	// the caption, for the clock tooltip

	//
	// Which machine's logo is currently in m_pIcon. The pixmap is only built
	// when it changes, and "is it null" is not the right question once the
	// panel can be pointed at a different machine.
	//
	CSystemAPI*				m_pIconFrom = NULL;

	//QLabel*					m_pUpTime;
	//QLabel*					m_pHostName;
	//QLabel*					m_pUserName;
	//QLineEdit*				m_pSystemDir;

	QTabWidget*				m_pTabs;
	
	CStatsView*				m_pStatsView;

	// Every machine has kernel modules; the five below are Windows kernel tables.
	CDriversView*			m_pDriversView;
	int						m_DriversTab = -1;

#ifdef WIN32
	CPoolView*				m_pPoolView;
	CNtObjectView*			m_pNtObjectView;
	CAtomView*				m_pAtomView;
	CRunObjView*			m_pRunObjView;
	CRpcView*				m_pRpcView;
#endif
};

