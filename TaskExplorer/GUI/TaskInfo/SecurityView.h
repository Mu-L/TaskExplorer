#pragma once
#include <qwidget.h>
#include "../../../MiscHelpers/Common/PanelView.h"
#include "../../API/Linux/LinuxProcess.h"

//
// What a process is allowed to do - the Linux counterpart of the Windows Token
// view.
//
// A Windows token carries the user, the groups and the privileges in one
// object. Linux spreads the same information across several places: the
// credentials in /proc/<pid>/status, the five capability sets, whichever LSM is
// active (AppArmor or SELinux), and the seccomp state. This view puts them
// together, because the question a person is asking - "how privileged is this
// thing" - is the same one.
//
class CSecurityView : public CPanelView
{
	Q_OBJECT

public:
	CSecurityView(QWidget *parent = 0);
	virtual ~CSecurityView();

public slots:
	void					ShowProcesses(const QList<CProcessPtr>& Processes);
	void					Refresh();

protected:
	virtual void			OnMenu(const QPoint& Point);
	virtual QTreeView*		GetView()	{ return m_pList->GetView(); }
	virtual QAbstractItemModel* GetModel() { return nullptr; }

	//
	// CProcessPtr, not a backend pointer: the process may be a remote one, and
	// everything this view needs is on the base.
	//
	CProcessPtr				m_pCurProcess;

private:
	void					SetValue(const QString& Group, const QString& Name, const QString& Value);
	void					PruneStale();

	//
	// The capability list, a row per capability with a mark in each set that
	// holds it. The Windows counterpart is the privilege list in the Token
	// view: a name and the state it is in, rather than one line per set with
	// forty names crammed into it.
	//
	void					ShowCapabilities(const SProcessSecurity& Security);
	void					ShowNamespaces();
	void					Clear();

	QGridLayout*			m_pHeaderLayout;

	//
	// The facts worth having without opening anything, in the shape the Token
	// view uses: who the process is, what confines it, and the two flags that
	// decide whether that confinement survives an execve.
	//
	QLineEdit*				m_pUser;
	QLineEdit*				m_pGroup;
	QLineEdit*				m_pProfile;
	QLineEdit*				m_pContainer;
	QLabel*					m_pSeccomp;
	QLabel*					m_pNoNewPrivs;

	QTabWidget*				m_pTabs;
	CPanelWidgetEx*			m_pList;
	CPanelWidgetEx*			m_pCaps;
	CPanelWidgetEx*			m_pNamespaces;

	QSet<QString>			m_LiveKeys;
	QMap<QString, QTreeWidgetItem*>	m_Items;
	QMap<QString, QTreeWidgetItem*>	m_Groups;

	QMap<int, QTreeWidgetItem*>	m_CapItems;
	QMap<QString, QTreeWidgetItem*>	m_NsItems;
};
