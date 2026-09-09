#pragma once
#include "../guihelpers_global.h"
#include <qwidget.h>

#ifdef USE_QEXTWIDGETS
#include "../../qextwidgets/qtabwidgetex.h"
#endif

class GUIHELPERS_EXPORT CTabPanel : public QWidget
{
	Q_OBJECT
public:
	CTabPanel(QWidget* parent = 0);
	virtual ~CTabPanel();

	virtual int			GetTabCount() { return m_AllTabs.size(); }
	virtual QString		GetTabLabel(int Index) { if (Index >= m_AllTabs.size()) return ""; return m_AllTabs[Index].Name; }

	//
	// Which platform a tab is about, where it is about one.
	//
	// Not the same question as whether it is shown. Every tab is built on every
	// platform, because a viewer watching another machine needs the tabs that
	// machine has - so a tab can be perfectly meaningful and still have nothing
	// to say about the computer it is running on. Somebody turning one on is
	// entitled to know which of the two it is before they wonder why it is
	// blank.
	//
	// Values are CSystemAPI::EOsType, which this class deliberately does not
	// include: it is a widget in the helper library and knows nothing about
	// systems. eAnyPlatform is not one of them because eOsWindows is zero.
	//
	enum { eAnyPlatform = -1 };
	virtual int			GetTabPlatform(int Index) { if (Index < 0 || Index >= m_AllTabs.size()) return eAnyPlatform; return m_AllTabs[Index].Platform; }

	//
	// Rename a tab after it was added.
	//
	// For the one tab whose name is a property of the machine being looked at
	// rather than of the program - a Windows service and a Linux daemon are the
	// same list under two words. Kept in m_AllTabs as well as on the widget so
	// that hiding and reshowing the tab does not bring the old name back.
	//
	// Returns whether the name actually changed, so a caller can skip the work
	// of following it elsewhere - the View menu carries the same words.
	//
	virtual bool		SetTabLabel(int Index, const QString& Name)
	{
		if (Index < 0 || Index >= m_AllTabs.size() || m_AllTabs[Index].Name == Name)
			return false;

		m_AllTabs[Index].Name = Name;

		const int TabIndex = m_pTabs->indexOf(m_AllTabs[Index].pWidget);
		if (TabIndex != -1)
			m_pTabs->setTabText(TabIndex, Name);
		return true;
	}
	virtual void		ShowTab(int Index, bool bShow);
	virtual bool		IsTabVisible(int Index) { if (Index >= m_AllTabs.size()) return false; return m_AllTabs[Index].bVisible; }

	//
	// Grey a tab out, with the reason on it.
	//
	// Not the same as hiding it: which tabs are shown is the user's choice and
	// is remembered, while this is about whether the thing currently being
	// looked at can answer for that tab at all. Hiding it would write the
	// answer into their saved layout and it would not come back.
	//
	// The enabled state does not survive RebuildTabs, which recreates the tabs
	// from scratch - re-apply it after changing which tabs are visible.
	//
	virtual void		SetTabEnabled(int Index, bool bEnabled, const QString& Reason = QString());

protected:
	virtual void		InitializeTabs() = 0;
	//
	// bVisible is the *default* - what this tab does before anybody has said
	// otherwise. A saved layout overrides it; see RebuildTabs.
	//
	// It exists because which tabs make sense is a property of the machine
	// being looked at, not of the machine doing the looking. Every tab is built
	// on every platform - a Windows viewer watching a Linux box needs the
	// control group and security tabs, and a Linux viewer watching Windows
	// needs the token and job ones - and this decides which of them are shown
	// to begin with.
	//
	// Platform says which system the tab is about; see GetTabPlatform.
	virtual int			AddTab(QWidget* pWidget, const QString& Name, bool bVisible = true, int Platform = eAnyPlatform);
	virtual void		RebuildTabs(const int ActiveTab, const QStringList& VisibleTabs);
	virtual void		SaveTabs(int& ActiveTab, QStringList& VisibleTabs);

	QVBoxLayout*		m_pMainLayout;

#ifdef USE_QEXTWIDGETS
	QTabWidgetEx*		m_pTabs;
#else
	QTabWidget*			m_pTabs;
#endif
	struct STab
	{
		QString	Name;
		QWidget* pWidget;
		bool bVisible;
		int Platform = eAnyPlatform;
	};
	QVector<STab>		m_AllTabs;
};

