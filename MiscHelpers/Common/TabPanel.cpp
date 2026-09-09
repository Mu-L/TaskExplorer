#include "stdafx.h"
#include "TabPanel.h"

CTabPanel::CTabPanel(QWidget* parent)
	: QWidget(parent)
{
	m_pMainLayout = new QVBoxLayout();
	m_pMainLayout->setContentsMargins(0,0,0,0);
	this->setLayout(m_pMainLayout);

#ifdef USE_QEXTWIDGETS
	m_pTabs = new QTabWidgetEx();
	m_pTabs->setMultiRow(true);
#else
	m_pTabs = new QTabWidget();
#endif
	m_pMainLayout->addWidget(m_pTabs);
}

CTabPanel::~CTabPanel()
{
}

void CTabPanel::ShowTab(int Index, bool bShow)
{
	if (Index >= m_AllTabs.size())
		return;
	
	m_AllTabs[Index].bVisible = bShow;

	int ActiveTab = 0;
	QStringList VisibleTabs;

	SaveTabs(ActiveTab, VisibleTabs);

	RebuildTabs(ActiveTab, VisibleTabs);
}

void CTabPanel::SetTabEnabled(int Index, bool bEnabled, const QString& Reason)
{
	if (Index >= m_AllTabs.size())
		return;

	const int TabIndex = m_pTabs->indexOf(m_AllTabs[Index].pWidget);
	if (TabIndex == -1)
		return;	// the user has this one hidden

	m_pTabs->setTabEnabled(TabIndex, bEnabled);
	m_pTabs->setTabToolTip(TabIndex, Reason);
}

int CTabPanel::AddTab(QWidget* pWidget, const QString& Name, bool bVisible, int Platform)
{
	STab Tab{Name, pWidget, bVisible, Platform};
	m_AllTabs.append(Tab);

	//
	// Added and then taken out again where it starts hidden, rather than simply
	// not added.
	//
	// Not added is not the same as hidden: the view was built with this panel as
	// its parent, so a widget that never reaches the tab widget stays a plain
	// child of the panel, outside its layout, and Qt draws it at the top left
	// over the tab bar. That is what the stray "Property" header was - the
	// control group and security trees painting over the tabs until the user
	// turned them on and they were finally given a page to live on.
	//
	// Doing it this way rather than by hiding the widget also means a tab hidden
	// by default and a tab the user hid are in the same state by construction,
	// which is what the tab bar and SetTabEnabled below both assume.
	//
	m_pTabs->addTab(Tab.pWidget, Tab.Name);
	if (!bVisible)
		m_pTabs->removeTab(m_pTabs->indexOf(Tab.pWidget));

	return m_AllTabs.count() - 1;
}

void CTabPanel::SaveTabs(int& ActiveTab, QStringList& VisibleTabs)
{
	ActiveTab = 0;
	VisibleTabs.clear();
	for(int i=0; i < m_AllTabs.size(); i++)
	{
		STab& Tab = m_AllTabs[i];

		VisibleTabs.append(QString::number(Tab.bVisible));
		if (m_pTabs->currentWidget() == Tab.pWidget)
			ActiveTab = i;
	}
}

void CTabPanel::RebuildTabs(const int ActiveTab, const QStringList& VisibleTabs)
{
	//
	// A saved layout is a list of flags by position, so it only means anything
	// against the same set of tabs it was written for. When a release adds or
	// removes one the old list would silently shift every choice along by one -
	// so a list of the wrong length is discarded and the defaults stand.
	//
	// Deliberately not migrated by name: the point of the defaults is that they
	// are right for the machine being looked at, and a half-mapped old layout is
	// worse than starting from what makes sense.
	//
	const bool bUseSaved = (VisibleTabs.size() == m_AllTabs.size());

	m_pTabs->clear();
	for(int i=0; i < m_AllTabs.size(); i++)
	{
		STab& Tab = m_AllTabs[i];

		//
		// The saved choice where there is a usable one, the default otherwise -
		// which for a tab that does not apply to the target is hidden.
		//
		if (bUseSaved)
			Tab.bVisible = (VisibleTabs[i].toInt() != 0);
		if (Tab.bVisible)
		{
			m_pTabs->addTab(Tab.pWidget, Tab.Name);
			if (i == ActiveTab)
				m_pTabs->setCurrentWidget(Tab.pWidget);
		}
	}
}
