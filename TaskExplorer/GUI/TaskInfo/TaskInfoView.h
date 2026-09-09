#pragma once
#include <qwidget.h>
#include "../../../MiscHelpers/Common/TabPanel.h"
#include "../../API/ProcessInfo.h"

class CProcessView;
class CHandlesView;
class CSocketsView;
class CThreadsView;
class CModulesView;
class CWindowsView;
class CMemoryView;
class CHeapView;
class CTokenView;
class CJobView;
//class CServicesView;
class CDotNetView;
class CGDIView;
class CCGroupView;
class CSecurityView;
//class CDnsCacheView;
class CDebugView;
//class CEnvironmentView;
class CSbieView;


class CTaskInfoView : public CTabPanel
{
	Q_OBJECT
public:
	CTaskInfoView(bool bAsWindow = false, QWidget* patent = 0);
	virtual ~CTaskInfoView();

	enum ETabs
	{
		eProcessView = 0, 
		eFilesView, 
		eHandlesView, 
		eSocketsView, 
		eThreadsView, 
		eModulesView, 
		eWindowsView, 
		eMemoryView, 
		eTokenView, 
		eJobView, 
		//eServiceView,
		eDotNetView, 
		eGDIView, 
		//eDnsCacheView, 
		eDebugView, 
		//eEnvironmentView,
		eTabCount
	};

public slots:
	void				OnTab(int tabIndex);
	//void				ShowProcess(const CProcessPtr& pProcess);
	void				ShowProcesses(const QList<CProcessPtr>& Processes);

	//
	// Lets go of anything collected on a machine that is no longer connected.
	//
	// Called rather than inferred, because nothing about a held CProcessPtr
	// changes when its machine goes: the object stays alive and answers its own
	// questions from the last round it saw. Only the machine's departure says
	// that what it answers is no longer true.
	//
	void				DropSystem(const CSystemPtr& pSystem);

private:
	//
	// Brings the selected processes’ detail up to date before a panel reads it.
	//
	// This is the caller API_CMD_PROCDETAIL never had. Everything the per-process
	// detail request carries - the working directory, the desktop, the PEB
	// addresses, the protection, the token’s groups and privileges - was written,
	// wired and then asked for by nobody, which is invisible precisely because
	// the fields it *duplicates* from the process list did arrive.
	//
	// Here because this is the one place that knows both halves of the question:
	// which processes are selected, and which panel is looking at them. A local
	// process answers instantly - CProcessInfo::UpdateDetails returns true and
	// does nothing - so this costs nothing at all unless the machine is remote.
	//
	void				UpdateDetails();

public:
	void				SelectThread(quint64 ThreadId);
	void				Refresh();

protected:
	virtual void		InitializeTabs();

	QList<CProcessPtr>  m_Processes;
	bool				m_bAsWindow;

	//
	// Which command each tab needs the machine the selected process lives on to
	// be able to answer, and the check that greys the ones it cannot. Only the
	// tabs that *are* a per-process list are in here; the rest read fields of the
	// process object and will be gated by the per-tab detail request when there
	// is one - see NEXT.md 5.3.
	//
	QMap<int, quint32>	m_TabFeature;

	//
	// The Windows tabs a process under Wine can actually fill.
	//
	// A Wine process is a Windows process to everything that matters here, but
	// only as far as the bridge into the prefix reaches - see CWineHelper. It
	// answers the token, the handles and the windows; there is nothing behind
	// the heap, the job, the managed counters, the GDI table or the debug
	// output, and enabling those tabs produced pages that could only ever be
	// blank.
	//
	QSet<int>			m_WineTabs;

	//
	// Tabs that only mean anything for the machine this viewer runs on.
	//
	// Not "not implemented over the wire" - most of those are shown and say so.
	// These are the ones whose data is a *stream* the daemon consumes locally,
	// with no subscription on the wire to carry it, so there is nothing to wait
	// for and nothing to explain later.
	//
	QSet<int>			m_LocalOnlyTabs;

	void				UpdateTabAvailability();

private:
	CProcessView*		m_pProcessView;
	CHandlesView*		m_pFilesView;
	CHandlesView*		m_pHandlesView;
	CSocketsView*		m_pSocketsView;
	CThreadsView*		m_pThreadsView;
	CModulesView*		m_pModulesView;
	CWindowsView*		m_pWindowsView;
	CMemoryView*		m_pMemoryView;
	CHeapView*			m_pHeapView;
	//
	// All of them, on both platforms. Which are shown is decided from the
	// target's operating system when the tabs are built - see InitializeTabs.
	//
	CTokenView*			m_pTokenView;
	CJobView*			m_pJobView;
	//CServicesView*		m_pServiceView;
	CDotNetView*		m_pDotNetView;
	CGDIView*			m_pGDIView;
	CCGroupView*		m_pCGroupView;
	CSecurityView*		m_pSecurityView;
	//CDnsCacheView*		m_pDnsCacheView;
	CDebugView*			m_pDebugView;
	//CEnvironmentView*	m_pEnvironmentView;
	CSbieView*			m_pSbieView;
};

