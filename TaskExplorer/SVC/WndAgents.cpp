#include "stdafx.h"
#include "WndAgents.h"
#include "TaskService.h"
#include "../API/WndInfo.h"
#include "../API/SystemAPI.h"
#include "../../MiscHelpers/Common/Common.h"
#include "../../MiscHelpers/Common/Settings.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>

#ifdef WIN32
#include <windows.h>
#include <wtsapi32.h>
#pragma comment(lib, "wtsapi32.lib")

//
// For StartProcessInSession, which is where starting a program in another
// session lives - the run dialog needs exactly the same thing.
//
#include "../API/Windows/WindowsAPI.h"
#endif

//
// How often the agents are asked, and how often a missing one is started.
//
// The first is a fraction of a second slower than the refresh, because a window
// list is not a counter and nobody watches one change. The second is far slower
// still: starting a process is the expensive half, and a session where the
// helper cannot be started is one where retrying every second would be a login
// storm rather than a monitor.
//
static const quint64 c_AskInterval = 2000;
static const quint64 c_StartInterval = 30000;
static const quint64 c_RetryInterval = 5000;

//
// Stopped when the application does.
//
// qAddPostRoutine rather than a destructor on a leaked singleton: the instance
// is deliberately never deleted - anything could still be asking it during
// teardown - but the helpers it started have to be told to go, and this is the
// last moment at which there is still a Qt event loop to tell them with.
//
// Shutdown(), not SetEnabled(false). This called SetEnabled(false), which
// writes the setting, which is guarded by QCoreApplication::closingDown() -
// and that guard is false here. Qt's destructor calls qt_call_post_routines()
// *five lines before* it sets is_app_closing, so a post routine asking whether
// the application is closing down is always told no. Every front end deletes
// theConf before its application object goes, so the write landed on a null
// pointer and the process died on the way out:
//
//     Qt6Core!QBasicMutex::lock
//     CoreHelpers!CSettings::SetValue+0x46
//     TaskCore!CWndAgents::SetEnabled+0x85
//     Qt6Core!qt_call_post_routines+0xe9
//     Qt6Core!QCoreApplication::~QCoreApplication+0x2d
//
// Which is why a service that had done its job looked like a service that
// would not start: Windows records the crash as "terminated unexpectedly",
// and a stopped service that crashed on the way out reads the same as one that
// never came up.
//
static void StopWndAgents()
{
	CWndAgents::Instance()->Shutdown();
}

CWndAgents* CWndAgents::Instance()
{
	static CWndAgents* pInstance = NULL;
	if (!pInstance)
	{
		pInstance = new CWndAgents();
		qAddPostRoutine(StopWndAgents);
	}
	return pInstance;
}

CWndAgents::CWndAgents(QObject* parent) : QObject(parent)
{
}

CWndAgents::~CWndAgents()
{
	StopAllAgents();
}

bool CWndAgents::IsEnabled() const
{
	QReadLocker Locker(&m_Mutex);
	if (!m_bChecked)
	{
		//
		// Read once and remembered, because this is asked on every window
		// enumeration and a settings lookup per refresh is a cost with no
		// answer to show for it. SetEnabled is what changes it.
		//
		const_cast<CWndAgents*>(this)->m_bEnabled =
			theConf ? theConf->GetBool("Options/UseDesktopAgents", false) : false;
		const_cast<CWndAgents*>(this)->m_bChecked = true;
	}
	return m_bEnabled;
}

void CWndAgents::SetEnabled(bool bEnable)
{
	{
		QWriteLocker Locker(&m_Mutex);
		m_bEnabled = bEnable;
		m_bChecked = true;
	}

	//
	// Written down, because this is a choice somebody made. The shutdown path
	// does not come through here - see Shutdown() - so there is nothing to
	// suppress and nothing to guard against; theConf is checked only because a
	// singleton that is deliberately never deleted can be reached from more
	// places than it can be reasoned about.
	//
	if (theConf)
		theConf->SetValue("Options/UseDesktopAgents", bEnable);

	//
	// Off means gone, not merely unused. A helper left running in somebody
	// else's session after the feature was switched off is precisely the thing
	// this feature is careful not to be.
	//
	if (!bEnable)
		StopAllAgents();
	else
		Update();
}

//
// The helpers go; the setting stays as the user left it.
//
// m_bEnabled is turned off as well, so that anything still asking during
// teardown is told the feature is not running - which is true - without that
// answer being written anywhere.
//
void CWndAgents::Shutdown()
{
	{
		QWriteLocker Locker(&m_Mutex);
		m_bEnabled = false;
		m_bChecked = true;
	}
	StopAllAgents();
}

int CWndAgents::GetAgentCount() const
{
	QReadLocker Locker(&m_Mutex);
	return m_Agents.count();
}

QString CWndAgents::GetLastError() const
{
	QReadLocker Locker(&m_Mutex);
	return m_LastError;
}

void CWndAgents::SetError(const QString& Text)
{
	QWriteLocker Locker(&m_Mutex);
	m_LastError = Text;
}

QStringList CWndAgents::GetAgentDescriptions() const
{
	QReadLocker Locker(&m_Mutex);

	QStringList List;
	foreach(const SAgent& Agent, m_Agents)
		List.append(QString("%1: %2").arg(Agent.SessionId).arg(Agent.UserName));
	return List;
}

QList<CWndAgents::SWindow> CWndAgents::GetWindows(quint64 ProcessId) const
{
	QReadLocker Locker(&m_Mutex);
	return m_Windows.values(ProcessId);
}

QMultiMap<quint64, quint64> CWndAgents::GetWindowThreads(quint64 ProcessId) const
{
	QReadLocker Locker(&m_Mutex);

	QMultiMap<quint64, quint64> Map;
	foreach(const SWindow& Window, m_Windows.values(ProcessId))
		Map.insert(Window.ThreadId, Window.hWnd);
	return Map;
}

void CWndAgents::Update()
{
	if (!IsEnabled())
		return;

	//
	// GetCurTick counts from when *this process* started, not from boot - so a
	// zero here means "now", not "long ago", and a plain difference would wait
	// out the whole interval before the first attempt. The explicit never is
	// what makes the first refresh after switching this on do something.
	//
	const quint64 Now = GetCurTick();

	//
	// Sooner while there is nothing. The long interval is there to stop a
	// session that cannot be entered from being hammered - but until one agent
	// exists there is nothing working to protect, and a first attempt that
	// happened to be made half a second too early should not cost half a
	// minute of blank window lists.
	//
	const quint64 Interval = m_Agents.isEmpty() ? c_RetryInterval : c_StartInterval;

	if (!m_LastStart || Now - m_LastStart > Interval)
	{
		m_LastStart = Now;
		StartMissingAgents();
	}

	if (m_LastUpdate && Now - m_LastUpdate < c_AskInterval)
		return;
	m_LastUpdate = Now;

	AskAgents();
}

//
// Ask every agent what it can see, and replace what is held.
//
// Replaced whole rather than merged: a window that has closed has to disappear,
// and an agent that has died has to take its windows with it rather than
// leaving a list nobody will ever correct.
//
void CWndAgents::AskAgents()
{
	QMap<quint32, SAgent> Agents;
	{
		QReadLocker Locker(&m_Mutex);
		Agents = m_Agents;
	}

	QMultiMap<quint64, SWindow> Windows;
	QMap<quint64, quint32> Sessions;
	QList<quint32> Dead;

	for (QMap<quint32, SAgent>::iterator I = Agents.begin(); I != Agents.end(); ++I)
	{
		const QVariant Reply = CTaskService::SendCommand(I->Socket, "EnumWindows", 10000);
		if (Reply.type() != QVariant::List)
		{
			//
			// Two strikes. One missed answer is a helper that was busy or a
			// session that was locking itself; a second in a row is one that
			// has gone, and holding its windows any longer would be showing
			// somebody a desktop that is not there.
			//
			if (++I->Failures >= 2)
				Dead.append(I.key());
			continue;
		}

		I->Failures = 0;

		foreach(const QVariant& One, Reply.toList())
		{
			const QVariantMap Entry = One.toMap();

			SWindow Window;
			Window.hWnd = Entry.value("hWnd").toULongLong();
			Window.Parent = Entry.value("Parent").toULongLong();
			Window.ProcessId = Entry.value("Pid").toULongLong();
			Window.ThreadId = Entry.value("Tid").toULongLong();
			Window.ShowCommand = Entry.value("Show").toUInt();
			Window.Visible = Entry.value("Visible").toInt() != 0;
			Window.Enabled = Entry.value("Enabled").toInt() != 0;
			Window.OnTop = Entry.value("OnTop").toInt() != 0;
			Window.Title = Entry.value("Title").toString();
			Window.Class = Entry.value("Class").toString();
			Window.Desktop = Entry.value("Desktop").toString();
			Window.SessionId = I->SessionId;

			if (!Window.hWnd || !Window.ProcessId)
				continue;

			Windows.insert(Window.ProcessId, Window);
			Sessions.insert(Window.hWnd, I->SessionId);
		}
	}

	QWriteLocker Locker(&m_Mutex);

	foreach(quint32 SessionId, Dead)
		m_Agents.remove(SessionId);

	for (QMap<quint32, SAgent>::const_iterator I = Agents.constBegin(); I != Agents.constEnd(); ++I)
	{
		if (m_Agents.contains(I.key()))
			m_Agents[I.key()].Failures = I->Failures;
	}

	m_Windows = Windows;
	m_WindowSessions = Sessions;
}

STATUS CWndAgents::Action(quint64 hWnd, EWndAction Action, qint64 Value)
{
	QString Socket;
	{
		QReadLocker Locker(&m_Mutex);

		const quint32 SessionId = m_WindowSessions.value(hWnd, (quint32)-1);
		if (SessionId == (quint32)-1)
			return ERR(TE_NotSupported);

		QMap<quint32, SAgent>::const_iterator I = m_Agents.constFind(SessionId);
		if (I == m_Agents.constEnd())
			return ERR(TE_HelperNoAnswer);
		Socket = I->Socket;
	}

	QVariantMap Parameters;
	Parameters["hWnd"] = hWnd;
	Parameters["Action"] = (quint64)Action;
	Parameters["Value"] = (qint64)Value;

	QVariantMap Request;
	Request["Command"] = "WndAction";
	Request["Parameters"] = Parameters;

	const QVariant Reply = CTaskService::SendCommand(Socket, Request, 10000);
	if (!Reply.isValid())
		return ERR(TE_HelperNoAnswer);

	const long Status = (long)Reply.toInt();
	if (Status != 0)
		return CStatus::Native(Status);
	return OK;
}

#ifdef WIN32

//
// A primary token for a session, by whichever route this process is entitled to.
//
// WTSQueryUserToken is the direct one and wants SeTcbPrivilege, which the
// LocalSystem account has and an administrator does not. So an elevated user
// falls back to borrowing the token of a process already in that session, which
// wants SeDebugPrivilege - which an elevated administrator does have.
//
// Neither route grants anything: both produce the token that session is already
// running under, and the helper started with it can see exactly what that user
// could see. That is the point of putting it there.
//
//
// The platform's own last error, kept apart because CWndAgents has a member of
// the same name and the Windows macro would otherwise win the argument.
//
static quint32 GetLastError_()
{
	return (quint32)::GetLastError();
}

bool CWndAgents::StartAgent(quint32 SessionId, const QString& UserName)
{
	QString BinaryPath = QCoreApplication::applicationDirPath() + "/TaskHelper.exe";
	BinaryPath = QDir::toNativeSeparators(QDir::cleanPath(BinaryPath));
	if (!QFile::exists(BinaryPath))
	{
		SetError(QString("TaskHelper.exe not found at %1").arg(BinaryPath));
		return false;
	}

	//
	// A timeout, and not a generous one.
	//
	// The agent is asked every couple of seconds for as long as anybody wants
	// it, so two minutes of silence means the thing that started it has gone -
	// and a helper sitting in somebody else's logon session because a viewer
	// crashed is exactly what this feature must not leave behind. Shutting them
	// down properly is done too; this is what covers the times that does not
	// run.
	//
	const QString Socket = QString("TaskExplorerWnd_%1_%2").arg(SessionId).arg(GetRand64Str());
	const QString Command = QString("\"%1\" -wrk \"%2\" -timeout 120000").arg(BinaryPath).arg(Socket);

	//
	// Through the same launcher the run dialog uses - see StartProcessInSession
	// in WindowsAPI.h. An agent is nothing but a program started in somebody
	// else's session, and there is no reason for two ways of doing that.
	//
	// The linked token, deliberately: user interface privilege isolation drops
	// a message sent from a medium integrity process to a high integrity
	// window, silently, so an agent holding only the filtered token would
	// report every window on the desktop and be able to act on about half of
	// them. It grants nothing - getting this far already required being
	// LocalSystem or an elevated administrator.
	//
	quint64 Pid = 0;
	const STATUS Status = StartProcessInSession(SessionId, Command, true, &Pid);
	if (Status.IsError())
	{
		SetError(QString("session %1: could not start the helper (%2)")
			.arg(SessionId).arg(Status.GetArgs().isEmpty() ? QString::number(Status.GetStatus()) : Status.GetArgs().first().toString()));
		return false;
	}

	//
	// Confirmed before it is recorded. A process that started and then failed
	// to serve its pipe would otherwise sit in the map being asked and never
	// answering, which reads as two strikes and a restart, for ever.
	//
	for (int i = 0; i < 20; i++)
	{
		if (CTaskService::SendCommand(Socket, "Refresh", 500).toBool())
		{
			SAgent Agent;
			Agent.SessionId = SessionId;
			Agent.UserName = UserName;
			Agent.Socket = Socket;
			Agent.ProcessId = Pid;

			QWriteLocker Locker(&m_Mutex);
			m_Agents.insert(SessionId, Agent);
			m_LastError.clear();
			return true;
		}
	}

	SetError(QString("session %1: the helper started as pid %2 but never answered")
		.arg(SessionId).arg(Pid));
	return false;
}

//
// One agent per session that has somebody logged into it.
//
// Including this process's own session, deliberately. It costs one small
// process and it means the window list has one source rather than two that have
// to be reconciled - and on a machine where this is switched on at all, the
// interesting case is usually that this process cannot see its own session
// either, because it is a service.
//
void CWndAgents::StartMissingAgents()
{
	PWTS_SESSION_INFOW Sessions = NULL;
	DWORD Count = 0;
	if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &Sessions, &Count))
	{
		SetError(QString("the sessions could not be enumerated (error %1)").arg((quint32)GetLastError_()));
		return;
	}

	QMap<quint32, QString> Wanted;
	for (DWORD i = 0; i < Count; i++)
	{
		//
		// Connected or disconnected but logged on. A session sitting at the
		// logon screen has no user and nothing worth looking at, and trying to
		// start something in it fails slowly.
		//
		if (Sessions[i].State != WTSActive && Sessions[i].State != WTSDisconnected)
			continue;

		LPWSTR Name = NULL;
		DWORD Size = 0;
		QString UserName;
		if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, Sessions[i].SessionId,
										WTSUserName, &Name, &Size))
		{
			UserName = QString::fromWCharArray(Name);
			WTSFreeMemory(Name);
		}

		if (UserName.isEmpty())
			continue;

		Wanted.insert((quint32)Sessions[i].SessionId, UserName);
	}
	WTSFreeMemory(Sessions);

	QList<quint32> Missing;
	{
		QReadLocker Locker(&m_Mutex);
		foreach(quint32 SessionId, Wanted.keys())
		{
			if (!m_Agents.contains(SessionId))
				Missing.append(SessionId);
		}
	}

	//
	// Said even when there is nothing to do, because "no agents and no reason"
	// is the one outcome that leaves somebody with nowhere to look - and a
	// machine with one logged-on session and an agent already in it is the
	// ordinary case, not a fault.
	//
	if (Wanted.isEmpty())
		SetError(QString("%1 session(s) enumerated, none with a logged-on user").arg(Count));
	else if (Missing.isEmpty())
		SetError(QString());

	foreach(quint32 SessionId, Missing)
		StartAgent(SessionId, Wanted.value(SessionId));
}

void CWndAgents::StopAllAgents()
{
	QMap<quint32, SAgent> Agents;
	{
		QWriteLocker Locker(&m_Mutex);
		Agents = m_Agents;
		m_Agents.clear();
		m_Windows.clear();
		m_WindowSessions.clear();
	}

	//
	// Asked to go rather than killed. The helper exits on the Quit command like
	// every other worker, and a process terminated out from under its own pipe
	// leaves the name held until the handle is reaped.
	//
	foreach(const SAgent& Agent, Agents)
		CTaskService::Terminate(Agent.Socket);
}

#else // !WIN32

//
// Desktops and window stations are a Windows notion. X11 and Wayland have the
// analogous problem - a process cannot enumerate another user's display - but
// the shape of the answer there is a different one, and nothing has asked for
// it yet. So this does nothing, visibly, rather than half of something.
//
bool CWndAgents::StartAgent(quint32 SessionId, const QString& UserName)
{
	Q_UNUSED(SessionId); Q_UNUSED(UserName);
	return false;
}

void CWndAgents::StartMissingAgents() {}

void CWndAgents::StopAllAgents()
{
	QWriteLocker Locker(&m_Mutex);
	m_Agents.clear();
	m_Windows.clear();
	m_WindowSessions.clear();
}

#endif

// ---------------------------------------------------------------- one window

CAgentWnd::CAgentWnd(QObject* parent) : CWndInfo(parent)
{
}

CAgentWnd::~CAgentWnd()
{
}

void CAgentWnd::Set(const CWndAgents::SWindow& Window, const QString& ProcessName)
{
	QWriteLocker Locker(&m_Mutex);

	m_hWnd = Window.hWnd;
	m_ParentWnd = Window.Parent;
	m_ProcessId = Window.ProcessId;
	m_ThreadId = Window.ThreadId;
	m_ProcessName = ProcessName;
	m_WindowClass = Window.Class;
	m_Desktop = Window.Desktop;

	m_WindowTitle = Window.Title;
	m_WindowVisible = Window.Visible;
	m_WindowEnabled = Window.Enabled;
	m_WindowOnTop = Window.OnTop;
	m_ShowCommand = Window.ShowCommand;
}

//
// Returns whether anything a view would redraw actually moved, which is what
// the update contract asks for: the process reports Added, Changed and Removed
// separately and a row that says it changed every round flickers.
//
bool CAgentWnd::Update(const CWndAgents::SWindow& Window)
{
	QWriteLocker Locker(&m_Mutex);

	bool bChanged = m_WindowTitle != Window.Title
				 || m_WindowVisible != Window.Visible
				 || m_WindowEnabled != Window.Enabled
				 || m_WindowOnTop != Window.OnTop
				 || m_ShowCommand != (int)Window.ShowCommand;

	m_WindowTitle = Window.Title;
	m_WindowVisible = Window.Visible;
	m_WindowEnabled = Window.Enabled;
	m_WindowOnTop = Window.OnTop;
	m_ShowCommand = Window.ShowCommand;

	return bChanged;
}

STATUS CAgentWnd::SetVisible(bool bSet)		{ return CWndAgents::Instance()->Action(GetHWnd(), CWndAgents::eSetVisible, bSet ? 1 : 0); }
STATUS CAgentWnd::SetEnabled(bool bSet)		{ return CWndAgents::Instance()->Action(GetHWnd(), CWndAgents::eSetEnabled, bSet ? 1 : 0); }
STATUS CAgentWnd::SetAlwaysOnTop(bool bSet)	{ return CWndAgents::Instance()->Action(GetHWnd(), CWndAgents::eSetOnTop, bSet ? 1 : 0); }
STATUS CAgentWnd::SetWindowAlpha(int iAlpha){ return CWndAgents::Instance()->Action(GetHWnd(), CWndAgents::eSetAlpha, iAlpha); }
STATUS CAgentWnd::BringToFront()			{ return CWndAgents::Instance()->Action(GetHWnd(), CWndAgents::eBringToFront); }
STATUS CAgentWnd::Highlight()				{ return CWndAgents::Instance()->Action(GetHWnd(), CWndAgents::eHighlight); }
STATUS CAgentWnd::Restore()					{ return CWndAgents::Instance()->Action(GetHWnd(), CWndAgents::eRestore); }
STATUS CAgentWnd::Minimize()				{ return CWndAgents::Instance()->Action(GetHWnd(), CWndAgents::eMinimize); }
STATUS CAgentWnd::Maximize()				{ return CWndAgents::Instance()->Action(GetHWnd(), CWndAgents::eMaximize); }
STATUS CAgentWnd::Close()					{ return CWndAgents::Instance()->Action(GetHWnd(), CWndAgents::eClose); }
