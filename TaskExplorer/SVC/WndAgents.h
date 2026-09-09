#pragma once
#include "../taskcore_global.h"
#include "../API/TaskStatus.h"
#include "../API/WndInfo.h"
#include <QObject>
#include <QMap>
#include <QMultiMap>
#include <QList>
#include <QString>
#include <QReadWriteLock>

//
// The windows only somebody standing in the right place can see.
//
// EnumWindows and EnumDesktopWindows enumerate the *calling thread's* desktop.
// That is not a permission that can be acquired: a process in session 0 has no
// way to enumerate session 1's desktop however privileged it is, and neither
// has one user's process for another user's session. The list simply comes back
// empty, which is why the Windows tab of a process belonging to another logged
// on user has always been blank, and why a daemon installed as a service
// reports no windows at all.
//
// So somebody has to be standing there. This starts a copy of TaskHelper inside
// each session, asks it what it can see, and merges the answers with what this
// process could see itself. The helper is the same small binary already used for
// the privileged and 32-bit work; it needs no Qt and costs a couple of hundred
// kilobytes per session.
//
// ---- why it is off unless asked for ----
//
// Starting a process inside somebody else's logon session is not a small thing
// to do quietly. It is visible in their process list, it holds a handle to their
// token for as long as it runs, and on a machine where nobody has asked for it
// there is nothing to gain: the ordinary case is one user, one session, and the
// windows already visible. So it is a setting, and it is off.
//
// ---- what it is not ----
//
// Not a way around access control. Each agent runs as the user whose session it
// is in and can therefore see exactly what that user could see - which is the
// point of putting it there rather than reaching across. Starting one at all
// needs the privilege to create a process in that session, and the same access
// model that governs everything else decides who may see the result.
//
class TASKCORE_EXPORT CWndAgents : public QObject
{
	Q_OBJECT

public:
	static CWndAgents* Instance();

	//
	// Off unless the setting says otherwise. Turning it off stops the agents as
	// well as forgetting them: a helper left running in somebody's session
	// after the feature was switched off is exactly the surprise this is
	// careful not to be.
	//
	bool					IsEnabled() const;
	void					SetEnabled(bool bEnable);

	//
	// Sends the helpers away without touching anything else.
	//
	// Separate from SetEnabled(false), which also writes the setting down - and
	// which is the wrong thing to do while the application is being destroyed,
	// both because a run that ended should not turn the feature off behind the
	// user's back and because the settings object may already be gone.
	//
	void					Shutdown();

	//
	// One window as an agent reported it.
	//
	// Every field the local collector would have read with a Win32 call, because
	// the caller cannot make one: an HWND from another session means nothing
	// here. See CAgentWnd, which is a window built out of exactly this.
	//
	struct SWindow
	{
		quint64	hWnd = 0;
		quint64	Parent = 0;
		quint64	ProcessId = 0;
		quint64	ThreadId = 0;
		quint32	ShowCommand = 0;
		bool	Visible = false;
		bool	Enabled = false;
		bool	OnTop = false;
		QString	Title;
		QString	Class;
		QString	Desktop;

		//
		// Which agent it came from, so an action on it can be sent back to the
		// one place that can carry it out.
		//
		quint32	SessionId = 0;
	};

	//
	// Start what is missing, drop what has gone, and re-ask.
	//
	// Called from the window enumeration, which already runs on the collector's
	// own cadence. Rate limited inside: starting a process is not something to
	// do at the refresh interval, and the answer does not change fast enough to
	// be worth asking for that often either.
	//
	void					Update();

	QList<SWindow>			GetWindows(quint64 ProcessId) const;
	QMultiMap<quint64, quint64> GetWindowThreads(quint64 ProcessId) const;	// tid -> hwnd

	//
	// One action, sent to the agent whose session the window is in. The
	// numbering is the one in TaskHelper's DoWindowAction, which is CWndInfo's
	// order of business rather than Win32's.
	//
	enum EWndAction
	{
		eSetVisible = 1, eSetEnabled, eSetOnTop, eSetAlpha,
		eBringToFront, eHighlight, eRestore, eMinimize, eMaximize, eClose
	};
	STATUS					Action(quint64 hWnd, EWndAction Action, qint64 Value = 0);

	//
	// How many agents are answering, for the settings page to say so rather
	// than leaving somebody to wonder whether it did anything.
	//
	int						GetAgentCount() const;
	QStringList				GetAgentDescriptions() const;

	//
	// Why the last attempt to start one failed, in the platform's own words.
	//
	// Kept because the failure modes here are all invisible from outside: a
	// privilege that is not held, a session that has no token to borrow, a
	// helper that started and did not serve its pipe. Without this the feature
	// is a checkbox that either works or does nothing, and "does nothing" is
	// not a thing anyone can act on.
	//
	QString					GetLastError() const;

protected:
	CWndAgents(QObject* parent = nullptr);
	virtual ~CWndAgents();

	struct SAgent
	{
		quint32	SessionId = 0;
		QString	UserName;
		QString	Socket;
		quint64	ProcessId = 0;
		int		Failures = 0;
	};

	//
	// Which sessions are worth putting an agent in, and starting one where
	// there is none. Both are platform work and live in the .cpp behind an
	// ifdef; on anything that is not Windows this class does nothing at all and
	// says so honestly rather than pretending.
	//
	void					StartMissingAgents();
	bool					StartAgent(quint32 SessionId, const QString& UserName);
	void					StopAllAgents();
	void					AskAgents();

	mutable QReadWriteLock	m_Mutex;

	QMap<quint32, SAgent>	m_Agents;
	QMultiMap<quint64, SWindow>	m_Windows;		// by pid
	QMap<quint64, quint32>	m_WindowSessions;	// hwnd -> which agent

	void					SetError(const QString& Text);
	QString					m_LastError;

	quint64					m_LastUpdate = 0;
	quint64					m_LastStart = 0;
	bool					m_bEnabled = false;
	bool					m_bChecked = false;
};

//
// A window an agent reported, rather than one this process can touch.
//
// Everything it answers came over the pipe; everything it does goes back the
// same way. The view cannot tell it from CWinWnd, which is the whole point -
// the Windows tab of a process in another session is the same tab.
//
class TASKCORE_EXPORT CAgentWnd : public CWndInfo
{
	Q_OBJECT

public:
	CAgentWnd(QObject* parent = nullptr);
	virtual ~CAgentWnd();

	void					Set(const CWndAgents::SWindow& Window, const QString& ProcessName);
	bool					Update(const CWndAgents::SWindow& Window);

	virtual QString			GetWindowClass() const		{ QReadLocker Locker(&m_Mutex); return m_WindowClass; }

	//
	// The desktop it lives on, which is the one thing a local window never has
	// to say: if you can see it at all, it is on yours.
	//
	QString					GetDesktop() const			{ QReadLocker Locker(&m_Mutex); return m_Desktop; }

	virtual bool			IsNormal() const			{ QReadLocker Locker(&m_Mutex); return m_ShowCommand == 1; }
	virtual bool			IsMinimized() const			{ QReadLocker Locker(&m_Mutex); return m_ShowCommand == 2 || m_ShowCommand == 6 || m_ShowCommand == 7; }
	virtual bool			IsMaximized() const			{ QReadLocker Locker(&m_Mutex); return m_ShowCommand == 3; }

	virtual STATUS			SetVisible(bool bSet);
	virtual STATUS			SetEnabled(bool bSet);
	virtual STATUS			SetAlwaysOnTop(bool bSet);
	virtual STATUS			SetWindowAlpha(int iAlpha);
	virtual STATUS			BringToFront();
	virtual STATUS			Highlight();
	virtual STATUS			Restore();
	virtual STATUS			Minimize();
	virtual STATUS			Maximize();
	virtual STATUS			Close();

protected:
	QString					m_WindowClass;
	QString					m_Desktop;
};
