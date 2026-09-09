#pragma once
#include <qobject.h>
#include "../../MiscHelpers/Common/Status.h"
#include "AbstractInfo.h"

#ifdef WIN32
#undef IsMinimized
#undef IsMaximized
#endif

class TASKCORE_EXPORT CWndInfo: public CAbstractInfo
{
	Q_OBJECT

public:
	CWndInfo(QObject *parent = nullptr);
	virtual ~CWndInfo();

	virtual quint64 GetHWnd() const				{ QReadLocker Locker(&m_Mutex); return m_hWnd; }
	virtual quint64 GetParentWnd() const		{ QReadLocker Locker(&m_Mutex); return m_ParentWnd; }
	virtual quint64 GetProcessId() const		{ QReadLocker Locker(&m_Mutex); return m_ProcessId; }
	virtual quint64 GetThreadId() const			{ QReadLocker Locker(&m_Mutex); return m_ThreadId; }
	virtual QString GetProcessName() const		{ QReadLocker Locker(&m_Mutex); return m_ProcessName; }

	virtual QString GetWindowTitle() const		{ QReadLocker Locker(&m_Mutex); return m_WindowTitle; }
	virtual bool IsVisible() const				{ QReadLocker Locker(&m_Mutex); return m_WindowVisible; }
	virtual STATUS SetVisible(bool bSet) = 0;
	virtual bool IsEnabled() const				{ QReadLocker Locker(&m_Mutex); return m_WindowEnabled; }
	virtual bool IsHung() const					{ QReadLocker Locker(&m_Mutex); return m_WindowHung; }
	virtual int GetShowCommand() const			{ QReadLocker Locker(&m_Mutex); return m_ShowCommand; }
	virtual STATUS SetEnabled(bool bSet) = 0;
	virtual bool IsAlwaysOnTop() const			{ QReadLocker Locker(&m_Mutex); return m_WindowOnTop; }
	virtual STATUS SetAlwaysOnTop(bool bSet) = 0;
	virtual int GetWindowAlpha() const			{ QReadLocker Locker(&m_Mutex); return m_WindowAlpha; }
	virtual STATUS SetWindowAlpha(int iAlpha) = 0;

	virtual STATUS BringToFront() = 0;
	virtual STATUS Highlight() = 0;
	virtual bool IsNormal() const = 0;
	virtual STATUS Restore() = 0;
	virtual bool IsMinimized() const = 0;
	virtual STATUS Minimize() = 0;
	virtual bool IsMaximized() const = 0;
	virtual STATUS Maximize() = 0;
	virtual STATUS Close() = 0;

	//
	// Ask the application to exit rather than just closing this window.
	//
	// Windows distinguishes WM_CLOSE from WM_QUIT; X11 has only the one close
	// protocol, WM_DELETE_WINDOW, so the default is simply Close().
	//
	virtual STATUS Quit()						{ return Close(); }
		

	//
	// ---- platform surface ----
	//
	// Everything either platform can report, so the models never need to know
	// which one answered. An implementation without the notion does not
	// override; the default below is the honest answer, and whether a column
	// built on it is worth showing is decided by GetOsType()/HasCapability().
	//
	//
	// The full detail sheet for one window: geometry, styles, class registration
	// and any properties attached to it. Collected on demand when the window
	// details pane is opened.
	//
	struct SWndInfo
	{
		QString AppID;
		QString Text;
		//
		// Which thread owns the window. The three parts are kept apart so the
		// line can be put together for reading; the start address is a symbol
		// only the machine holding the process can resolve.
		//
		QString ThreadStartAddress;
		quint64 ThreadProcessId = 0;
		quint64 ThreadId = 0;
		QRect	Rect;
		QRect	NormalRect;
		QRect	ClientRect;
		quint64 MenuHandle = 0;
		quint64 InstanceHandle = 0;
		QString InstanceString;
		quint64 UserdataHandle = 0;
		bool	IsUnicode = false;
		quint32	WindowId = 0;
		QString Font;
		QString Styles;
		QString StylesEx;

		QString ClassName;
		quint64 Atom = 0;
		quint64 hIcon = 0;
		quint64 hIconSm = 0;
		quint64 lpszMenuName = 0;
		quint64 hCursor = 0;
		quint64 hbrBackground = 0;
		QString StylesClass;
		quint64 InstanceHandle2 = 0;
		QString InstanceString2;

		QMap<QString, QString> Properties;

		QMap<QString, QString> PropertyStorage;
	};
	virtual SWndInfo GetWndInfo() const				{ return SWndInfo(); }

	virtual QString GetWindowClass() const			{ return QString(); }
	virtual QString GetModuleString() const			{ return QString(); }

protected:

	quint64			m_hWnd;
	quint64			m_ParentWnd;
	quint64			m_ProcessId;
    quint64			m_ThreadId;
	QString			m_ProcessName;

	QString			m_WindowTitle;
	bool			m_WindowVisible;
	bool			m_WindowEnabled;
	bool			m_WindowHung;
	int				m_ShowCommand;
	bool			m_WindowOnTop;
	int				m_WindowAlpha;

	/*QWeakPointer<CWndInfo>						m_ParentWindow;
	QMap<quint64, QSharedPointer<CWndInfo> >	m_ChildWindows;*/
};

typedef QSharedPointer<CWndInfo> CWndPtr;
typedef QWeakPointer<CWndInfo> CWndRef;