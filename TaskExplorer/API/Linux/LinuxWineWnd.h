#pragma once
#include "../WndInfo.h"

class CVariant;

//
// A top-level window of a process running under Wine, as user32 sees it.
//
// The Linux side is not blind to these: a Wine top-level window is also an X11
// window, and CLinuxWnd finds it through _NET_CLIENT_LIST like any other. But
// what X11 has is the X11 window - its geometry, and whatever the toolkit chose
// to advertise. The HWND the program itself passes around, the class it
// registered, the styles it was created with, whether it is enabled: those are
// user32's, and only something running inside the prefix can ask.
//
// Keyed apart from the X11 windows in the process's list - see c_WineWindowKey -
// because the two describe the same window from two sides and neither is a
// substitute for the other.
//
// Acting on one goes back through the helper, because every one of these is a
// message or a call that only user32 can make and user32 here lives in the
// prefix. Which prefix that is comes from the process the window belongs to and
// is kept here, so that acting on a window does not have to find its way back
// to a process first.
//
class CWineWnd : public CWndInfo
{
	Q_OBJECT
public:
	CWineWnd(QObject* parent = NULL);

	//
	// Fill from one entry of a "Windows" reply. False for an entry with no
	// window handle, which is the only part that has to be there.
	//
	bool					Apply(quint64 Pid, const CVariant& Entry);

	virtual QString			GetWindowClass() const	{ QReadLocker Locker(&m_Mutex); return m_WindowClass; }

	virtual bool			IsNormal() const		{ return !IsMinimized() && !IsMaximized(); }
	virtual bool			IsMinimized() const		{ QReadLocker Locker(&m_Mutex); return m_bMinimized; }
	virtual bool			IsMaximized() const		{ QReadLocker Locker(&m_Mutex); return m_bMaximized; }

	//
	// What the helper can be asked to do to a window. Numbers rather than names
	// because that is what crosses to it; appended to, never reordered, since a
	// helper is deployed beside a daemon but not necessarily rebuilt with it.
	//
	enum EAction
	{
		eClose = 0,
		eQuit,
		eMinimize,
		eMaximize,
		eRestore,
		eBringToFront,
		eShow,
		eHide,
		eEnable,
		eDisable,
	};

	//
	// Which prefix to ask, and as whom. Set by the collector when the window is
	// first seen; see CLinuxProcess::UpdateWindows.
	//
	void					SetTarget(const QString& Prefix, int Bits, quint32 Uid)
							{ QWriteLocker Locker(&m_Mutex); m_Prefix = Prefix; m_Bits = Bits; m_Uid = Uid; }

	//
	// Each says what it was trying to do when it failed, using the same codes
	// the X11 windows use - the reading is the same whichever side of a Wine
	// process answered.
	//
	virtual STATUS			SetVisible(bool bSet)	{ return DoAction(bSet ? eShow : eHide, TE_ChangeWindowVisibility); }
	virtual STATUS			SetEnabled(bool bSet)	{ return DoAction(bSet ? eEnable : eDisable, TE_EnablingDisablingWindow); }
	virtual STATUS			BringToFront()			{ return DoAction(eBringToFront, TE_ActivateWindow); }
	virtual STATUS			Restore()				{ return DoAction(eRestore, TE_RestoreWindow); }
	virtual STATUS			Minimize()				{ return DoAction(eMinimize, TE_MinimizeWindow); }
	virtual STATUS			Maximize()				{ return DoAction(eMaximize, TE_MaximizeWindow); }
	virtual STATUS			Close()					{ return DoAction(eClose, TE_CloseWindow); }
	virtual STATUS			Quit()					{ return DoAction(eQuit, TE_CloseWindow); }

	//
	// Not through the helper. Alpha and always-on-top are layered-window and
	// z-order properties that Wine maps onto the host window manager, and
	// highlighting means drawing on the screen from a process that has no
	// business drawing there.
	//
	virtual STATUS			SetAlwaysOnTop(bool bSet) { Q_UNUSED(bSet); return ERR(TE_NotSupported); }
	virtual STATUS			SetWindowAlpha(int iAlpha) { Q_UNUSED(iAlpha); return ERR(TE_NotSupported); }
	virtual STATUS			Highlight()				{ return ERR(TE_NotSupported); }

	virtual SWndInfo		GetWndInfo() const;

protected:
	STATUS					DoAction(EAction Action, ETaskMsgCode FailCode);

	QString					m_Prefix;
	int						m_Bits = 0;
	quint32					m_Uid = 0;

	QString					m_WindowClass;
	bool					m_bMinimized = false;
	bool					m_bMaximized = false;
	quint32					m_Style = 0;
	quint32					m_StyleEx = 0;
	QRect					m_Rect;
};

//
// Where a Wine window sits in a process's window map.
//
// The map is keyed by the window handle, and both kinds of window have one: an
// X11 window id and an HWND are both small numbers and would collide. Above
// every X11 id there can be - those are 32 bit - so the two sets cannot meet.
//
static const quint64 c_WineWindowKey = 0x0000000100000000ull;

typedef QSharedPointer<CWineWnd> CWineWndPtr;
