#pragma once
#include "../WndInfo.h"

#undef IsMinimized
#undef IsMaximized

class CWinWnd : public CWndInfo
{
	Q_OBJECT

	TRACK_OBJECT(CWinWnd)
public:
	CWinWnd(QObject *parent = nullptr);
	virtual ~CWinWnd();

	virtual QString GetWindowClass() const		{ QReadLocker Locker(&m_Mutex); return m_WindowClass; }
	virtual QString GetModuleString() const		{ QReadLocker Locker(&m_Mutex); return m_ModuleString; }

	virtual bool IsWindowValid() const;

	virtual STATUS SetVisible(bool bSet);
	virtual STATUS SetEnabled(bool bSet);
	virtual STATUS SetAlwaysOnTop(bool bSet);
	virtual STATUS SetWindowAlpha(int iAlpha);

	virtual STATUS PostWndMessage(quint32 Msg, quint64 wParam = 0, quint64 lParam = 0);
	virtual STATUS Quit();
	virtual STATUS BringToFront();
	virtual STATUS Highlight();
	virtual bool IsNormal() const;
	virtual STATUS Restore();
	virtual bool IsMinimized() const;
	virtual STATUS Minimize();
	virtual bool IsMaximized() const;
	virtual STATUS Maximize();
	virtual STATUS Close();


	virtual SWndInfo GetWndInfo() const;

	typedef void (*WNDENUMPROCEX)(quint64 hWnd, /*quint64 hParent,*/ void* Param);

	static void EnumAllWindows(WNDENUMPROCEX in_Proc, void* in_Param);

protected:
	friend class CWindowsAPI;
	friend class CWinProcess;

	bool InitStaticData(quint64 ProcessId, quint64 ThreadId, quint64 hWnd, void* QueryHandle, const QString& ProcessName);
	bool UpdateDynamicData();

	QString			m_WindowClass;
	QString			m_ModuleString;
};