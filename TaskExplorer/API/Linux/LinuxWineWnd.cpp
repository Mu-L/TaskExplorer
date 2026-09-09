#include "stdafx.h"
#include "LinuxWineWnd.h"
#include "LinuxWineHelper.h"
#include "../../../MiscHelpers/Common/Variant.h"
#include "../../../MiscHelpers/Common/XVariant.h"

CWineWnd::CWineWnd(QObject* parent)
	: CWndInfo(parent)
{
}

bool CWineWnd::Apply(quint64 Pid, const CVariant& Entry)
{
	CVariant Value;
	if (!Entry.Find("Wnd", Value))
		return false;

	QWriteLocker Locker(&m_Mutex);

	m_hWnd = Value.To<quint64>();
	m_ProcessId = Pid;

	if (Entry.Find("Parent", Value))	m_ParentWnd = Value.To<quint64>();
	if (Entry.Find("Thread", Value))	m_ThreadId = Value.To<quint32>();
	if (Entry.Find("Class", Value))		m_WindowClass = XVariant(Value).AsQStr();

	//
	// A window with no title is ordinary - a tool window, a hidden message-only
	// window - so the field is absent rather than empty and is cleared here.
	//
	m_WindowTitle = Entry.Find("Title", Value) ? XVariant(Value).AsQStr() : QString();

	if (Entry.Find("Visible", Value))	m_WindowVisible = Value.To<bool>();
	if (Entry.Find("Enabled", Value))	m_WindowEnabled = Value.To<bool>();
	if (Entry.Find("Minimized", Value))	m_bMinimized = Value.To<bool>();
	if (Entry.Find("Maximized", Value))	m_bMaximized = Value.To<bool>();

	if (Entry.Find("Style", Value))		m_Style = Value.To<quint32>();
	if (Entry.Find("StyleEx", Value))	m_StyleEx = Value.To<quint32>();

	//
	// The rectangle travels as its four edges rather than as a QRect, because a
	// QRect is not a value this protocol carries and the four numbers are.
	//
	CVariant L, T, R, B;
	if (Entry.Find("Left", L) && Entry.Find("Top", T) && Entry.Find("Right", R) && Entry.Find("Bottom", B))
		m_Rect = QRect(QPoint((int)L.To<qint32>(), (int)T.To<qint32>()),
					   QPoint((int)R.To<qint32>() - 1, (int)B.To<qint32>() - 1));

	//
	// Not asked for and not guessed at. Whether a window is answering is a thing
	// only the machine it lives on can find out, by sending it something and
	// waiting; the helper does not, so this stays false rather than becoming a
	// claim that it is healthy.
	//
	m_WindowHung = false;

	return true;
}

CWndInfo::SWndInfo CWineWnd::GetWndInfo() const
{
	QReadLocker Locker(&m_Mutex);

	SWndInfo Info;
	Info.Text = m_WindowTitle;
	Info.ClassName = m_WindowClass;
	Info.ThreadId = m_ThreadId;
	Info.ThreadProcessId = m_ProcessId;
	Info.Rect = m_Rect;
	Info.NormalRect = m_Rect;

	//
	// The style words go over as numbers and are spelled out by the viewer,
	// which is where words are chosen. Sent as hexadecimal here only because the
	// detail sheet takes strings and there is nothing yet that reads a style
	// mask on this side; it is the value, not a reading of it.
	//
	Info.Styles = QString("0x%1").arg(m_Style, 8, 16, QChar('0'));
	Info.StylesEx = QString("0x%1").arg(m_StyleEx, 8, 16, QChar('0'));

	return Info;
}

//
// One action, sent to the prefix the window lives in.
//
// Blocking, like everything else that goes through the helper: this is called
// from a menu, the person is waiting for it, and a window action that returned
// before anything had happened would be reported as a success it had not yet
// earned. The timeout is short - none of these do any work, they post a message
// or set a flag - so a helper that has stopped answering is found out quickly
// rather than holding the collector's thread.
//
STATUS CWineWnd::DoAction(EAction Action, ETaskMsgCode FailCode)
{
	QReadLocker Locker(&m_Mutex);
	const QString Prefix = m_Prefix;
	const int Bits = m_Bits;
	const quint32 Uid = m_Uid;
	const quint64 hWnd = m_hWnd;
	Locker.unlock();

	if (Prefix.isEmpty() || !hWnd)
		return ERR(TE_NotSupported);

	if (!CWineHelpers::IsAvailable(Bits))
		return ERR(TE_NotSupported);

	CVariant Query;
	Query.BeginMap();
	Query.Write("Cmd", "WindowAction");
	Query.Write("Wnd", (uint64)hWnd);
	Query.Write("Action", (uint32)Action);
	Query.Finish();

	CVariant Reply;
	if (!CWineHelpers::Instance()->Get(Prefix, Bits, Uid)->Request(Query, Reply, 5000))
		return ERR(FailCode);

	CVariant Value;
	if (!Reply.Find("Ok", Value) || !Value.To<bool>())
		return ERR(FailCode);

	return OK;
}
