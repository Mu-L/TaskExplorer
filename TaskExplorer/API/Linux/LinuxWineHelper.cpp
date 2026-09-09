#include "stdafx.h"
#include "LinuxWineHelper.h"
#include "../../../MiscHelpers/Common/Variant.h"
#include "../../../MiscHelpers/Common/XVariant.h"
#include "../../../MiscHelpers/Common/Common.h"
#include "LinuxWineToken.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QProcess>
#include <QStandardPaths>

#include <pwd.h>
#include <grp.h>
#include <unistd.h>

//
// Asking Wine what Windows sees, by running Windows code inside the prefix.
//
// Everything the Linux side can answer about a Wine process it already answers -
// see LinuxWine.cpp. This is for the rest: what wineserver knows and /proc
// cannot. See NEXT.md 5.16.
//

//
// Where the Windows helper is, for a given bitness.
//
// Beside the daemon, because that is where a Linux install puts what it ships. A
// PE in a Linux install looks odd until you remember what it is for.
//
static QString HelperPath(int Bits)
{
	const QString Dir = QCoreApplication::applicationDirPath();

	QStringList Names;
	if (Bits == 32)
		Names << "TaskHelper32.exe";
	else
		Names << "TaskHelper64.exe" << "TaskHelper.exe";

	foreach(const QString& Name, Names)
	{
		if (QFileInfo(Dir + "/" + Name).isFile())
			return Dir + "/" + Name;
	}
	return QString();
}

bool CWineHelpers::IsAvailable(int Bits)
{
	if (HelperPath(Bits).isEmpty())
		return false;

	//
	// And a wine to run it with. Looked up once: PATH does not change under a
	// running daemon and this is asked on a refresh path.
	//
	static const bool bHaveWine = !QStandardPaths::findExecutable("wine").isEmpty();
	return bHaveWine;
}

//
// What a prefix can host.
//
// A 64-bit prefix keeps its 32-bit side in syswow64; a win32 prefix has no
// 64-bit side at all and a 64-bit helper will not load in it. Read from the
// directory layout rather than from the registry, because it is one stat against
// parsing four megabytes of system.reg.
//
int CWineHelpers::PrefixBits(const QString& Prefix)
{
	if (Prefix.isEmpty())
		return 0;
	if (QDir(Prefix + "/drive_c/windows/syswow64").exists())
		return 64;
	if (QDir(Prefix + "/drive_c/windows/system32").exists())
		return 32;
	return 0;
}

CWineHelpers* CWineHelpers::Instance()
{
	static CWineHelpers Helpers;
	return &Helpers;
}

CWineHelper* CWineHelpers::Get(const QString& Prefix, int Bits, quint32 Uid)
{
	const QString Key = Prefix + "|" + QString::number(Bits);

	CWineHelper* pHelper = m_Helpers.value(Key);
	if (!pHelper)
	{
		pHelper = new CWineHelper(Prefix, Bits, Uid);
		m_Helpers.insert(Key, pHelper);
	}
	return pHelper;
}

void CWineHelpers::StopIdle(quint64 MaxAgeMs)
{
	const quint64 Now = GetCurTick();

	for (QMap<QString, CWineHelper*>::iterator I = m_Helpers.begin(); I != m_Helpers.end(); )
	{
		CWineHelper* pHelper = I.value();

		//
		// Gone means gone: a prefix that has been deleted takes its helper with
		// it, whether or not anything has asked lately.
		//
		const bool bGone = !QDir(pHelper->GetPrefix()).exists();
		const bool bIdle = pHelper->GetLastUse() && (Now - pHelper->GetLastUse() > MaxAgeMs);

		if (bGone || bIdle)
		{
			delete pHelper;
			I = m_Helpers.erase(I);
		}
		else
			++I;
	}
}

void CWineHelpers::StopAll()
{
	qDeleteAll(m_Helpers);
	m_Helpers.clear();
}

CWineHelper::CWineHelper(const QString& Prefix, int Bits, quint32 Uid, QObject* parent)
	: QObject(parent), m_Prefix(Prefix), m_Bits(Bits), m_Uid(Uid)
{
}

CWineHelper::~CWineHelper()
{
	Stop();
}

bool CWineHelper::IsRunning() const
{
	return m_pProcess && m_pProcess->state() == QProcess::Running;
}

void CWineHelper::Stop()
{
	if (!m_pProcess)
		return;

	//
	// Closing the write end is the polite way: the helper reads end of file and
	// returns from its loop. Killed only if it does not take the hint.
	//
	if (m_pProcess->state() == QProcess::Running)
	{
		m_pProcess->closeWriteChannel();
		if (!m_pProcess->waitForFinished(3000))
		{
			m_pProcess->kill();
			m_pProcess->waitForFinished(2000);
		}
	}

	delete m_pProcess;
	m_pProcess = NULL;
}

bool CWineHelper::Ensure()
{
	if (IsRunning())
		return true;

	//
	// A helper that exited is cleared before another is started, or the old
	// QProcess would be leaked and its pipes with it.
	//
	if (m_pProcess)
	{
		delete m_pProcess;
		m_pProcess = NULL;
	}

	//
	// Not immediately again after a failure. Starting Wine costs the better part
	// of a second, and a prefix that cannot host the helper - the wrong bitness,
	// a broken install - would otherwise be retried on every refresh for ever.
	//
	const quint64 Now = GetCurTick();
	if (m_LastStartFailed && Now - m_LastStartFailed < 60000)
		return false;

	const QString Helper = HelperPath(m_Bits);
	if (Helper.isEmpty())
		return false;

	struct passwd* pPw = ::getpwuid(m_Uid);
	if (!pPw)
		return false;

	const QString Home = QString::fromLocal8Bit(pPw->pw_dir);
	const QString User = QString::fromLocal8Bit(pPw->pw_name);
	const quint32 Gid = pPw->pw_gid;

	m_pProcess = new QProcess();

	QProcessEnvironment Env = QProcessEnvironment::systemEnvironment();
	Env.insert("WINEPREFIX", m_Prefix);
	Env.insert("HOME", Home);
	//
	// Wine's own diagnostics go to stderr and would be noise; more to the point
	// a chatty channel is a slow one, and this one is on a refresh path.
	//
	Env.insert("WINEDEBUG", "-all");
	m_pProcess->setProcessEnvironment(Env);

	//
	// As the owner of the prefix, never as ourselves.
	//
	// The daemon usually runs as root, and root running wine against somebody
	// else's prefix leaves root-owned files in it - a registry the owner can no
	// longer write, locks they cannot remove. The prefix would be broken for its
	// owner by the act of looking at it.
	//
	// Group before user: dropping the user first takes away the privilege needed
	// to drop the group.
	//
	if (::geteuid() == 0)
	{
		const QByteArray UserName = User.toLocal8Bit();
		const QByteArray HomeDir = Home.toLocal8Bit();
		const quint32 Uid = m_Uid;

		m_pProcess->setChildProcessModifier([Uid, Gid, UserName, HomeDir]() {
			if (::setgid(Gid) != 0) ::_exit(127);
			::initgroups(UserName.constData(), Gid);
			if (::setuid(Uid) != 0) ::_exit(127);
			if (::chdir(HomeDir.constData()) != 0) { /* not fatal */ }
		});
	}

	//
	// The helper's own idle timeout, which is a backstop rather than the policy:
	// CWineHelpers::StopIdle is what normally ends one. This covers the case
	// where the daemon dies without closing anything, leaving a Wine process in
	// somebody's prefix with nobody to answer.
	//
	m_pProcess->start("wine", QStringList() << Helper << "-wine-serve" << "300000");

	if (!m_pProcess->waitForStarted(10000))
	{
		m_LastStartFailed = Now;
		delete m_pProcess;
		m_pProcess = NULL;
		return false;
	}

	m_LastStartFailed = 0;
	return true;
}

//
// Query, not Request: a parameter named after the method it is in hides the
// method, and the compiler only says so at the call site. This class was written
// with that mistake in it once already - see CRemoteSystem::RequestAction, which
// had the same one.
//
bool CWineHelper::Request(const CVariant& Query, CVariant& Reply, int TimeoutMs)
{
	if (!Ensure())
		return false;

	m_LastUse = GetCurTick();

	//
	// Anything left over from a previous exchange would be read as this one's
	// reply. There should never be any - the protocol is one packet each way -
	// but a helper that misbehaved once should not corrupt every answer after.
	//
	m_pProcess->readAllStandardOutput();

	CBuffer Packet;
	Query.ToPacket(&Packet);

	const quint32 Length = (quint32)Packet.GetSize();
	m_pProcess->write((const char*)&Length, sizeof(Length));
	m_pProcess->write((const char*)Packet.GetBuffer(), Packet.GetSize());

	if (!m_pProcess->waitForBytesWritten(5000))
	{
		Stop();
		return false;
	}

	//
	// Read the length, then exactly that much. waitForReadyRead returns as soon
	// as anything arrives, which for a packet of any size is usually less than
	// all of it.
	//
	QByteArray Header;
	while (Header.size() < (int)sizeof(quint32))
	{
		if (!m_pProcess->waitForReadyRead(TimeoutMs))
		{
			//
			// A helper that stopped answering is not left running: the next
			// request would find its stale output waiting.
			//
			Stop();
			return false;
		}
		Header += m_pProcess->readAllStandardOutput();
	}

	quint32 ReplyLength = 0;
	memcpy(&ReplyLength, Header.constData(), sizeof(ReplyLength));
	if (ReplyLength == 0 || ReplyLength > 0x02000000)
	{
		Stop();
		return false;
	}

	QByteArray Body = Header.mid(sizeof(quint32));
	while ((quint32)Body.size() < ReplyLength)
	{
		if (!m_pProcess->waitForReadyRead(TimeoutMs))
		{
			Stop();
			return false;
		}
		Body += m_pProcess->readAllStandardOutput();
	}

	try {
		CBuffer ReplyBuffer((void*)Body.constData(), ReplyLength, true);
		Reply.FromPacket(&ReplyBuffer);
	} catch (...) {
		//
		// Not a packet. The helper is older than this daemon, or Wine mangled
		// the stream; either way nothing here is worth keeping.
		//
		Stop();
		return false;
	}

	return true;
}

QList<SWineProcess> CWineHelper::ListProcesses(int TimeoutMs)
{
	QList<SWineProcess> Result;

	CVariant Query;
	Query.BeginMap();
	Query.Write("Cmd", "ProcessList");
	Query.Finish();

	CVariant Reply;
	if (!Request(Query, Reply, TimeoutMs))
		return Result;

	CVariant Processes;
	if (!Reply.Find("Processes", Processes))
		return Result;

	try {
		Processes.ReadRawList([&](const CVariant& Entry) {
			SWineProcess Process;
			CVariant Value;
			if (Entry.Find("Pid", Value))		Process.Pid = Value.To<quint32>();
			if (Entry.Find("ParentPid", Value))	Process.ParentPid = Value.To<quint32>();
			if (Entry.Find("Image", Value))		Process.ImagePath = XVariant(Value).AsQStr();
			if (Entry.Find("Name", Value))		Process.Name = XVariant(Value).AsQStr();

			if (Process.Pid)
				Result.append(Process);
		});
	} catch (...) {
		Result.clear();
	}

	return Result;
}

bool CWineHelper::ListHandles(quint32 WinPid, CVariant& Handles, int TimeoutMs)
{
	if (!WinPid)
		return false;

	CVariant Query;
	Query.BeginMap();
	Query.Write("Cmd", "Handles");
	Query.Write("Pid", (uint32)WinPid);
	Query.Finish();

	CVariant Reply;
	if (!Request(Query, Reply, TimeoutMs))
		return false;

	//
	// An empty list has more than one cause, and the helper says which - the
	// process could not be opened, the table could not be read, or the process
	// genuinely holds nothing. Only the last is ordinary, so the other two are
	// worth a line rather than a silently short list.
	//
	CVariant Value;
	if (Reply.Find("OpenError", Value))
		qWarning("CWineHelper: cannot open Wine process %u for its handles (error %u)", WinPid, Value.To<quint32>());
	else if (Reply.Find("QueryStatus", Value))
		qWarning("CWineHelper: the prefix will not report its handle table (status 0x%08x)", Value.To<quint32>());

	return Reply.Find("Handles", Handles);
}

bool CWineHelper::ListWindows(quint32 WinPid, CVariant& Windows, int TimeoutMs)
{
	if (!WinPid)
		return false;

	CVariant Query;
	Query.BeginMap();
	Query.Write("Cmd", "Windows");
	Query.Write("Pid", (uint32)WinPid);
	Query.Finish();

	CVariant Reply;
	if (!Request(Query, Reply, TimeoutMs))
		return false;

	return Reply.Find("Windows", Windows);
}

bool CWineHelper::GetToken(quint32 WinPid, CWineToken* pToken, int TimeoutMs)
{
	if (!WinPid || !pToken)
		return false;

	CVariant Query;
	Query.BeginMap();
	Query.Write("Cmd", "Token");
	Query.Write("Pid", (uint32)WinPid);
	Query.Finish();

	CVariant Reply;
	if (!Request(Query, Reply, TimeoutMs))
		return false;

	CVariant Token;
	if (!Reply.Find("Token", Token))
		return false;

	try {
		return pToken->Apply(Token);
	} catch (...) {
		return false;
	}
}
