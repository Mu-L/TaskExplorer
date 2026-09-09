#pragma once
#include <QList>
#include <QMap>
#include <QObject>
#include <QString>

class QProcess;
class CVariant;

//
// One process as Windows sees it, from inside a Wine prefix.
//
// The pid here is Wine's, which has nothing to do with the Linux one - see
// NEXT.md 5.16 for the measurement. ImagePath is what both sides can be matched
// on, because the Linux side reads the same string out of /proc/<pid>/cmdline.
//
struct SWineProcess
{
	quint32	Pid = 0;
	quint32	ParentPid = 0;
	QString	ImagePath;	// "C:\\windows\\system32\\services.exe"
	QString	Name;		// "services.exe"
};

//
// A resident helper inside one Wine prefix.
//
// It is the Windows build of this project's own helper, running under Wine and
// speaking the same length-prefixed CVariant packets it speaks over a pipe on
// Windows - here over its standard streams, because a Wine named pipe is a
// wineserver object with no name outside the prefix and a Linux process has
// nothing to connect to.
//
class CWineHelper : public QObject
{
	Q_OBJECT
public:
	CWineHelper(const QString& Prefix, int Bits, quint32 Uid, QObject* parent = NULL);
	virtual ~CWineHelper();

	QString				GetPrefix() const	{ return m_Prefix; }
	int					GetBits() const		{ return m_Bits; }

	bool				IsRunning() const;
	void				Stop();

	//
	// One request, one reply. Starts the helper if it is not up yet.
	//
	// Blocking: this is called from the collector's thread, which is the same
	// thread that would otherwise be reading /proc, and the caller has already
	// decided the answer is worth waiting for.
	//
	bool				Request(const CVariant& Query, CVariant& Reply, int TimeoutMs = 15000);

	QList<SWineProcess>	ListProcesses(int TimeoutMs = 30000);

	//
	// The token of one Windows process, as Wine reports it. The pid is Wine's,
	// not the Linux one - see SWineProcess.
	//
	bool				GetToken(quint32 WinPid, class CWineToken* pToken, int TimeoutMs = 15000);

	//
	// The wineserver objects one Windows process holds, as a list of entries to
	// be handed to CWineHandle::Apply. The reply is passed through rather than
	// parsed here so that the shape of an entry is described in one place.
	//
	// The pid is Wine's. False for a helper that could not answer, which is not
	// the same as a process holding nothing.
	//
	bool				ListHandles(quint32 WinPid, CVariant& Handles, int TimeoutMs = 15000);

	//
	// The top-level windows one Windows process has, as a list of entries to be
	// handed to CWineWnd::Apply. The pid is Wine's.
	//
	bool				ListWindows(quint32 WinPid, CVariant& Windows, int TimeoutMs = 15000);

	quint64				GetLastUse() const	{ return m_LastUse; }

private:
	bool				Ensure();

	QString				m_Prefix;
	int					m_Bits;
	quint32				m_Uid;
	QProcess*			m_pProcess = NULL;
	quint64				m_LastUse = 0;
	quint64				m_LastStartFailed = 0;
};

//
// The helpers, one per prefix and bitness.
//
// A machine can have any number of prefixes - a bottle per program is a normal
// way to use Wine - and they share nothing: separate wineserver, separate
// registry, separate drive letters. A prefix can also be win32-only, where a
// 64-bit helper will not load at all, and a 64-bit prefix may still be worth
// asking from both sides for the processes of each kind. So the key is the pair.
//
// Not thread safe by design: everything here is driven from the collector's
// thread, and a second thread starting Wine processes behind its back is not a
// situation worth supporting.
//
class CWineHelpers
{
public:
	static CWineHelpers*	Instance();

	//
	// Whether there is anything to run: a helper binary of that bitness beside
	// the daemon, and a wine to run it with. Says nothing about whether the user
	// wants it run - that is a setting, and the caller checks it.
	//
	static bool			IsAvailable(int Bits = 64);

	//
	// Which bitness a prefix can host. A win32 prefix has no 64-bit side at all.
	//
	static int			PrefixBits(const QString& Prefix);

	CWineHelper*		Get(const QString& Prefix, int Bits, quint32 Uid);

	//
	// Shut down helpers nothing has asked anything of for a while, and any whose
	// prefix has gone. Called from the refresh; the helper also times itself out
	// from the inside, which covers the case of this process dying first.
	//
	void				StopIdle(quint64 MaxAgeMs = 300000);
	void				StopAll();

private:
	CWineHelpers() {}

	// Keyed "<prefix>|<bits>".
	QMap<QString, CWineHelper*>	m_Helpers;
};
