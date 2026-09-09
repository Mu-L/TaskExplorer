#include "stdafx.h"
#include "LinuxAPI.h"
#include "ProcFs.h"
#include "../../../MiscHelpers/Common/Settings.h"

#include <QProcess>
#include <QFileInfo>
#include <QDir>

#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

//
// ---- starting a program on this machine ----
//
// None of this existed here: CLinuxAPI overrode nothing in the run family, so
// the base class answered TE_NotSupported and the dialog offered empty combo
// boxes above a button that could not work. The empty boxes were the visible
// half of a feature that was simply not written.
//
// Everything below is deliberately plain. There is no CreateProcessAsUser here
// and no equivalent: changing user means changing the identity of the calling
// process, which can only be done between fork and exec, and only by root. So
// the shape is fork, become somebody, exec - and where that cannot be done, say
// so rather than approximate it.
//

//
// Where the run history is kept.
//
// In the settings rather than in the platform, which is the opposite of
// Windows: there the MRU list belongs to the shell and is shared with the Run
// dialog everyone else uses. Linux has no such list to join - a desktop's
// launcher history is its own - so inventing one here and keeping it to
// ourselves is the honest option.
//
#define RUN_HISTORY_KEY		"Options/RunHistoryLinux"
#define RUN_HISTORY_MAX		16

QStringList CLinuxAPI::GetRunHistory() const
{
	return theConf ? theConf->GetStringList(RUN_HISTORY_KEY) : QStringList();
}

void CLinuxAPI::AddRunHistory(const QString& Program)
{
	if (!theConf || Program.isEmpty())
		return;

	QStringList History = theConf->GetStringList(RUN_HISTORY_KEY);

	//
	// Most recent first, and only once. Removing before prepending is what
	// makes re-running the same thing move it up rather than accumulate.
	//
	History.removeAll(Program);
	History.prepend(Program);
	while (History.count() > RUN_HISTORY_MAX)
		History.removeLast();

	theConf->SetValue(RUN_HISTORY_KEY, History);
}

//
// The accounts worth offering.
//
// Real people and root, not the sixty system accounts a distribution installs.
// The line is the one every login screen draws: uid 0, or uid at or above the
// distribution's first ordinary user, and not the nobody account at the top of
// the range.
//
// UID_MIN is read from /etc/login.defs where it is set, because it is not
// always 1000 - some distributions start at 500 - and guessing it wrong either
// hides a real account or offers a daemon.
//
static quint32 FirstOrdinaryUid()
{
	QFile File("/etc/login.defs");
	if (File.open(QIODevice::ReadOnly | QIODevice::Text))
	{
		while (!File.atEnd())
		{
			const QString Line = QString::fromLatin1(File.readLine()).trimmed();
			if (!Line.startsWith("UID_MIN"))
				continue;
			const QStringList Parts = Line.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
			if (Parts.count() > 1)
			{
				bool bOk = false;
				const quint32 Value = Parts[1].toUInt(&bOk);
				if (bOk)
					return Value;
			}
		}
	}
	return 1000;
}

//
// Whether an account is one nobody logs in as.
//
// The shell is what says so, and it is what every distribution uses to say it:
// a daemon gets /usr/sbin/nologin or /bin/false so that a stolen password buys
// nothing. The dialog greys the password box for these, which is the same thing
// the Windows side does for a service account.
//
bool CLinuxAPI::IsServiceAccount(const QString& UserName) const
{
	const QByteArray Name = UserName.toLocal8Bit();
	struct passwd* pEntry = getpwnam(Name.constData());
	if (!pEntry || !pEntry->pw_shell)
		return false;

	const QString Shell = QString::fromLocal8Bit(pEntry->pw_shell);
	return Shell.endsWith("/nologin") || Shell.endsWith("/false") || Shell.isEmpty();
}

CSystemAPI::SRunAsChoices CLinuxAPI::GetRunAsChoices() const
{
	SRunAsChoices Choices;

	//
	// No logon types. Windows has five ways to sign in and they change what the
	// resulting token may do; here there is one way, and offering a box with
	// nothing in it - which is what this did - says the opposite of "not
	// applicable". The dialog hides a choice it has none of.
	//
	// No sessions either, and for a sharper reason: SRunAsOptions carries a
	// numeric session id, logind names its sessions with strings, and exec pays
	// no attention to either. A picker that cannot be honoured is worse than no
	// picker.
	//

	const quint32 FirstUid = FirstOrdinaryUid();

	setpwent();
	while (struct passwd* pEntry = getpwent())
	{
		if (!pEntry->pw_name)
			continue;
		if (pEntry->pw_uid != 0 && (pEntry->pw_uid < FirstUid || pEntry->pw_uid >= 65534))
			continue;
		Choices.Accounts.append(QString::fromLocal8Bit(pEntry->pw_name));
	}
	endpwent();
	Choices.Accounts.sort();

	//
	// The displays a program could be put on.
	//
	// Taken from the processes that are on one, because that is where the
	// answer actually is: a display exists because something is serving it, and
	// the sockets under /tmp/.X11-unix only ever describe the X11 half. See
	// CLinuxProcess::GetUsedDesktop, which reads the same two variables.
	//
	{
		//
		// const_cast because GetProcessList is not const on the base and every
		// backend overrides it; nothing here changes anything.
		//
		QSet<QString> Seen;
		foreach(const CProcessPtr& pProcess, const_cast<CLinuxAPI*>(this)->GetProcessList())
		{
			const QString Display = pProcess->GetUsedDesktop();
			if (!Display.isEmpty())
				Seen.insert(Display);
		}
		Choices.Desktops = Seen.values();
		Choices.Desktops.sort();
	}

	//
	// Ours, so the dialog can start on it - which is nearly always what is
	// wanted, and is the only one a program started from here can be sure of.
	//
	Choices.CurrentDesktop = qEnvironmentVariable("WAYLAND_DISPLAY");
	if (Choices.CurrentDesktop.isEmpty())
		Choices.CurrentDesktop = qEnvironmentVariable("DISPLAY");

	return Choices;
}

//
// Splits a command line the way a shell would, so that arguments survive.
//
// QProcess::splitCommand does exactly this and honours quotes, which matters:
// the dialog takes one string and people put paths with spaces in it.
//
static QStringList SplitCommand(const QString& Program, QString* pExecutable)
{
	QStringList Parts = QProcess::splitCommand(Program);
	if (Parts.isEmpty())
		return QStringList();

	*pExecutable = Parts.takeFirst();
	return Parts;
}

//
// How a child says why it never became the program.
//
// Two ints down a pipe, written with write(2) because everything after a fork
// in a threaded process must be async-signal-safe - no QString, no ERR(), no
// allocation of any kind. The parent turns them back into a sentence.
//
enum EChildStage
{
	eStageGroups = 1,
	eStageGid,
	eStageUid,
	eStageExec,
	eStageFork,
};

static void ChildFailed(int Fd, int Stage, int Error)
{
	int Record[2] = { Stage, Error };
	const ssize_t Written = write(Fd, Record, sizeof(Record));
	(void)Written;	// nothing useful to do about a failed write here
	_exit(127);
}

//
// Starts a program, optionally suspended, optionally with a library preloaded.
//
// fork and exec by hand rather than QProcess, because two of the options cannot
// be expressed through it: stopping the child before it runs, and becoming
// somebody else first. Both live in the window between fork and exec, which is
// the one place QProcess does not let a caller into.
//
static STATUS ForkAndExec(const QString& Program, const QString& InjectLib,
                          const QString& Display, bool bSuspended,
                          const struct passwd* pAs)
{
	QString Executable;
	const QStringList Arguments = SplitCommand(Program, &Executable);
	if (Executable.isEmpty())
		return ERR(TE_Message, QVariantList() << CLinuxAPI::tr("No program was given."));

	//
	// Built before the fork. Everything after it must be async-signal-safe and
	// allocating a QString is not - the child of a forked multi-threaded process
	// may hold a lock no thread is left to release.
	//
	QList<QByteArray> ArgStore;
	ArgStore.append(Executable.toLocal8Bit());
	foreach(const QString& Arg, Arguments)
		ArgStore.append(Arg.toLocal8Bit());

	QVector<char*> Argv;
	for (int i = 0; i < ArgStore.count(); i++)
		Argv.append(ArgStore[i].data());
	Argv.append(NULL);

	const QByteArray PreloadVar = InjectLib.isEmpty() ? QByteArray()
		: ("LD_PRELOAD=" + InjectLib.toLocal8Bit());
	const QByteArray DisplayVar = Display.isEmpty() ? QByteArray()
		: ((Display.startsWith("wayland") ? QByteArray("WAYLAND_DISPLAY=") : QByteArray("DISPLAY="))
			+ Display.toLocal8Bit());

	const QByteArray Home = pAs && pAs->pw_dir ? QByteArray(pAs->pw_dir) : QByteArray();
	const QByteArray User = pAs && pAs->pw_name ? QByteArray(pAs->pw_name) : QByteArray();

	//
	// Two forks and a pipe.
	//
	// The pipe is the answer to "did it start". It is close-on-exec, so a
	// successful exec closes it and the parent reads end-of-file - that, and
	// only that, means the program is running. Without it there was nothing to
	// report but the result of fork, which succeeds even when the path is
	// misspelled, so every failure looked like a success.
	//
	// The second fork is so that nothing is left to reap. A launched program is
	// not the viewer's child in any meaningful sense, and a long lived daemon
	// that never waits would collect a zombie for every program anybody ever
	// started through it. The middle process exits immediately and is waited
	// for right here; the program itself is orphaned and becomes init's to
	// collect.
	//
	int Pipe[2] = { -1, -1 };
	if (pipe(Pipe) != 0)
		return ERR(TE_Message, QVariantList() << QString("pipe failed: %1").arg(QString::fromLocal8Bit(strerror(errno))));
	fcntl(Pipe[0], F_SETFD, FD_CLOEXEC);
	fcntl(Pipe[1], F_SETFD, FD_CLOEXEC);

	const pid_t Middle = fork();
	if (Middle < 0)
	{
		const int Error = errno;
		close(Pipe[0]);
		close(Pipe[1]);
		return ERR(TE_Message, QVariantList() << QString("fork failed: %1").arg(QString::fromLocal8Bit(strerror(Error))));
	}

	if (Middle == 0)
	{
		close(Pipe[0]);

		const pid_t Child = fork();
		if (Child < 0)
			ChildFailed(Pipe[1], eStageFork, errno);

		if (Child == 0)
		{
			//
			// The program to be. Nothing here may allocate or take a lock.
			//
			// Its own session, so that a Ctrl-C in whatever terminal started
			// this viewer does not travel to a program somebody launched from
			// it, and so that the program leads the session it appears in
			// rather than pointing at a middle process that is already gone.
			//
			setsid();

			if (pAs)
			{
				//
				// Groups before the uid, and the uid last: dropping to the
				// target user first would take away the privilege needed to
				// do the rest.
				//
				if (initgroups(User.constData(), pAs->pw_gid) != 0) ChildFailed(Pipe[1], eStageGroups, errno);
				if (setgid(pAs->pw_gid) != 0) ChildFailed(Pipe[1], eStageGid, errno);
				if (setuid(pAs->pw_uid) != 0) ChildFailed(Pipe[1], eStageUid, errno);

				if (!Home.isEmpty())
				{
					setenv("HOME", Home.constData(), 1);
					setenv("USER", User.constData(), 1);
					setenv("LOGNAME", User.constData(), 1);
					if (chdir(Home.constData()) != 0)
						{ /* not fatal: an unreadable home is not a reason to refuse */ }
				}
			}

			if (!PreloadVar.isEmpty())
				putenv(const_cast<char*>(PreloadVar.constData()));
			if (!DisplayVar.isEmpty())
				putenv(const_cast<char*>(DisplayVar.constData()));

			//
			// Suspended means stopped holding the program, not stopped instead
			// of it. Asking to be traced makes the kernel stop this process at
			// the end of a successful exec - by which time the image is the one
			// that was asked for, so the task list names the program rather
			// than showing a second copy of the daemon that forked it.
			//
			// Stopping here by hand is the fallback, and it is the lesser
			// answer for exactly that reason: it stops the right process
			// wearing the wrong name.
			//
			if (bSuspended && ptrace(PTRACE_TRACEME, 0, 0, 0) != 0)
				raise(SIGSTOP);

			execvp(Argv[0], Argv.data());
			ChildFailed(Pipe[1], eStageExec, errno);
		}

		//
		// Closed before the wait, so that the parent hears about the exec as
		// soon as it happens rather than after the handover below.
		//
		close(Pipe[1]);

		if (bSuspended)
		{
			//
			// Detaching while delivering a stop leaves the program stopped and
			// untraced - nobody's tracee, so anything can attach to it later,
			// and a plain SIGCONT is all it takes to let it run.
			//
			int Status = 0;
			if (waitpid(Child, &Status, WUNTRACED) == Child && WIFSTOPPED(Status))
				ptrace(PTRACE_DETACH, Child, 0, SIGSTOP);
		}
		_exit(0);
	}

	close(Pipe[1]);

	int Record[2] = { 0, 0 };
	size_t Got = 0;
	while (Got < sizeof(Record))
	{
		const ssize_t Read = read(Pipe[0], (char*)Record + Got, sizeof(Record) - Got);
		if (Read > 0)
			Got += (size_t)Read;
		else if (Read == 0 || errno != EINTR)
			break;
	}
	close(Pipe[0]);

	//
	// The middle process is gone by now or about to be, and it is the one thing
	// here that does have to be waited for.
	//
	while (waitpid(Middle, NULL, 0) < 0 && errno == EINTR)
		;

	if (Got == sizeof(Record))
	{
		const QString Reason = QString::fromLocal8Bit(strerror(Record[1]));
		switch (Record[0])
		{
		case eStageGroups:
		case eStageGid:
		case eStageUid:
			return ERR(TE_Message, QVariantList() << CLinuxAPI::tr("Unable to run as %1: %2")
				.arg(QString::fromLocal8Bit(User)).arg(Reason));
		case eStageExec:
			return ERR(TE_Message, QVariantList() << CLinuxAPI::tr("Unable to start %1: %2")
				.arg(Executable).arg(Reason));
		default:
			return ERR(TE_Message, QVariantList() << QString("fork failed: %1").arg(Reason));
		}
	}

	return OK;
}

STATUS CLinuxAPI::RunProgram(const SRunOptions& Options)
{
	if (Options.Program.isEmpty())
		return ERR(TE_Message, QVariantList() << tr("No program was given."));

	//
	// "Elevated" means root here, and it is only a request. Already root, there
	// is nothing to do; otherwise it is the same handover the run-as path uses,
	// because raising privilege and changing user are the same operation on
	// this platform.
	//
	if (Options.Elevated && geteuid() != 0)
	{
		SRunAsOptions AsRoot;
		AsRoot.Program = Options.Program;
		AsRoot.UserName = "root";
		AsRoot.Suspended = Options.Suspended;
		return RunProgramAs(AsRoot);
	}

	const STATUS Status = ForkAndExec(Options.Program, Options.InjectDll,
		QString(), Options.Suspended, NULL);
	if (!Status.IsError())
		AddRunHistory(Options.Program);
	return Status;
}

STATUS CLinuxAPI::RunProgramAs(const SRunAsOptions& Options)
{
	if (Options.Program.isEmpty())
		return ERR(TE_Message, QVariantList() << tr("No program was given."));

	const QByteArray Name = Options.UserName.toLocal8Bit();
	struct passwd* pEntry = Name.isEmpty() ? NULL : getpwnam(Name.constData());
	if (!pEntry)
		return ERR(TE_Message, QVariantList()
			<< tr("There is no account called \"%1\" on this machine.").arg(Options.UserName));

	//
	// Root can become anybody, and does it itself - see ForkAndExec.
	//
	if (geteuid() == 0)
	{
		const STATUS Status = ForkAndExec(Options.Program, QString(),
			Options.Desktop, Options.Suspended, pEntry);
		if (!Status.IsError())
			AddRunHistory(Options.Program);
		return Status;
	}

	//
	// And anybody else asks the desktop to arrange it.
	//
	// pkexec rather than su or sudo: those two want a terminal to read a
	// password from and there is none here, while pkexec raises the
	// authentication agent the session already has. What it cannot do is start
	// something the policy will not allow, and that refusal is the desktop's to
	// make and to explain.
	//
	// The password box in the dialog is not used on this path and must not be:
	// handing a password to a helper on a command line would publish it to every
	// process list on the machine.
	//
	QString Executable;
	const QStringList Arguments = SplitCommand(Options.Program, &Executable);
	if (Executable.isEmpty())
		return ERR(TE_Message, QVariantList() << tr("No program was given."));

	QStringList PkArgs;
	PkArgs << "--user" << Options.UserName;
	if (!Options.Desktop.isEmpty())
	{
		//
		// pkexec starts with a minimal environment on purpose, so a graphical
		// program needs to be told where to draw.
		//
		PkArgs << "env";
		PkArgs << ((Options.Desktop.startsWith("wayland") ? "WAYLAND_DISPLAY=" : "DISPLAY=")
			+ Options.Desktop);
	}
	PkArgs << Executable << Arguments;

	if (!QProcess::startDetached("pkexec", PkArgs))
	{
		return ERR(TE_Message, QVariantList() << tr(
			"Starting a program as another user needs root, or pkexec, and neither "
			"is available. Start TaskExplorer as root, or install polkit."));
	}

	AddRunHistory(Options.Program);
	return OK;
}
