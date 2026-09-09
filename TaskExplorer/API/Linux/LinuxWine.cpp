#include "stdafx.h"
#include "LinuxWine.h"
#include "ProcFs.h"

#include <QDir>
#include <QFileInfo>
#include <QRegularExpression>

#include <pwd.h>

//
// Recognising a Wine process, and working out what it really is, from Linux
// alone. See NEXT.md 5.16 for the measurements this is built on and for the
// line between what /proc can answer and what needs a helper inside the prefix.
//

//
// A DOS path at the front of the command line - "Z:\\mnt\\c\\Bin\\putty.exe".
//
// Wine puts the Windows command line in /proc/<pid>/cmdline verbatim, which is
// both the cheapest marker there is - cmdline is world readable, unlike exe and
// environ - and the answer itself.
//
static const QRegularExpression& DosPathExpr()
{
	static const QRegularExpression Expr("^[A-Za-z]:\\\\");
	return Expr;
}

//
// The loader, under any of the names it ships as.
//
static bool IsWineLoader(const QString& ExePath)
{
	if (ExePath.isEmpty())
		return false;

	const QString Name = QFileInfo(ExePath).fileName();
	return Name == "wine-preloader" || Name == "wine64-preloader"
		|| Name == "wine" || Name == "wine64" || Name == "wineserver";
}

//
// Which prefix the process belongs to.
//
// WINEPREFIX where the environment can be read - which for another user's
// process it cannot - and the owner's ~/.wine otherwise, that being the default
// Wine itself uses. Only returned when the directory looks like a prefix, so a
// wrong guess produces nothing rather than a path that misleads.
//
static QString FindPrefix(quint64 Pid)
{
	QString Prefix;

	foreach(const QString& Var, ProcFs::ReadNulList(ProcFs::ProcPath(Pid, "environ")))
	{
		if (Var.startsWith("WINEPREFIX="))
		{
			Prefix = Var.mid(11);
			break;
		}
	}

	if (Prefix.isEmpty())
	{
		//
		// The owner's home, from the passwd database rather than from this
		// process's own HOME - the process being looked at may be somebody
		// else's.
		//
		const QMap<QString, QString> Status = ProcFs::ReadStatus(Pid);
		const QStringList UidFields = Status.value("Uid").split('\t', Qt::SkipEmptyParts);
		if (UidFields.size() > 1)
		{
			if (struct passwd* pPw = ::getpwuid(UidFields[1].toUInt()))
				Prefix = QString::fromLocal8Bit(pPw->pw_dir) + "/.wine";
		}
	}

	if (Prefix.isEmpty() || !QDir(Prefix + "/dosdevices").exists())
		return QString();

	return Prefix;
}

//
// The mapped file that is this process's own image.
//
// Wine maps the PE itself, so the map holds a real path to it - the difficulty
// is only telling it apart from the hundred and forty other files mapped into
// the same address space. Matched on the file name the Windows command line
// gives, which is exactly the one the loader was asked for.
//
static QString FindImageInMaps(quint64 Pid, const QString& DosPath)
{
	const QString Wanted = DosPath.mid(DosPath.lastIndexOf('\\') + 1);
	if (Wanted.isEmpty())
		return QString();

	QString Best;
	for (const ProcFs::SMapEntry& Entry : ProcFs::ReadMaps(Pid))
	{
		if (Entry.Inode == 0 || Entry.Path.isEmpty())
			continue;

		if (QFileInfo(Entry.Path).fileName().compare(Wanted, Qt::CaseInsensitive) != 0)
			continue;

		//
		// An executable mapping for preference: a PE is mapped several times
		// over with different protections, and the one carrying code is the
		// least ambiguous of them. Any mapping of the right file will do if
		// none of them says executable.
		//
		if (Entry.Exec)
			return Entry.Path;
		if (Best.isEmpty())
			Best = Entry.Path;
	}
	return Best;
}

SWineInfo LinuxDetectWine(quint64 Pid, const QString& ExePath, const QStringList& CmdLine)
{
	SWineInfo Info;

	const QString Arg0 = CmdLine.isEmpty() ? QString() : CmdLine.first();
	const bool bDosPath = !Arg0.isEmpty() && DosPathExpr().match(Arg0).hasMatch();

	//
	// Either marker on its own is enough, and they cover different cases: the
	// DOS command line is there for every Windows program in the prefix, and
	// the loader name catches wineserver and the Unix-side helpers, which have
	// ordinary command lines.
	//
	if (!bDosPath && !IsWineLoader(ExePath))
		return Info;

	Info.Valid = true;
	Info.Prefix = FindPrefix(Pid);

	if (bDosPath)
	{
		Info.ImagePath = Arg0;
		Info.UnixImagePath = FindImageInMaps(Pid, Arg0);
	}
	else
	{
		//
		// wineserver and the loader itself are Unix programs; they have no
		// Windows image and saying so is better than inventing one.
		//
		Info.UnixImagePath = ExePath;
	}

	return Info;
}
