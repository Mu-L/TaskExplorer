#pragma once
#include "../taskcore_global.h"
#include <QString>

//
// A process that is running under Wine.
//
// Such a process is two things at once: a real Linux process with a pid, a
// memory map and file descriptors, and a Windows one with an image path, a
// command line and - inside wineserver - a whole world of handles, windows and
// tokens that /proc knows nothing about. This structure carries the half that
// can be established from Linux alone.
//
// Valid is the whole test. A collector with no notion of Wine leaves it false,
// which is what CProcessInfo's default does, and a view that shows any of this
// checks it first. See NEXT.md 5.16 for what is here and what needs a helper
// running inside the prefix.
//
struct SWineInfo
{
	bool	Valid = false;

	//
	// The image as Windows sees it - "Z:\\mnt\\c\\Bin\\putty.exe".
	//
	// This is not cosmetic. /proc/<pid>/exe names the loader for every process
	// in the prefix, so without this every Wine process looks like
	// wine-preloader and the one thing that tells them apart is missing.
	//
	QString	ImagePath;

	//
	// And the same file in the terms this machine uses, which is what anything
	// that wants to open it needs. Empty when the mapping could not be found.
	//
	QString	UnixImagePath;

	// The prefix this process belongs to, as a Unix directory. Processes in
	// different prefixes share nothing - separate wineserver, separate registry,
	// separate drive letters - so this is what the bridge keys on.
	QString	Prefix;

	//
	// What Windows calls this process, which has nothing to do with its Linux
	// pid - measured, 296 against 15336 for the same program. Zero until the
	// bridge has run and paired them, and zero is not "process 0": check it
	// before showing it.
	//
	quint32	WinPid = 0;
	quint32	WinParentPid = 0;
};
