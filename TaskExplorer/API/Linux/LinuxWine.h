#pragma once
#include "../WineInfo.h"
#include <QStringList>

//
// Whether this process is running under Wine, and what it is if so.
//
// Everything here comes from /proc and from the prefix on disk; nothing runs
// Windows code and nothing talks to wineserver, so what it can answer stops
// where wineserver's own bookkeeping starts - see NEXT.md 5.16.
//
// Takes the values CLinuxProcess::InitStaticData has already read rather than
// reading them again: this is called once per process, in the middle of a pass
// that has just opened four /proc files for the same pid.
//
SWineInfo LinuxDetectWine(quint64 Pid, const QString& ExePath, const QStringList& CmdLine);
