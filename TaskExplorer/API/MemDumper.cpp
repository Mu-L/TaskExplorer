#include "stdafx.h"
#include "MemDumper.h"
#ifdef WIN32
#include "Windows/WinDumper.h"
//
// GetPresetFlags composes MINIDUMP_TYPE values, which come from dbghelp.h on
// Windows and from the mirrored enum in the header elsewhere. Same include
// order as WinDumper.cpp uses.
//
#include "Windows/ProcessHacker.h"
#include <dbghelp.h>
#else
#include "Linux/LinuxDumper.h"
#endif // WIN32

CMemDumper::CMemDumper(QObject* parent)
	: QThread(parent)
{
}

CMemDumper::~CMemDumper()
{
	if(!wait(10*1000))
		terminate();
}

CMemDumper* CMemDumper::New()
{
#ifdef WIN32
	return new CWinDumper();
#else
	return new CLinuxDumper();
#endif // WIN32
}

quint32 CMemDumper::GetPresetFlags(EDumpPreset Preset)
{
	switch (Preset)
	{
	case eDumpMinimal:
		return MiniDumpWithDataSegs
			 | MiniDumpWithUnloadedModules
			 | MiniDumpWithThreadInfo
			 | MiniDumpIgnoreInaccessibleMemory;

	case eDumpLimited:
		return MiniDumpWithFullMemory
			 | MiniDumpWithUnloadedModules
			 | MiniDumpWithFullMemoryInfo
			 | MiniDumpWithThreadInfo
			 | MiniDumpIgnoreInaccessibleMemory;

	case eDumpNormal:
		return MiniDumpWithFullMemory
			 | MiniDumpWithHandleData
			 | MiniDumpWithUnloadedModules
			 | MiniDumpWithFullMemoryInfo
			 | MiniDumpWithThreadInfo
			 | MiniDumpIgnoreInaccessibleMemory
			 | MiniDumpWithIptTrace;

	case eDumpFull:
		return MiniDumpWithDataSegs
			 | MiniDumpWithFullMemory
			 | MiniDumpWithHandleData
			 | MiniDumpWithUnloadedModules
			 | MiniDumpWithIndirectlyReferencedMemory
			 | MiniDumpWithProcessThreadData
			 | MiniDumpWithPrivateReadWriteMemory
			 | MiniDumpWithFullMemoryInfo
			 | MiniDumpWithCodeSegs
			 | MiniDumpWithFullAuxiliaryState
			 | MiniDumpWithPrivateWriteCopyMemory
			 | MiniDumpIgnoreInaccessibleMemory
			 | MiniDumpWithTokenInformation
			 | MiniDumpWithModuleHeaders
			 | MiniDumpWithAvxXStateContext
			 | MiniDumpWithIptTrace;
	}
	return MiniDumpNormal;
}
