#pragma once
#include "../taskcore_global.h"
#include "ProcessInfo.h"

#ifndef WIN32
//
// The dump-type flags the GUI passes to PrepareDump() are MINIDUMP_TYPE values
// from dbghelp.h. Mirroring the values here keeps the dump-type menu in
// ProcessTree.cpp platform independent: the flags describe *what* to capture,
// which is a meaningful request regardless of the container format.
//
// CLinuxDumper writes an ELF core rather than a minidump and interprets the
// subset that maps onto that (full memory vs. private read/write only, whether
// to skip inaccessible regions); the rest are ignored.
//
enum MINIDUMP_TYPE
{
	MiniDumpNormal                         = 0x00000000,
	MiniDumpWithDataSegs                   = 0x00000001,
	MiniDumpWithFullMemory                 = 0x00000002,
	MiniDumpWithHandleData                 = 0x00000004,
	MiniDumpFilterMemory                   = 0x00000008,
	MiniDumpScanMemory                     = 0x00000010,
	MiniDumpWithUnloadedModules            = 0x00000020,
	MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
	MiniDumpFilterModulePaths              = 0x00000080,
	MiniDumpWithProcessThreadData          = 0x00000100,
	MiniDumpWithPrivateReadWriteMemory     = 0x00000200,
	MiniDumpWithoutOptionalData            = 0x00000400,
	MiniDumpWithFullMemoryInfo             = 0x00000800,
	MiniDumpWithThreadInfo                 = 0x00001000,
	MiniDumpWithCodeSegs                   = 0x00002000,
	MiniDumpWithoutAuxiliaryState          = 0x00004000,
	MiniDumpWithFullAuxiliaryState         = 0x00008000,
	MiniDumpWithPrivateWriteCopyMemory     = 0x00010000,
	MiniDumpIgnoreInaccessibleMemory       = 0x00020000,
	MiniDumpWithTokenInformation           = 0x00040000,
	MiniDumpWithModuleHeaders              = 0x00080000,
	MiniDumpFilterTriage                   = 0x00100000,
	MiniDumpWithAvxXStateContext           = 0x00200000,
	MiniDumpWithIptTrace                   = 0x00400000,
	MiniDumpScanInaccessiblePartialPages   = 0x00800000,
};
#endif // !WIN32

class TASKCORE_EXPORT CMemDumper : public QThread
{
	Q_OBJECT

	TRACK_OBJECT(CMemDumper)
public:
	CMemDumper(QObject* parent = NULL);
	~CMemDumper();

	static CMemDumper* New();

	//
	// What a dump should contain, named rather than spelled out as flags.
	//
	// The menu asks for "Minimal" or "Full"; composing the MINIDUMP_TYPE bits
	// for that is the dumper's business, not the view's - and on Windows those
	// constants come from an SDK header the GUI should not need to include.
	//
	enum EDumpPreset
	{
		eDumpMinimal,
		eDumpLimited,
		eDumpNormal,
		eDumpFull,
	};
	static quint32	GetPresetFlags(EDumpPreset Preset);

	virtual STATUS	PrepareDump(const CProcessPtr& pProcess, quint32 DumpType, const QString& DumpPath) = 0;

public slots:
	virtual void	Cancel() = 0;

signals:
	//
	// What the dump is doing, and how it ended. Both carry a code and its
	// arguments rather than a sentence, so a viewer watching a dump on another
	// machine reads it in its own language.
	//
	void			ProgressMessage(const CStatus& Message, int Progress = -1);
	void			StatusMessage(const CStatus& Message);

protected:
	virtual void	run() {}
};