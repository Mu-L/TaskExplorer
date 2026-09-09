/*
 * System Informer -
 *   qt port of perfpage.c
 *
 * Copyright (C) 2015-2018 dmex
 * Copyright (C) 2019-2022 David Xanatos
 *
 * This file is part of Task Explorer and contains System Informer code.
 * 
 */

#include "stdafx.h"
#include "../Processhacker.h"
#include "DotNet.h"
#include "clr\perfcounterdefs.h"

extern "C" {

// counters

PVOID GetPerfIpcBlock_V2(
    _In_ BOOLEAN Wow64,
    _In_ PVOID BlockTableAddress
    );

PVOID GetPerfIpcBlock_V4(
    _In_ BOOLEAN Wow64,
    _In_ PVOID BlockTableAddress
    );

_Success_(return)
BOOLEAN OpenDotNetPublicControlBlock_V2(
    _In_ HANDLE ProcessId,
    _Out_ PVOID* BlockTableAddress
    );

_Success_(return)
BOOLEAN OpenDotNetPublicControlBlock_V4(
    _In_ BOOLEAN IsImmersive,
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE ProcessId,
    _Out_ PVOID* BlockTableAddress
    );

PPH_LIST QueryDotNetAppDomainsForPid_V2(
    _In_ BOOLEAN Wow64,
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE ProcessId
    );

PPH_LIST QueryDotNetAppDomainsForPid_V4(
    _In_ BOOLEAN Wow64,
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE ProcessId
    );

}


// Convenience macros
#define PhInitFormatC(f, v) do { (f)->Type = CharFormatType; (f)->u.Char = (v); } while (0)
#define PhInitFormatS(f, v) do { (f)->Type = StringFormatType; PhInitializeStringRef(&(f)->u.String, (v)); } while (0)
#define PhInitFormatSR(f, v) do { (f)->Type = StringFormatType; (f)->u.String = (v); } while (0)
#define PhInitFormatUCS(f, v) do { (f)->Type = StringFormatType; PhUnicodeStringToStringRef((v), &(f)->u.String); } while (0)
#define PhInitFormatMultiByteS(f, v) do { (f)->Type = MultiByteStringFormatType; PhInitializeBytesRef(&(f)->u.MultiByteString, (v)); } while (0)
#define PhInitFormatD(f, v) do { (f)->Type = Int32FormatType; (f)->u.Int32 = (v); } while (0)
#define PhInitFormatU(f, v) do { (f)->Type = UInt32FormatType; (f)->u.UInt32 = (v); } while (0)
#define PhInitFormatX(f, v) do { (f)->Type = (PH_FORMAT_TYPE)(UInt32FormatType | FormatUseRadix); (f)->u.UInt32 = (v); (f)->Radix = 16; } while (0)
#define PhInitFormatI64D(f, v) do { (f)->Type = Int64FormatType; (f)->u.Int64 = (v); } while (0)
#define PhInitFormatI64U(f, v) do { (f)->Type = UInt64FormatType; (f)->u.UInt64 = (v); } while (0)
#define PhInitFormatI64UGroupDigits(f, v) do { (f)->Type = (PH_FORMAT_TYPE)(UInt64FormatType | FormatGroupDigits); (f)->u.UInt64 = (v); } while (0)
#define PhInitFormatI64UWithWidth(f, v, w) do { (f)->Type = (PH_FORMAT_TYPE)(UInt64FormatType | FormatPadZeros); (f)->u.UInt64 = (v); (f)->Width = (w); } while (0)
#define PhInitFormatI64X(f, v) do { (f)->Type = (PH_FORMAT_TYPE)(UInt64FormatType | FormatUseRadix); (f)->u.UInt64 = (v); (f)->Radix = 16; } while (0)
#define PhInitFormatIU(f, v) do { (f)->Type = UIntPtrFormatType; (f)->u.UIntPtr = (v); } while (0)
#define PhInitFormatIX(f, v) do { (f)->Type = (PH_FORMAT_TYPE)(UIntPtrFormatType | FormatUseRadix); (f)->u.UIntPtr = (v); (f)->Radix = 16; } while (0)
#define PhInitFormatIXPadZeros(f, v) do { (f)->Type = UIntPtrFormatType | FormatUseRadix | FormatPadZeros; (f)->u.UIntPtr = (v); (f)->Radix = 16; (f)->Width = sizeof(ULONG_PTR) * 2; } while (0)
#define PhInitFormatF(f, v, p) do { (f)->Type = (PH_FORMAT_TYPE)(DoubleFormatType | FormatUsePrecision); (f)->u.Double = (v); (f)->Precision = (p); } while (0)
#define PhInitFormatE(f, v, p) do { (f)->Type = (PH_FORMAT_TYPE)(DoubleFormatType | FormatStandardForm | FormatUsePrecision); (f)->u.Double = (v); (f)->Precision = (p); } while (0)
#define PhInitFormatA(f, v, p) do { (f)->Type = (PH_FORMAT_TYPE)(DoubleFormatType | FormatHexadecimalForm | FormatUsePrecision); (f)->u.Double = (v); (f)->Precision = (p); } while (0)
#define PhInitFormatSize(f, v) do { (f)->Type = SizeFormatType; (f)->u.Size = (v); } while (0)
#define PhInitFormatSizeWithPrecision(f, v, p) do { (f)->Type = (PH_FORMAT_TYPE)(SizeFormatType | FormatUsePrecision); (f)->u.Size = (v); (f)->Precision = (p); } while (0)


#include "../../DotNetPerf.h"
#include "../WinProcess.h"

//
// The shape the CLR publishes, once both bitnesses have been folded into it.
//
struct SDotNetContext
{
	Perf_GC DotNetPerfGC;
	Perf_Contexts DotNetPerfContext;
	Perf_Interop DotNetPerfInterop;
	Perf_Loading DotNetPerfLoading;
	Perf_Excep DotNetPerfExceptions;
	Perf_LocksAndThreads DotNetPerfLocksAndThreads;
	Perf_Jit DotNetPerfJit;
	Perf_Security DotNetPerfSecurity;
};

//
// A 32bit CLR lays the block out differently, so the Wow64 form is copied
// field by field into the native one rather than cast onto it.
//
static void DotNet__ReadPerfBlock(PVOID perfStatBlock, BOOLEAN IsWow64, SDotNetContext* Context)
{
if (IsWow64)
{
	PerfCounterIPCControlBlock_Wow64* perfBlock = (PerfCounterIPCControlBlock_Wow64*)perfStatBlock;
	Perf_GC_Wow64 dotNetPerfGC_Wow64 = perfBlock->GC;
	Perf_Loading_Wow64 dotNetPerfLoading_Wow64 = perfBlock->Loading;
	Perf_Security_Wow64 dotNetPerfSecurity_Wow64 = perfBlock->Security;

	// Thunk the Wow64 structures into their 64bit versions (or 32bit version on x86).

	Context->DotNetPerfGC.cGenCollections[0] = dotNetPerfGC_Wow64.cGenCollections[0];
	Context->DotNetPerfGC.cGenCollections[1] = dotNetPerfGC_Wow64.cGenCollections[1];
	Context->DotNetPerfGC.cGenCollections[2] = dotNetPerfGC_Wow64.cGenCollections[2];
	Context->DotNetPerfGC.cbPromotedMem[0] = dotNetPerfGC_Wow64.cbPromotedMem[0];
	Context->DotNetPerfGC.cbPromotedMem[1] = dotNetPerfGC_Wow64.cbPromotedMem[1];
	Context->DotNetPerfGC.cbPromotedFinalizationMem = dotNetPerfGC_Wow64.cbPromotedFinalizationMem;
	Context->DotNetPerfGC.cProcessID = dotNetPerfGC_Wow64.cProcessID;
	Context->DotNetPerfGC.cGenHeapSize[0] = dotNetPerfGC_Wow64.cGenHeapSize[0];
	Context->DotNetPerfGC.cGenHeapSize[1] = dotNetPerfGC_Wow64.cGenHeapSize[1];
	Context->DotNetPerfGC.cGenHeapSize[2] = dotNetPerfGC_Wow64.cGenHeapSize[2];
	Context->DotNetPerfGC.cTotalCommittedBytes = dotNetPerfGC_Wow64.cTotalCommittedBytes;
	Context->DotNetPerfGC.cTotalReservedBytes = dotNetPerfGC_Wow64.cTotalReservedBytes;
	Context->DotNetPerfGC.cLrgObjSize = dotNetPerfGC_Wow64.cLrgObjSize;
	Context->DotNetPerfGC.cSurviveFinalize = dotNetPerfGC_Wow64.cSurviveFinalize;
	Context->DotNetPerfGC.cHandles = dotNetPerfGC_Wow64.cHandles;
	Context->DotNetPerfGC.cbAlloc = dotNetPerfGC_Wow64.cbAlloc;
	Context->DotNetPerfGC.cbLargeAlloc = dotNetPerfGC_Wow64.cbLargeAlloc;
	Context->DotNetPerfGC.cInducedGCs = dotNetPerfGC_Wow64.cInducedGCs;
	Context->DotNetPerfGC.timeInGC = dotNetPerfGC_Wow64.timeInGC;
	Context->DotNetPerfGC.timeInGCBase = dotNetPerfGC_Wow64.timeInGCBase;
	Context->DotNetPerfGC.cPinnedObj = dotNetPerfGC_Wow64.cPinnedObj;
	Context->DotNetPerfGC.cSinkBlocks = dotNetPerfGC_Wow64.cSinkBlocks;

	Context->DotNetPerfContext = perfBlock->Context;
	Context->DotNetPerfInterop = perfBlock->Interop;

	Context->DotNetPerfLoading.cClassesLoaded.Current = dotNetPerfLoading_Wow64.cClassesLoaded.Current;
	Context->DotNetPerfLoading.cClassesLoaded.Total = dotNetPerfLoading_Wow64.cClassesLoaded.Total;
	Context->DotNetPerfLoading.cAppDomains.Current = dotNetPerfLoading_Wow64.cAppDomains.Current;
	Context->DotNetPerfLoading.cAppDomains.Total = dotNetPerfLoading_Wow64.cAppDomains.Total;
	Context->DotNetPerfLoading.cAssemblies.Current = dotNetPerfLoading_Wow64.cAssemblies.Current;
	Context->DotNetPerfLoading.cAssemblies.Total = dotNetPerfLoading_Wow64.cAssemblies.Total;
	Context->DotNetPerfLoading.timeLoading = dotNetPerfLoading_Wow64.timeLoading;
	Context->DotNetPerfLoading.cAsmSearchLen = dotNetPerfLoading_Wow64.cAsmSearchLen;
	Context->DotNetPerfLoading.cLoadFailures.Total = dotNetPerfLoading_Wow64.cLoadFailures.Total;
	Context->DotNetPerfLoading.cbLoaderHeapSize = dotNetPerfLoading_Wow64.cbLoaderHeapSize;
	Context->DotNetPerfLoading.cAppDomainsUnloaded = dotNetPerfLoading_Wow64.cAppDomainsUnloaded;

	Context->DotNetPerfExceptions = perfBlock->Exceptions;
	Context->DotNetPerfLocksAndThreads = perfBlock->LocksAndThreads;
	Context->DotNetPerfJit = perfBlock->Jit;

	Context->DotNetPerfSecurity.cTotalRTChecks = dotNetPerfSecurity_Wow64.cTotalRTChecks;
	Context->DotNetPerfSecurity.timeAuthorize = dotNetPerfSecurity_Wow64.timeAuthorize;
	Context->DotNetPerfSecurity.cLinkChecks = dotNetPerfSecurity_Wow64.cLinkChecks;
	Context->DotNetPerfSecurity.timeRTchecks = dotNetPerfSecurity_Wow64.timeRTchecks;
	Context->DotNetPerfSecurity.timeRTchecksBase = dotNetPerfSecurity_Wow64.timeRTchecksBase;
	Context->DotNetPerfSecurity.stackWalkDepth = dotNetPerfSecurity_Wow64.stackWalkDepth;
}
else
{
	PerfCounterIPCControlBlock* perfBlock = (PerfCounterIPCControlBlock*)perfStatBlock;

	Context->DotNetPerfGC = perfBlock->GC;
	Context->DotNetPerfContext = perfBlock->Context;
	Context->DotNetPerfInterop = perfBlock->Interop;
	Context->DotNetPerfLoading = perfBlock->Loading;
	Context->DotNetPerfExceptions = perfBlock->Exceptions;
	Context->DotNetPerfLocksAndThreads = perfBlock->LocksAndThreads;
	Context->DotNetPerfJit = perfBlock->Jit;
	Context->DotNetPerfSecurity = perfBlock->Security;
}
}

//
// Read the CLR performance IPC block and report the counters as values.
// The tree that displays them lives in GUI/TaskInfo/DotNetStats.cpp.
//
SDotNetCounters CWinProcess::GetDotNetPerfCounters() const
{
	SDotNetCounters Counters;

	PH_AUTO_POOL autoPool;
	PhInitializeAutoPool(&autoPool);

	HANDLE ProcessId = (HANDLE)GetProcessId();
#ifdef _WIN64
	BOOLEAN IsWow64 = ((CWinProcess*)this)->IsWoW64();
#else
	// HACK: Work-around for Appdomain enumeration on 32bit.
	BOOLEAN IsWow64 = TRUE;
#endif
	BOOLEAN IsImmersive = ((CWinProcess*)this)->IsImmersiveProcess();

	BOOLEAN ClrV4 = FALSE;

	HANDLE ProcessHandle = NULL;
	if (NT_SUCCESS(PhOpenProcess(&ProcessHandle, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE | SYNCHRONIZE, ProcessId)))
	{
		ULONG flags = 0;

		if (NT_SUCCESS(PhGetProcessIsDotNetEx(ProcessId, ProcessHandle, IsImmersive == 1 ? 0 : PH_CLR_USE_SECTION_CHECK, NULL, &flags)))
		{
			if (flags & PH_CLR_VERSION_4_ABOVE)
				ClrV4 = TRUE;
		}
	}

	PVOID BlockTableAddress = NULL;
	BOOLEAN ControlBlockValid = FALSE;

	if (ClrV4)
		ControlBlockValid = OpenDotNetPublicControlBlock_V4(!!IsImmersive, ProcessHandle, ProcessId, &BlockTableAddress);
	else
		ControlBlockValid = OpenDotNetPublicControlBlock_V2(ProcessId, &BlockTableAddress);

	if (ControlBlockValid)
	{
		PVOID perfStatBlock = ClrV4 ? GetPerfIpcBlock_V4(IsWow64, BlockTableAddress)
								   : GetPerfIpcBlock_V2(IsWow64, BlockTableAddress);

		if (perfStatBlock)
		{
			SDotNetContext TempContext;
			SDotNetContext* context = &TempContext;
			DotNet__ReadPerfBlock(perfStatBlock, IsWow64, context);

			Counters.insert(DOTNET_INDEX_EXCEPTIONS_THROWNCOUNT, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfExceptions.cThrown.Total));
			Counters.insert(DOTNET_INDEX_EXCEPTIONS_FILTERSCOUNT, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfExceptions.cFiltersExecuted));
			Counters.insert(DOTNET_INDEX_EXCEPTIONS_FINALLYCOUNT, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfExceptions.cFinallysExecuted));
			Counters.insert(DOTNET_INDEX_INTEROP_CCWCOUNT, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfInterop.cCCW));
			Counters.insert(DOTNET_INDEX_INTEROP_STUBCOUNT, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfInterop.cStubs));
			Counters.insert(DOTNET_INDEX_INTEROP_MARSHALCOUNT, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfInterop.cMarshalling));
			Counters.insert(DOTNET_INDEX_INTEROP_TLBIMPORTPERSEC, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfInterop.cTLBImports));
			Counters.insert(DOTNET_INDEX_INTEROP_TLBEXPORTPERSEC, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfInterop.cTLBExports));
			Counters.insert(DOTNET_INDEX_JIT_ILMETHODSJITTED, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfJit.cMethodsJitted));
			Counters.insert(DOTNET_INDEX_JIT_ILBYTESJITTED, SDotNetCounter(SDotNetCounter::eSize, context->DotNetPerfJit.cbILJitted.Current));
			Counters.insert(DOTNET_INDEX_JIT_ILTOTALBYTESJITTED, SDotNetCounter(SDotNetCounter::eSize, context->DotNetPerfJit.cbILJitted.Total));
			Counters.insert(DOTNET_INDEX_JIT_FAILURES, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfJit.cJitFailures));
			Counters.insert(DOTNET_INDEX_JIT_TIME, context->DotNetPerfJit.timeInJitBase != 0
				? SDotNetCounter((float)((context->DotNetPerfJit.timeInJit << 8) * 100 / (FLOAT)(context->DotNetPerfJit.timeInJitBase << 8)))
				: SDotNetCounter(0.0f));
			Counters.insert(DOTNET_INDEX_LOADING_CURRENTLOADED, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfLoading.cClassesLoaded.Current));
			Counters.insert(DOTNET_INDEX_LOADING_TOTALLOADED, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfLoading.cClassesLoaded.Total));
			Counters.insert(DOTNET_INDEX_LOADING_CURRENTAPPDOMAINS, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfLoading.cAppDomains.Current));
			Counters.insert(DOTNET_INDEX_LOADING_TOTALAPPDOMAINS, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfLoading.cAppDomains.Total));
			Counters.insert(DOTNET_INDEX_LOADING_CURRENTASSEMBLIES, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfLoading.cAssemblies.Current));
			Counters.insert(DOTNET_INDEX_LOADING_TOTALASSEMBLIES, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfLoading.cAssemblies.Total));
			Counters.insert(DOTNET_INDEX_LOADING_ASSEMBLYSEARCHLENGTH, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfLoading.cAsmSearchLen));
			Counters.insert(DOTNET_INDEX_LOADING_TOTALLOADFAILURES, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfLoading.cLoadFailures.Total));
			Counters.insert(DOTNET_INDEX_LOADING_BYTESINLOADERHEAP, SDotNetCounter(SDotNetCounter::eSize, context->DotNetPerfLoading.cbLoaderHeapSize));
			Counters.insert(DOTNET_INDEX_LOADING_TOTALAPPDOMAINSUNLOADED, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfLoading.cAppDomainsUnloaded.Total));
			Counters.insert(DOTNET_INDEX_LOCKSANDTHREADS_TOTALLOCKS, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfLocksAndThreads.cContention.Total));
			Counters.insert(DOTNET_INDEX_LOCKSANDTHREADS_TOTALQUEUELENGTH, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfLocksAndThreads.cQueueLength.Current));
			Counters.insert(DOTNET_INDEX_LOCKSANDTHREADS_QUEUELENGTHPEAK, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfLocksAndThreads.cQueueLength.Total));
			Counters.insert(DOTNET_INDEX_LOCKSANDTHREADS_CURRENTLOGICAL, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfLocksAndThreads.cCurrentThreadsLogical));
			Counters.insert(DOTNET_INDEX_LOCKSANDTHREADS_CURRENTPHYSICAL, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfLocksAndThreads.cCurrentThreadsPhysical));
			Counters.insert(DOTNET_INDEX_LOCKSANDTHREADS_CURRENTRECOGNIZED, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfLocksAndThreads.cRecognizedThreads.Current));
			Counters.insert(DOTNET_INDEX_LOCKSANDTHREADS_TOTALRECOGNIZED, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfLocksAndThreads.cRecognizedThreads.Total));
			Counters.insert(DOTNET_INDEX_MEMORY_GENZEROCOLLECTIONS, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfGC.cGenCollections[0]));
			Counters.insert(DOTNET_INDEX_MEMORY_GENONECOLLECTIONS, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfGC.cGenCollections[1]));
			Counters.insert(DOTNET_INDEX_MEMORY_GENTWOCOLLECTIONS, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfGC.cGenCollections[2]));
			Counters.insert(DOTNET_INDEX_MEMORY_PROMOTEDFROMGENZERO, SDotNetCounter(SDotNetCounter::eSize, context->DotNetPerfGC.cbPromotedMem[0]));
			Counters.insert(DOTNET_INDEX_MEMORY_PROMOTEDFROMGENONE, SDotNetCounter(SDotNetCounter::eSize, context->DotNetPerfGC.cbPromotedMem[1]));
			Counters.insert(DOTNET_INDEX_MEMORY_PROMOTEDFINALFROMGENZERO, SDotNetCounter(SDotNetCounter::eSize, context->DotNetPerfGC.cbPromotedFinalizationMem));
			Counters.insert(DOTNET_INDEX_MEMORY_PROCESSID, SDotNetCounter(SDotNetCounter::ePlain, context->DotNetPerfGC.cProcessID));
			Counters.insert(DOTNET_INDEX_MEMORY_GENZEROHEAPSIZE, SDotNetCounter(SDotNetCounter::eSize, context->DotNetPerfGC.cGenHeapSize[0]));
			Counters.insert(DOTNET_INDEX_MEMORY_GENONEHEAPSIZE, SDotNetCounter(SDotNetCounter::eSize, context->DotNetPerfGC.cGenHeapSize[1]));
			Counters.insert(DOTNET_INDEX_MEMORY_GENTWOHEAPSIZE, SDotNetCounter(SDotNetCounter::eSize, context->DotNetPerfGC.cGenHeapSize[2]));
			Counters.insert(DOTNET_INDEX_MEMORY_LOHSIZE, SDotNetCounter(SDotNetCounter::eSize, context->DotNetPerfGC.cLrgObjSize));
			Counters.insert(DOTNET_INDEX_MEMORY_FINALSURVIVORS, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfGC.cSurviveFinalize));
			Counters.insert(DOTNET_INDEX_MEMORY_GCHANDLES, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfGC.cHandles));
			Counters.insert(DOTNET_INDEX_MEMORY_INDUCEDGC, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfGC.cInducedGCs));
			Counters.insert(DOTNET_INDEX_MEMORY_TIMEINGC, context->DotNetPerfGC.timeInGCBase != 0
				? SDotNetCounter((float)((FLOAT)context->DotNetPerfGC.timeInGC * 100 / (FLOAT)context->DotNetPerfGC.timeInGCBase))
				: SDotNetCounter(0.0f));
			Counters.insert(DOTNET_INDEX_MEMORY_BYTESINALLHEAPS, SDotNetCounter(SDotNetCounter::eSize, context->DotNetPerfGC.cGenHeapSize[1] + context->DotNetPerfGC.cGenHeapSize[2] + context->DotNetPerfGC.cLrgObjSize));
			Counters.insert(DOTNET_INDEX_MEMORY_TOTALCOMMITTED, SDotNetCounter(SDotNetCounter::eSize, context->DotNetPerfGC.cTotalCommittedBytes));
			Counters.insert(DOTNET_INDEX_MEMORY_TOTALRESERVED, SDotNetCounter(SDotNetCounter::eSize, context->DotNetPerfGC.cTotalReservedBytes));
			Counters.insert(DOTNET_INDEX_MEMORY_TOTALPINNED, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfGC.cPinnedObj));
			Counters.insert(DOTNET_INDEX_MEMORY_TOTALSINKS, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfGC.cSinkBlocks));
			Counters.insert(DOTNET_INDEX_MEMORY_TOTALBYTESSINCESTART, SDotNetCounter(SDotNetCounter::eSize, context->DotNetPerfGC.cbAlloc));
			Counters.insert(DOTNET_INDEX_MEMORY_TOTALLOHBYTESSINCESTART, SDotNetCounter(SDotNetCounter::eSize, context->DotNetPerfGC.cbLargeAlloc));
			Counters.insert(DOTNET_INDEX_REMOTING_TOTALREMOTECALLS, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfContext.cRemoteCalls.Total));
			Counters.insert(DOTNET_INDEX_REMOTING_CHANNELS, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfContext.cChannels));
			Counters.insert(DOTNET_INDEX_REMOTING_CONTEXTPROXIES, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfContext.cProxies));
			Counters.insert(DOTNET_INDEX_REMOTING_CONTEXTCLASSESLOADED, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfContext.cClasses));
			Counters.insert(DOTNET_INDEX_REMOTING_CONTEXTS, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfContext.cContexts));
			Counters.insert(DOTNET_INDEX_REMOTING_CONTEXTSALLOCATED, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfContext.cObjAlloc));
			Counters.insert(DOTNET_INDEX_SECURITY_TOTALRUNTIMECHECKS, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfSecurity.cTotalRTChecks));
			Counters.insert(DOTNET_INDEX_SECURITY_LINKTIMECHECKS, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfSecurity.cLinkChecks));
			Counters.insert(DOTNET_INDEX_SECURITY_TIMEINRTCHECKS, context->DotNetPerfSecurity.timeRTchecksBase != 0
				? SDotNetCounter((float)((FLOAT)context->DotNetPerfSecurity.timeRTchecks * 100 / (FLOAT)context->DotNetPerfSecurity.timeRTchecksBase))
				: SDotNetCounter(0.0f));
			Counters.insert(DOTNET_INDEX_SECURITY_STACKWALKDEPTH, SDotNetCounter(SDotNetCounter::eCount, context->DotNetPerfSecurity.stackWalkDepth));
		}
	}

	//
	// The original leaked this handle on every refresh of the .NET tab.
	//
	if (ProcessHandle)
		NtClose(ProcessHandle);

	PhDeleteAutoPool(&autoPool);
	return Counters;
}
