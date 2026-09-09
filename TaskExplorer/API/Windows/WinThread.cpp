/*
 * Task Explorer -
 *   qt wrapper and support functions based on thrdprv.c
 *
 * Copyright (C) 2010-2016 wj32
 * Copyright (C) 2019 David Xanatos
 *
 * This file is part of Task Explorer and contains System Informer code.
 * 
 */

#include "stdafx.h"
#include "WinThread.h"
#include "WinToken.h"
#include "ProcessHacker.h"
#include "WinSecurityEditor.h"
#include "WindowsAPI.h"
#include "../../SVC/TaskService.h"

struct SWinThread
{
	SWinThread()
	{
		UniqueThreadId = NULL;
		ThreadHandle = NULL;
		//LastExtendedUpdate = GetCurTick();
		StartAddressResolveLevel = PhsrlAddress;
		StartAddressResolvePending = false;
		memset(&idealProcessorNumber, 0, sizeof(PROCESSOR_NUMBER));

		CreateTime.QuadPart = 0;

		LastSystemCallStatus = STATUS_UNSUCCESSFUL;
		memset(&LastSystemCall, 0, sizeof(THREAD_LAST_SYSCALL_INFORMATION));

		LastStatusValue = 0;
		LastStatusQueryStatus = STATUS_UNSUCCESSFUL;

		memset(&ApartmentInfo, 0, sizeof(PH_APARTMENT_INFO));

		LxssThreadId = 0;
	}

	HANDLE UniqueThreadId;
	HANDLE ThreadHandle;
	HANDLE ProcessHandle;
	//quint64 LastExtendedUpdate;
	PH_SYMBOL_RESOLVE_LEVEL StartAddressResolveLevel;
	bool StartAddressResolvePending;

	PROCESSOR_NUMBER idealProcessorNumber;

	LARGE_INTEGER CreateTime;

	NTSTATUS LastSystemCallStatus;
	THREAD_LAST_SYSCALL_INFORMATION LastSystemCall;

	NTSTATUS LastStatusValue;
	NTSTATUS LastStatusQueryStatus;

	PH_APARTMENT_INFO ApartmentInfo;

	//IO_COUNTERS IoCounters;

	quint64 LxssThreadId;
};

CWinThread::CWinThread(QObject *parent) 
	: CThreadInfo(parent) 
{
	m_StartAddress = 0;

	m_BasePriorityIncrement = 0;

	m_MiscStates = 0;
	
	m_TokenState = eTokenStateUnknown;
	m_HasToken2 = false;

	m_bHasRpcState = false;

	m = new SWinThread();
}

CWinThread::~CWinThread()
{
	UnInit(); // just in case 

	delete m;
}

bool CWinThread::InitStaticData(void* ProcessHandle, struct _SYSTEM_THREAD_INFORMATION* thread)
{
	QWriteLocker Locker(&m_Mutex);

	m_ThreadId = (quint64)thread->ClientId.UniqueThread;
	m_ProcessId = (quint64)thread->ClientId.UniqueProcess;

	m->CreateTime = thread->CreateTime;
	m_CreateTimeStamp = FILETIME2ms(m->CreateTime.QuadPart);

    // Try to open a handle to the thread.
	m->UniqueThreadId = thread->ClientId.UniqueThread;
	if (!NT_SUCCESS(PhOpenThread(&m->ThreadHandle, THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, m->UniqueThreadId)))
	{
		if (!NT_SUCCESS(PhOpenThread(&m->ThreadHandle, THREAD_QUERY_INFORMATION, thread->ClientId.UniqueThread)))
		{
			PhOpenThread(&m->ThreadHandle, THREAD_QUERY_LIMITED_INFORMATION, thread->ClientId.UniqueThread);
		}
	}

	m->ProcessHandle = ProcessHandle;

	ULONG_PTR startAddress = NULL;
    if (m->ThreadHandle)
    {
        PhGetThreadStartAddress(m->ThreadHandle, &startAddress);

		PVOID serviceTag;
		if (NT_SUCCESS(PhGetThreadServiceTag(m->ThreadHandle, ProcessHandle, &serviceTag)))
		{
			PPH_STRING serviceName = PhGetServiceNameFromTag(thread->ClientId.UniqueProcess, serviceTag);

			m_ServiceName = CastPhString(serviceName);
		}
    }

    if (!startAddress)
        startAddress = (ULONG_PTR)thread->StartAddress;

    m_StartAddress = (ULONG64)startAddress;
	m_StartAddressString = FormatAddress(m_StartAddress); // this will be replaced with the resolved symbol

	return true;
}

bool CWinThread::UpdateDynamicData(struct _SYSTEM_THREAD_INFORMATION* thread, quint64 sysTotalTime, quint64 sysTotalCycleTime)
{
	QWriteLocker Locker(&m_Mutex);

	BOOLEAN modified = FALSE;

	m_KernelTime = thread->KernelTime.QuadPart;
	m_UserTime = thread->UserTime.QuadPart;

	m_Priority = thread->Priority;
	m_BasePriority = thread->BasePriority;
	
	if (m_State != (KTHREAD_STATE)thread->ThreadState)
	{
		m_State = (KTHREAD_STATE)thread->ThreadState;
		modified = TRUE;
	}

	if (m_WaitReason != thread->WaitReason)
	{
		m_WaitReason = thread->WaitReason;
		modified = TRUE;
	}

	bool HandleReOpened = false;
	if (m->ThreadHandle == NULL)
	{
		if (!NT_SUCCESS(PhOpenThread(&m->ThreadHandle, THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, m->UniqueThreadId)))
		{
			if (!NT_SUCCESS(PhOpenThread(&m->ThreadHandle, THREAD_QUERY_INFORMATION, m->UniqueThreadId)))
			{
				PhOpenThread(&m->ThreadHandle, THREAD_QUERY_LIMITED_INFORMATION, m->UniqueThreadId);
			}
		}

		HandleReOpened = true;
	}


	QWriteLocker StatsLocker(&m_StatsMutex);

    // Update the context switch count.
    {
        ULONG oldDelta = m_CpuStats.ContextSwitchesDelta.Delta;
        m_CpuStats.ContextSwitchesDelta.Update(thread->ContextSwitches);
        if (m_CpuStats.ContextSwitchesDelta.Delta != oldDelta)
            modified = TRUE;
    }

	// Update the cycle count.
	if (m->ThreadHandle)
	{
		ULONG64 oldDelta = m_CpuStats.CycleDelta.Delta;

		ULONG64 cycles = 0;
		if (m_ProcessId != (quint64)SYSTEM_IDLE_PROCESS_ID)
			PhGetThreadCycleTime(m->ThreadHandle, &cycles);
		else
			cycles = qobject_cast<CWindowsAPI*>(GetSystem().data())->GetCpuIdleCycleTime(m_ThreadId);

		m_CpuStats.CycleDelta.Update(cycles);

		// without this we will get a cpu usage spike when starting to display this thread
		if (HandleReOpened)
			m_CpuStats.CycleDelta.Delta = 0;

		if (m_CpuStats.CycleDelta.Delta != oldDelta)
			modified = TRUE;
	}

    // Update the CPU time deltas.
    m_CpuStats.CpuKernelDelta.Update(m_KernelTime);
    m_CpuStats.CpuUserDelta.Update(m_UserTime);

	// If the cycle time isn't available, we'll fall back to using the CPU time.
	m_CpuStats.UpdateStats(sysTotalTime, (m_ProcessId == (quint64)SYSTEM_IDLE_PROCESS_ID || m->ThreadHandle) ? sysTotalCycleTime : 0);

	StatsLocker.unlock();

	// Update the GUI thread status.
    {
        GUITHREADINFO info = { sizeof(GUITHREADINFO) };
        bool oldIsGuiThread = m_IsGuiThread;

        m_IsGuiThread = !!GetGUIThreadInfo(m_ThreadId, &info);

        if (m_IsGuiThread != oldIsGuiThread)
            modified = TRUE;
    }

	if (m->StartAddressResolveLevel != PhsrlFunction && !m->StartAddressResolvePending)
	{
		m->StartAddressResolvePending = true;
		qobject_cast<CWindowsAPI*>(GetSystem().data())->GetSymbolProvider()->GetSymbolFromAddress(m_ProcessId, m_StartAddress, this, SLOT(OnSymbolFromAddress(quint64, quint64, int, const QString&, const QString&, const QString&)));
	}

	// for all other values we need a handle
	if (!m->ThreadHandle)
		return modified;

	// Thread debug name
	if (WindowsVersion >= WINDOWS_10_RS1)
    {
        PPH_STRING threadName;
        if (NT_SUCCESS(PhGetThreadName(m->ThreadHandle, &threadName)))
        {
            m_ThreadName = CastPhString(threadName);
        }
    }

    // Update the base priority increment.
    {
		LONG basePriorityIncrement = THREAD_PRIORITY_ERROR_RETURN;
		quint64 threadAffinityMask = 0;
		THREAD_BASIC_INFORMATION basicInfo;
        if (m->ThreadHandle && NT_SUCCESS(PhGetThreadBasicInformation(m->ThreadHandle,&basicInfo)))
        {
            basePriorityIncrement = basicInfo.BasePriority;
			threadAffinityMask = basicInfo.AffinityMask;
        }

        if (m_BasePriorityIncrement != basePriorityIncrement || m_AffinityMask != threadAffinityMask)
        {
			m_BasePriorityIncrement = basePriorityIncrement;
			m_AffinityMask = threadAffinityMask;

            modified = TRUE;
        }
    }
	
    // Update the page priority increment.
    {
		ULONG pagePriorityInteger = MEMORY_PRIORITY_NORMAL + 1;
		PhGetThreadPagePriority(m->ThreadHandle, &pagePriorityInteger);

        if (m_PagePriority != pagePriorityInteger)
        {
			m_PagePriority = pagePriorityInteger;

            modified = TRUE;
        }
    }

    // Update the I/O priority increment.
    {
		IO_PRIORITY_HINT ioPriorityInteger = MaxIoPriorityTypes;
		PhGetThreadIoPriority(m->ThreadHandle, &ioPriorityInteger);

        if (m_IOPriority != ioPriorityInteger)
        {
			m_IOPriority = ioPriorityInteger;

            modified = TRUE;
        }
    }

	// update critical flag
	{
		BOOLEAN breakOnTermination;
		if (NT_SUCCESS(PhGetThreadBreakOnTermination(m->ThreadHandle, &breakOnTermination)))
		{
			if ((bool)breakOnTermination != m_IsCritical)
			{
				m_IsCritical = breakOnTermination;
				modified = TRUE;
			}
		}
	}

	// update HasToken
	{
		ETokenState tokenState;
		HANDLE tokenHandle;
		NTSTATUS status = PhOpenThreadToken(m->ThreadHandle, TOKEN_QUERY, TRUE, &tokenHandle);
		if (status == STATUS_NO_TOKEN)
		{
			tokenState = eTokenStateNotPresent;
		}
		else if (status == STATUS_CANT_OPEN_ANONYMOUS)
		{
			tokenState = eTokenStateAnonymous;
		}
		else
		{
			tokenState = eTokenStatePresent;
		}

		if (NT_SUCCESS(status))
			NtClose(tokenHandle);

		if (tokenState != m_TokenState)
		{
			m_TokenState = tokenState;
			modified = TRUE;
		}
	}

	if (m_IsSandboxed) 
	{
		BOOLEAN HasToken2 = FALSE;

		CSandboxieAPI* pSandboxieAPI = ((CWindowsAPI*)GetSystem().data())->GetSandboxieAPI();
		HasToken2 = pSandboxieAPI && pSandboxieAPI->TestOriginalToken(m_ProcessId, m_ThreadId);
		if ((bool)HasToken2 != m_HasToken2)
		{
			m_HasToken2 = HasToken2;
			modified = TRUE;
		}
	}

	// ideal processor
	{
		PROCESSOR_NUMBER idealProcessorNumber;
		if (NT_SUCCESS(PhGetThreadIdealProcessor(m->ThreadHandle, &idealProcessorNumber)))
		{
			if (memcmp(&idealProcessorNumber, &m->idealProcessorNumber, sizeof(PROCESSOR_NUMBER)) != 0)
			{
				memcpy(&m->idealProcessorNumber, &idealProcessorNumber, sizeof(PROCESSOR_NUMBER));
				modified = TRUE;
			}
		}
	}

	BOOLEAN pendingIrp;
	if (NT_SUCCESS(PhGetThreadIsIoPending(m->ThreadHandle, &pendingIrp)))
	{
		m_PendingIrp = !!pendingIrp;
	}

	BOOLEAN threadIsFiber;
	if (NT_SUCCESS(PhGetThreadIsFiber(m->ThreadHandle, m->ProcessHandle, &threadIsFiber)))
	{
		m_IsFiber = !!threadIsFiber;
	}

	BOOLEAN priorityBoostDisabled = FALSE;
	if (NT_SUCCESS(PhGetThreadPriorityBoost(m->ThreadHandle, &priorityBoostDisabled)))
	{
		m_PriorityBoost = priorityBoostDisabled;
	}

	if (m_ProcessId != (quint64)SYSTEM_IDLE_PROCESS_ID && m_ProcessId != (quint64)SYSTEM_PROCESS_ID)
	{
		THREAD_LAST_SYSCALL_INFORMATION lastSystemCall;
		m->LastSystemCallStatus = PhGetThreadLastSystemCall(m->ThreadHandle, &lastSystemCall);
		if (NT_SUCCESS(m->LastSystemCallStatus))
			m->LastSystemCall = lastSystemCall;
	}

	m->LastStatusQueryStatus = PhGetThreadLastStatusValue(m->ThreadHandle, m->ProcessHandle, &m->LastStatusValue);

	PhGetThreadApartment(m->ThreadHandle, m->ProcessHandle, &m->ApartmentInfo);

	BOOLEAN hasRpcState;
	if (NT_SUCCESS(PhGetThreadRpcState(m->ThreadHandle, m->ProcessHandle, &hasRpcState)))
	{
		m_bHasRpcState = !!hasRpcState;
	}

	ULONG lxssThreadId;
	if (NT_SUCCESS(KphQueryInformationThread(m->ThreadHandle, KphThreadWSLThreadId, &lxssThreadId, sizeof(ULONG), NULL)))
	{
		m->LxssThreadId = lxssThreadId;
	}

	ULONG_PTR stackUsage = 0;
	ULONG_PTR stackLimit = 0;
	if (NT_SUCCESS(PhGetThreadStackSize(m->ThreadHandle, m->ProcessHandle, &stackUsage, &stackLimit)) && stackUsage && stackLimit)
	{
		FLOAT percent = (FLOAT)stackUsage / stackLimit * 100;
		m_StackUsageFloat = percent;
		m_StackUsage = stackUsage;
		m_StackLimit = stackLimit;
	}

	IO_COUNTERS IoCounters;
	if (KsiLevel() >= KphLevelMed && NT_SUCCESS(KphQueryInformationThread(m->ThreadHandle, KphThreadIoCounters, &IoCounters, sizeof(IO_COUNTERS), NULL)))
	{
		m_IoStats.SetRead(IoCounters.ReadTransferCount, IoCounters.ReadOperationCount);
		m_IoStats.SetWrite(IoCounters.WriteTransferCount, IoCounters.WriteOperationCount);
		m_IoStats.SetOther(IoCounters.OtherTransferCount, IoCounters.OtherOperationCount);
	}

	if (WindowsVersion >= WINDOWS_11_22H2)
	{
		POWER_THROTTLING_THREAD_STATE powerThrottlingState;
		if (NT_SUCCESS(PhGetThreadPowerThrottlingState(m->ThreadHandle, &powerThrottlingState)))
		{
			m_IsPowerThrottled = FALSE;

			if (powerThrottlingState.ControlMask & POWER_THROTTLING_THREAD_EXECUTION_SPEED &&
				powerThrottlingState.StateMask & POWER_THROTTLING_THREAD_EXECUTION_SPEED)
			{
				m_IsPowerThrottled = TRUE;
			}
		}
	}

	return modified;
}
void CWinThread::OnSymbolFromAddress(quint64 ProcessId, quint64 Address, int ResolveLevel, const QString& StartAddressString, const QString& FileName, const QString& SymbolName)
{
	m->StartAddressResolvePending = false;
	m->StartAddressResolveLevel = (PH_SYMBOL_RESOLVE_LEVEL)ResolveLevel;
	m_StartAddressString = StartAddressString;
	m_StartAddressFileName = FileName;
}

void CWinThread::CloseHandle()
{
	QWriteLocker Locker(&m_Mutex);

	if (m->ThreadHandle != NULL) {
		NtClose(m->ThreadHandle);
		m->ThreadHandle = NULL;
	}
}

void CWinThread::UnInit()
{
	CloseHandle();

	QWriteLocker StatsLocker(&m_StatsMutex);

	m_CpuStats.ContextSwitchesDelta.Delta = 0;
	
	m_CpuStats.CpuUsage = 0;
	m_CpuStats.CpuKernelUsage = 0;
	m_CpuStats.CpuUserUsage = 0;
}

quint64 CWinThread::TraceStack()
{
	return qobject_cast<CWindowsAPI*>(GetSystem().data())->GetSymbolProvider()->GetStackTrace(m_ProcessId, m_ThreadId, this, SIGNAL(StackTraced(const CStackTracePtr&)));
}

QString CWinThread::GetName() const
{
	CProcessPtr pProcess = GetProcess().staticCast<CProcessInfo>();
	if (pProcess)
		return pProcess->GetName();
	return MakePlaceholder(TE_NAME_UNKNOWN_PROCESS);
}
quint64 CWinThread::GetRawCreateTime() const
{
	QReadLocker Locker(&m_Mutex); 
	return m->CreateTime.QuadPart; 
}

QString CWinThread::GetStartAddressString() const
{
	QReadLocker Locker(&m_Mutex);
	return m_StartAddressString;
}

STATUS CWinThread::SetPriorityBoost(bool Value)
{
	NTSTATUS status;
	HANDLE threadHandle;

	if (NT_SUCCESS(status = PhOpenThread(&threadHandle, THREAD_SET_LIMITED_INFORMATION, (HANDLE)m_ThreadId)))
	{
		status = PhSetThreadPriorityBoost(threadHandle, Value);
		NtClose(threadHandle);
	}

	if (NT_SUCCESS(status))
		m_PriorityBoost = Value;
	else
	{
		if(CTaskService::CheckStatus(status))
		{
			if (CTaskService::TaskAction(m_ProcessId, m_ThreadId, "SetPriorityBoost", Value))
				return OK;
		}

		return ERR(TE_SetThreadPriorityBoost, status);
	}
	return OK;
}

STATUS CWinThread::SetPriority(qint32 Value)
{
	QWriteLocker Locker(&m_Mutex); 

    // Special saturation values
    if (Value == THREAD_PRIORITY_TIME_CRITICAL)
        Value = THREAD_BASE_PRIORITY_LOWRT + 1;
    else if (Value == THREAD_PRIORITY_IDLE)
        Value = THREAD_BASE_PRIORITY_IDLE - 1;

	NTSTATUS status;
    HANDLE threadHandle;
	if (NT_SUCCESS(status = PhOpenThread(&threadHandle, THREAD_SET_INFORMATION, (HANDLE)m_ThreadId)))
    {
        status = PhSetThreadBasePriority(threadHandle, Value);
        NtClose(threadHandle);
    }

    if (!NT_SUCCESS(status))
    {
		if(CTaskService::CheckStatus(status))
		{
			if (CTaskService::TaskAction(m_ProcessId, m_ThreadId, "SetPriority", Value))
				return OK;
		}

		return ERR(TE_SetThreadPriority, status);
    }
	return OK;
}

STATUS CWinThread::SetPagePriority(qint32 Value)
{
	QWriteLocker Locker(&m_Mutex); 

	NTSTATUS status;
    HANDLE threadHandle;
	if (NT_SUCCESS(status = PhOpenThread(&threadHandle, THREAD_SET_INFORMATION, (HANDLE)m_ThreadId)))
    {
        status = PhSetThreadPagePriority(threadHandle, Value);
        NtClose(threadHandle);
    }

    if (!NT_SUCCESS(status))
    {
		if(CTaskService::CheckStatus(status))
		{
			if (CTaskService::TaskAction(m_ProcessId, m_ThreadId, "SetPagePriority", Value))
				return OK;
		}

		return ERR(TE_SetPagePriority, status);
    }
	return OK;
}

STATUS CWinThread::SetIOPriority(qint32 Value)
{
	QWriteLocker Locker(&m_Mutex); 

	NTSTATUS status;
    HANDLE threadHandle;
	if (NT_SUCCESS(status = PhOpenThread(&threadHandle, THREAD_SET_INFORMATION, (HANDLE)m_ThreadId)))
    {
        status = PhSetThreadIoPriority(threadHandle, (IO_PRIORITY_HINT)Value);
        NtClose(threadHandle);
    }

    if (!NT_SUCCESS(status))
    {
		if(CTaskService::CheckStatus(status))
		{
			if (CTaskService::TaskAction(m_ProcessId, m_ThreadId, "SetIOPriority", Value))
				return OK;
		}

		return ERR(TE_SetIoPriority, status);
    }
	return OK;
}

STATUS CWinThread::SetAffinityMask(quint64 Value)
{	
	QWriteLocker Locker(&m_Mutex); 

	NTSTATUS status;
	HANDLE threadHandle;
    if (NT_SUCCESS(status = PhOpenThread(&threadHandle, THREAD_SET_LIMITED_INFORMATION, (HANDLE)m_ThreadId)))
    {
        status = PhSetThreadAffinityMask(threadHandle, Value);
        NtClose(threadHandle);
    }

    if (!NT_SUCCESS(status))
    {
		if(CTaskService::CheckStatus(status))
		{
			if (CTaskService::TaskAction(m_ProcessId, m_ThreadId, "SetAffinityMask", Value))
				return OK;
		}

		return ERR(TE_SetCpuAffinity, status);
    }
	return OK;
}

STATUS CWinThread::Terminate(bool bForce)
{
	QWriteLocker Locker(&m_Mutex); 

    NTSTATUS status;
    HANDLE threadHandle;
    if (NT_SUCCESS(status = PhOpenThread(&threadHandle, THREAD_QUERY_INFORMATION | THREAD_TERMINATE, (HANDLE)m_ThreadId)))
    {
#ifndef SAFE_MODE // in safe mode always check and fail
		if (!bForce)
#endif
		{
			BOOLEAN breakOnTermination;
			PhGetThreadBreakOnTermination(threadHandle, &breakOnTermination);

			if (breakOnTermination /*m_IsCritical*/)
			{
				NtClose(threadHandle);
				return ERR(TE_ConfirmTerminateCriticalThread, ERROR_CONFIRM);
			}
		}

        status = NtTerminateThread(threadHandle, STATUS_SUCCESS);
        NtClose(threadHandle);
    }

    if (!NT_SUCCESS(status))
    {
		if(CTaskService::CheckStatus(status))
		{
			if (CTaskService::TaskAction(m_ProcessId, m_ThreadId, "Terminate"))
				return OK;
		}

		return ERR(TE_TerminateThread, status);
    }
	return OK;
}

bool CWinThread::IsSuspended() const
{
	QReadLocker Locker(&m_Mutex);
	return m_State == Waiting && m_WaitReason == Suspended;
}

STATUS CWinThread::Suspend()
{
	QWriteLocker Locker(&m_Mutex); 

    NTSTATUS status;
    HANDLE threadHandle;
    if (NT_SUCCESS(status = PhOpenThread(&threadHandle, THREAD_SUSPEND_RESUME, (HANDLE)m_ThreadId)))
    {
        status = NtSuspendThread(threadHandle, NULL);
        NtClose(threadHandle);
    }

    if (!NT_SUCCESS(status))
    {
		if(CTaskService::CheckStatus(status))
		{
			if (CTaskService::TaskAction(m_ProcessId, m_ThreadId, "Suspend"))
				return OK;
		}

		return ERR(TE_SuspendThread, status);
    }
	return OK;
}

STATUS CWinThread::Resume()
{
	QWriteLocker Locker(&m_Mutex); 

    NTSTATUS status;
    HANDLE threadHandle;
    if (NT_SUCCESS(status = PhOpenThread(&threadHandle, THREAD_SUSPEND_RESUME, (HANDLE)m_ThreadId)))
    {
        status = NtResumeThread(threadHandle, NULL);
        NtClose(threadHandle);
    }

    if (!NT_SUCCESS(status))
    {
		if(CTaskService::CheckStatus(status))
		{
			if (CTaskService::TaskAction(m_ProcessId, m_ThreadId, "Resume"))
				return OK;
		}

		return ERR(TE_ResumeThread, status);
    }
	return OK;
}

int CWinThread::GetIdealProcessorGroup() const
{
	return m->idealProcessorNumber.Group;
}

int CWinThread::GetIdealProcessorNumber() const
{
	return m->idealProcessorNumber.Number;
}
STATUS CWinThread::SetCriticalThread(bool bSet, bool bForce)
{
	QWriteLocker Locker(&m_Mutex);

	NTSTATUS status;
    HANDLE threadHandle;
    BOOLEAN breakOnTermination;

    status = PhOpenThread(&threadHandle, THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION, (HANDLE)m_ThreadId);
    if (NT_SUCCESS(status))
    {
        status = PhGetThreadBreakOnTermination(threadHandle, &breakOnTermination);

        if (NT_SUCCESS(status))
        {
			if (bSet == false && breakOnTermination)
            {
				status = PhSetThreadBreakOnTermination(threadHandle, FALSE);
            }
			else if (bSet == true && !breakOnTermination)
			{
#ifndef SAFE_MODE // in safe mode always check and fail
				if (!bForce)
#endif
				{
					NtClose(threadHandle);

					return ERR(TE_ConfirmCriticalProcShutdown, ERROR_CONFIRM);
				}

				status = PhSetThreadBreakOnTermination(threadHandle, TRUE);
			} 
        }

        NtClose(threadHandle);
    }

    if (!NT_SUCCESS(status))
    {
        return ERR(TE_ChangeThreadCritical, status);
    }

	m_IsCritical = bSet;
	return OK;
}

STATUS CWinThread::CancelIO()
{
	QWriteLocker Locker(&m_Mutex);

	NTSTATUS status;

	HANDLE threadHandle;
    if (NT_SUCCESS(status = PhOpenThread(&threadHandle, THREAD_TERMINATE, (HANDLE)m_ThreadId)))
    {
		IO_STATUS_BLOCK isb;
        status = NtCancelSynchronousIoFile(threadHandle, NULL, &isb);
    }

    if (status == STATUS_NOT_FOUND)
    {
        return ERR(TE_NoSynchronousIo, status);
    }
    if (!NT_SUCCESS(status))
    {
		return ERR(TE_CancelSynchronousIo, status);
    }
	return OK;
}

extern "C" {
#include "ProcessHacker/clrsup.h"
}

QString GetClrThreadAppDomainImpl(quint64 ProcessId, quint64 ThreadId)
{
	QString AppDomain;
	PCLR_PROCESS_SUPPORT support = CreateClrProcessSupport((HANDLE)ProcessId);
	if (support)
	{
		IXCLRDataTask *task;
		if (SUCCEEDED(IXCLRDataProcess_GetTaskByOSThreadID(support->DataProcess, ThreadId, &task)))
		{
			IXCLRDataAppDomain *appDomain;
			if (SUCCEEDED(IXCLRDataTask_GetCurrentAppDomain(task, &appDomain)))
			{
				AppDomain = CastPhString(GetNameXClrDataAppDomain(appDomain));

				IXCLRDataAppDomain_Release(appDomain);
			}

			IXCLRDataTask_Release(task);
		}

		FreeClrProcessSupport(support);
	}
	return AppDomain;
}

QString SvcGetClrThreadAppDomain(const QVariantMap& Parameters)
{
	return GetClrThreadAppDomainImpl(Parameters["ProcessId"].toULongLong(), Parameters["ThreadId"].toULongLong());
}

QString GetClrThreadAppDomain(quint64 ProcessId, quint64 ThreadId)
{
	/*BOOLEAN isDotNet;
	if (!NT_SUCCESS(PhGetProcessIsDotNet((HANDLE)ProcessId, &isDotNet)) || !isDotNet)
		return "";*/

#ifdef _WIN64
	BOOLEAN IsWow64 = FALSE;

    HANDLE processHandle;
    if (NT_SUCCESS(PhOpenProcess(&processHandle, PROCESS_QUERY_LIMITED_INFORMATION, (HANDLE)ProcessId)))
    {
        PhGetProcessIsWow64(processHandle, &IsWow64);
        NtClose(processHandle);
    }

    if (IsWow64)
    {
		QString SocketName = CTaskService::RunWorker(false, true);

		if (!SocketName.isEmpty())
		{
			QVariantMap Parameters;
			Parameters["ProcessId"] = ProcessId;
			Parameters["ThreadId"] = ThreadId;

			QVariantMap Request;
			Request["Command"] = "GetClrThreadAppDomain";
			Request["Parameters"] = Parameters;

			QVariant Response = CTaskService::SendCommand(SocketName, Request);

			if (Response.type() == QVariant::String)
				return Response.toString();
		}
		return "";
    }
#endif
	return GetClrThreadAppDomainImpl(ProcessId, ThreadId);
}

QString CWinThread::GetAppDomain() const
{
	QReadLocker Locker(&m_Mutex);
	if (!m_AppDomain.isNull())
		return m_AppDomain;
	Locker.unlock();

	((CWinThread*)this)->SetAppDomain("");
	QTimer::singleShot(0, this, SLOT(UpdateAppDomain()));
	return "";
}

void CWinThread::UpdateAppDomain()
{
	BOOLEAN isDotNet;
	if (!NT_SUCCESS(PhGetProcessIsDotNet((HANDLE)m_ProcessId, &isDotNet)) || !isDotNet)
		return; // nothign to do here

	QFutureWatcher<QString>* pWatcher = new QFutureWatcher<QString>(this);
	QObject::connect(pWatcher, SIGNAL(resultReadyAt(int)), this, SLOT(OnAppDomain(int)));
	QObject::connect(pWatcher, SIGNAL(finished()), pWatcher, SLOT(deleteLater()));
	quint64 ThreadId = m_ThreadId;
	quint64 ProcessId= m_ProcessId;
	pWatcher->setFuture(QtConcurrent::run([ProcessId, ThreadId]() {
		return GetClrThreadAppDomain(ProcessId, ThreadId);
	}));
}

void CWinThread::OnAppDomain(int Index)
{
	QFutureWatcher<QString>* pWatcher = (QFutureWatcher<QString>*)sender();
	if (pWatcher)
		SetAppDomain(pWatcher->resultAt(Index));
}

static NTSTATUS NTAPI CWinThread_OpenThreadPermissions(_Out_ PHANDLE Handle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ PVOID Context)
{
    return PhOpenThread(Handle, DesiredAccess, (HANDLE)Context);
}

CTokenInfoPtr CWinThread::GetToken() const
{
	return CTokenInfoPtr(CWinToken::TokenFromThread(GetSystem(), m_ThreadId));
}

CTokenInfoPtr CWinThread::GetOriginalToken() const
{
	return CTokenInfoPtr(CWinToken::OriginalToken(GetSystem(), m_ProcessId, m_ThreadId));
}

CSecurityEditablePtr CWinThread::GetSecurityObject() const
{
	return CSecurityEditablePtr(new CWinSecurityObject(
		QString(), "Thread",
		(CWinSecurityObject::POpenObject)CWinThread_OpenThreadPermissions, GetThreadId(), GetThreadId()));
}

extern "C" PPH_STRING PhGetSystemCallNumberName(_In_ USHORT SystemCallNumber);

//
// phlib's apartment numbering happens to match ours, but it is its own
// constant set rather than a platform ABI, so it is mapped rather than passed
// through.
//
int CWinThread::GetApartmentType() const
{
	QReadLocker Locker(&m_Mutex);

	switch (m->ApartmentInfo.Type)
	{
	case PH_APARTMENT_TYPE_STA:				return eApartmentSta;
	case PH_APARTMENT_TYPE_MAIN_STA:		return eApartmentMainSta;
	case PH_APARTMENT_TYPE_APPLICATION_STA:	return eApartmentApplicationSta;
	case PH_APARTMENT_TYPE_MTA:				return eApartmentMta;
	case PH_APARTMENT_TYPE_IMPLICIT_MTA:	return eApartmentImplicitMta;
	}
	return eApartmentNone;
}

bool CWinThread::IsInNeutralApartment() const
{
	QReadLocker Locker(&m_Mutex);
	return m->ApartmentInfo.InNeutral != 0;
}

quint32 CWinThread::GetComInitCount() const
{
	QReadLocker Locker(&m_Mutex);
	return m->ApartmentInfo.ComInits;
}

quint32 CWinThread::GetApartmentFlags() const
{
	QReadLocker Locker(&m_Mutex);

	static_assert(eOleLocalTid                 == OLETLS_LOCALTID,                  "ole local tid");
	static_assert(eOleUuidInitialized          == OLETLS_UUIDINITIALIZED,           "ole uuid initialized");
	static_assert(eOleInThreadDetach           == OLETLS_INTHREADDETACH,            "ole in thread detach");
	static_assert(eOleChannelThreadInitialized == OLETLS_CHANNELTHREADINITIALZED,   "ole channel thread initialized");
	static_assert(eOleWowThread                == OLETLS_WOWTHREAD,                 "ole wow thread");
	static_assert(eOleThreadUninitializing     == OLETLS_THREADUNINITIALIZING,      "ole thread uninitializing");
	static_assert(eOleDisableOle1Dde           == OLETLS_DISABLE_OLE1DDE,           "ole disable ole1dde");
	static_assert(eOleApartmentThreaded        == OLETLS_APARTMENTTHREADED,         "ole apartment threaded");
	static_assert(eOleMultiThreaded            == OLETLS_MULTITHREADED,             "ole multi threaded");
	static_assert(eOleImpersonating            == OLETLS_IMPERSONATING,             "ole impersonating");
	static_assert(eOleDisableEventLogger       == OLETLS_DISABLE_EVENTLOGGER,       "ole disable eventlogger");
	static_assert(eOleInNeutralApt             == OLETLS_INNEUTRALAPT,              "ole in neutral apt");
	static_assert(eOleDispatchThread           == OLETLS_DISPATCHTHREAD,            "ole dispatch thread");
	static_assert(eOleHostThread               == OLETLS_HOSTTHREAD,                "ole host thread");
	static_assert(eOleAllowCoInit              == OLETLS_ALLOWCOINIT,               "ole allow coinit");
	static_assert(eOlePendingUninit            == OLETLS_PENDINGUNINIT,             "ole pending uninit");
	static_assert(eOleFirstMtaInit             == OLETLS_FIRSTMTAINIT,              "ole first mta init");
	static_assert(eOleFirstNtaInit             == OLETLS_FIRSTNTAINIT,              "ole first nta init");
	static_assert(eOleAptInitializing          == OLETLS_APTINITIALIZING,           "ole apt initializing");
	static_assert(eOleUiMsgsInModalLoop        == OLETLS_UIMSGSINMODALLOOP,         "ole ui msgs in modal loop");
	static_assert(eOleMarshalingErrorObject    == OLETLS_MARSHALING_ERROR_OBJECT,   "ole marshaling error object");
	static_assert(eOleWinRtInitialize          == OLETLS_WINRT_INITIALIZE,          "ole winrt initialize");
	static_assert(eOleApplicationSta           == OLETLS_APPLICATION_STA,           "ole application sta");
	static_assert(eOleInShutdownCallbacks      == OLETLS_IN_SHUTDOWN_CALLBACKS,     "ole in shutdown callbacks");
	static_assert(eOlePointerInputBlocked      == OLETLS_POINTER_INPUT_BLOCKED,     "ole pointer input blocked");
	static_assert(eOleInActivationFilter       == OLETLS_IN_ACTIVATION_FILTER,      "ole in activation filter");
	static_assert(eOleAstaToAstaExemptQuirk    == OLETLS_ASTATOASTAEXEMPT_QUIRK,    "ole asta exempt quirk");
	static_assert(eOleAstaToAstaExemptProxy    == OLETLS_ASTATOASTAEXEMPT_PROXY,    "ole asta exempt proxy");
	static_assert(eOleAstaToAstaExemptIndoubt  == OLETLS_ASTATOASTAEXEMPT_INDOUBT,  "ole asta exempt indoubt");
	static_assert(eOleDetectedUserInitialized  == OLETLS_DETECTED_USER_INITIALIZED, "ole detected user initialized");
	static_assert(eOleBridgeSta                == OLETLS_BRIDGE_STA,                "ole bridge sta");
	static_assert(eOleNaInitializing           == OLETLS_NAINITIALIZING,            "ole na initializing");

	return m->ApartmentInfo.Flags;
}

//
// A thread created in a frozen process that has not run yet answers "success"
// with nothing in it, which is not the same as having made a call.
//
bool CWinThread::HasLastSysCall() const
{
	QReadLocker Locker(&m_Mutex);

	if (!NT_SUCCESS(m->LastSystemCallStatus))
		return false;

	return m->LastSystemCall.SystemCallNumber != 0 || m->LastSystemCall.FirstArgument != NULL;
}

quint32 CWinThread::GetLastSysCallNumber() const
{
	QReadLocker Locker(&m_Mutex);
	return m->LastSystemCall.SystemCallNumber;
}

QString CWinThread::GetLastSysCallName() const
{
	QReadLocker Locker(&m_Mutex);

	PPH_STRING systemCallName = PhGetSystemCallNumberName(m->LastSystemCall.SystemCallNumber);
	return systemCallName ? CastPhString(systemCallName) : QString();
}

quint64 CWinThread::GetLastSysCallArgument() const
{
	QReadLocker Locker(&m_Mutex);
	return (quint64)m->LastSystemCall.FirstArgument;
}

//
// The wait time only exists from Windows 8 on; older versions leave the field
// undefined rather than zero, so it is not reported at all there.
//
quint64 CWinThread::GetLastSysCallWaitTime() const
{
	if (WindowsVersion < WINDOWS_8)
		return 0;

	QReadLocker Locker(&m_Mutex);

	// The kernel counts in 100ns units.
	return m->LastSystemCall.WaitTime / 10000;
}

//
// The thread-state and wait-reason numbering CThreadInfo names is the kernel's
// own; the viewer's tables are indexed by it, so a drift here would rename
// every state at once.
//
static_assert(CThreadInfo::eThreadInitialized == Initialized,          "thread state initialized");
static_assert(CThreadInfo::eThreadWaiting     == Waiting,              "thread state waiting");
static_assert(CThreadInfo::eThreadStateCount  == MaximumThreadState,   "thread state count");
static_assert(CThreadInfo::eWaitExecutive     == Executive,            "wait reason executive");
static_assert(CThreadInfo::eWaitSuspended     == Suspended,            "wait reason suspended");
static_assert(CThreadInfo::eWaitReasonCount   == MaximumWaitReason,    "wait reason count");

//
// A thread whose status could not be read, and one whose last call succeeded,
// both have nothing to report - and neither is an error worth showing.
//
bool CWinThread::HasLastStatus() const
{
	return NT_SUCCESS(m->LastStatusQueryStatus) && m->LastStatusValue != STATUS_SUCCESS;
}

quint32 CWinThread::GetLastStatusValue() const
{
	return (quint32)m->LastStatusValue;
}

QString CWinThread::GetLastStatusMessage() const
{
	PPH_STRING errorMessage = PhGetStatusMessage(m->LastStatusValue, 0);
	return errorMessage ? CastPhString(errorMessage) : QString();
}

//
// Only meaningful for a thread waiting on Suspended; anything else has no
// suspend count to give.
//
quint32 CWinThread::GetSuspendCount() const
{
	QReadLocker Locker(&m_Mutex);

	ULONG suspendCount = 0;
	if (m->ThreadHandle && NT_SUCCESS(PhGetThreadSuspendCount(m->ThreadHandle, &suspendCount)))
		return suspendCount;
	return 0;
}

quint64 CWinThread::GetLXSSThreadId() const 
{ 
	QReadLocker Locker(&m_Mutex); 
	return m->LxssThreadId; 
}