/*
 * Copyright (c) 2025 David Xanatos, xanasoft.com  All rights reserved.
 *
 * This file is part of KTaskExplorer.
 *
 * Authors:
 *
 *     Asynchronous Process Verification Queue Implementation
 *
 */

#include <kph.h>

#include <trace.h>

#ifdef IS_KTE

#define KTE_VERIFY_TIMEOUT_MS 1000 // 1 second timeout to avoid blocking OB callbacks

typedef struct _KTE_VERIFY_WORK_ITEM
{
    LIST_ENTRY ListEntry;
    volatile LONG Canceled;
    PEPROCESS EProcess;
    PKPH_PROCESS_CONTEXT Process;
    volatile LONG ReferenceCount;
    KEVENT CompletionEvent;
} KTE_VERIFY_WORK_ITEM, *PKTE_VERIFY_WORK_ITEM;


static LIST_ENTRY KtepVerifyWorkQueue;
static KSPIN_LOCK KtepVerifyWorkQueueLock;
static BOOLEAN KtepVerifyQueueInitialized = 0;
static PAGED_LOOKASIDE_LIST KtepVerifyWorkItemLookaside = { 0 };

KPH_PAGED_FILE();

/**
 * \brief Initializes the verification queue infrastructure.
 *
 * \return Successful or errant status.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KteInitializeVerificationQueue(
    VOID
    )
{
    KPH_PAGED_CODE_PASSIVE();

    NT_ASSERT(!KtepVerifyQueueInitialized);

    KphInitializePagedLookaside(&KtepVerifyWorkItemLookaside,
        sizeof(KTE_VERIFY_WORK_ITEM),
        KPH_TAG_VERIFY_WORK_ITEM);

    InitializeListHead(&KtepVerifyWorkQueue);
    KeInitializeSpinLock(&KtepVerifyWorkQueueLock);

    KtepVerifyQueueInitialized = TRUE;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KtepDereferenceVerificationItem(
    PKTE_VERIFY_WORK_ITEM workItem
    )
{
    if(InterlockedDecrement(&workItem->ReferenceCount) == 0)
    {
#ifdef KERNEL_DEBUG
        DbgPrintEx(DPFLTR_DEFAULT_ID, 0xFFFFFFFF, "BAM KtepDereferenceVerificationItem for process %s\n", PsGetProcessImageFileName(workItem->EProcess));
#endif

        ObDereferenceObject(workItem->EProcess);
        if (workItem->Process)
        {
            KphDereferenceObject(workItem->Process);
        }

        KphFreeToPagedLookaside(&KtepVerifyWorkItemLookaside, workItem);
    }
}

/**
 * \brief Cleans up the verification queue infrastructure.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KteCleanupVerificationQueue(
    VOID
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PKTE_VERIFY_WORK_ITEM workItem;

    KPH_PAGED_CODE_PASSIVE();

    if (!KtepVerifyQueueInitialized)
    {
        return;
    }

    KeAcquireSpinLock(&KtepVerifyWorkQueueLock, &oldIrql);

    while (!IsListEmpty(&KtepVerifyWorkQueue))
    {
        entry = RemoveHeadList(&KtepVerifyWorkQueue);
        workItem = CONTAINING_RECORD(entry, KTE_VERIFY_WORK_ITEM, ListEntry);
        KtepDereferenceVerificationItem(workItem);
    }

    KeReleaseSpinLock(&KtepVerifyWorkQueueLock, oldIrql);

    KphDeletePagedLookaside(&KtepVerifyWorkItemLookaside);

    KtepVerifyQueueInitialized = FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KtepProcessVerificationItem(
    PKTE_VERIFY_WORK_ITEM workItem
)
{
    if(!workItem->Process)
    {
        //
        // No existing process context, track it now, this may return an already tracked process
        //
        workItem->Process = KphTrackProcessContext(workItem->EProcess);
    }

    if(!workItem->Process)
    {
        KphTracePrint(TRACE_LEVEL_WARNING,
            PROTECTION,
            "Failed to track process context for EPROCESS %p",
            workItem->EProcess);
        
        KeSetEvent(&workItem->CompletionEvent, IO_NO_INCREMENT, FALSE);
        return;
    }

    if (!workItem->Process->DecidedOnProtection)
    {
        KphVerifyProcessAndProtectIfAppropriate(workItem->Process);
    }

    if(workItem->Canceled)
    {
        workItem->Process->VerifyTimeout = TRUE;
    }

    KeSetEvent(&workItem->CompletionEvent, IO_NO_INCREMENT, FALSE);
}


/**
 * \brief Processes verification work items from the queue.
 *
 * \details Called by the worker thread to process pending verification requests.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KteProcessVerificationQueue(
    VOID
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PKTE_VERIFY_WORK_ITEM workItem;

    KPH_PAGED_CODE_PASSIVE();

    if (!KtepVerifyQueueInitialized)
    {
        return;
    }

    //
    // Process all work items outside the lock
    //

    KeAcquireSpinLock(&KtepVerifyWorkQueueLock, &oldIrql);

    while (!IsListEmpty(&KtepVerifyWorkQueue))
    {
        entry = RemoveHeadList(&KtepVerifyWorkQueue);
        workItem = CONTAINING_RECORD(entry, KTE_VERIFY_WORK_ITEM, ListEntry);

        KeReleaseSpinLock(&KtepVerifyWorkQueueLock, oldIrql);

        KtepProcessVerificationItem(workItem);
        KtepDereferenceVerificationItem(workItem);

        KeAcquireSpinLock(&KtepVerifyWorkQueueLock, &oldIrql);
    }

    KeReleaseSpinLock(&KtepVerifyWorkQueueLock, oldIrql);
}

/**
 * \brief Queues a process for asynchronous tracking and verification.
 *
 * \param[in] EProcess The process object to track and verify. This function
 * takes a reference on the EPROCESS and transfers ownership to the worker thread.
 * The caller does not need to reference the object before calling.
 *
 * \param[out] Process Optional. On success (not timeout), receives a referenced
 * process context that the caller must dereference. On timeout, set to NULL.
 *
 * \return Successful or errant status. Returns STATUS_TIMEOUT if verification
 * could not complete within the timeout period.
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS KteQueueProcessVerification(
    _In_ PEPROCESS EProcess,
    _Out_opt_ PKPH_PROCESS_CONTEXT* Process
    )
{
    NTSTATUS status;
    PKTE_VERIFY_WORK_ITEM workItem;
    KIRQL oldIrql;
    LARGE_INTEGER timeout;

    KPH_PAGED_CODE();

    if (!KtepVerifyQueueInitialized)
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      PROTECTION,
                      "Verification queue not initialized");
        return STATUS_UNSUCCESSFUL;
    }

    workItem = KphAllocateFromPagedLookaside(&KtepVerifyWorkItemLookaside);
    if (!workItem)
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      PROTECTION,
                      "Failed to allocate work item for EPROCESS %p (%lu)",
                      EProcess,
                      HandleToULong(PsGetProcessId(EProcess)));

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize work item
    //
    RtlZeroMemory(workItem, sizeof(*workItem));
    workItem->EProcess = EProcess;
    ObReferenceObject(EProcess);
    if (Process && *Process) // transfer ownership to work item
    {
        workItem->Process = *Process;
        *Process = NULL;
    }
    workItem->ReferenceCount = 2; // one for queue, one for caller wait
    KeInitializeEvent(&workItem->CompletionEvent, NotificationEvent, FALSE);

    //
    // Enqueue the work item
    //
    KeAcquireSpinLock(&KtepVerifyWorkQueueLock, &oldIrql);
    InsertTailList(&KtepVerifyWorkQueue, &workItem->ListEntry);
    KeReleaseSpinLock(&KtepVerifyWorkQueueLock, oldIrql);

    //
    // Trigger the worker thread to process the queue
    //
    KteTriggerWorkerThread();

    KphTracePrint(TRACE_LEVEL_VERBOSE,
                  PROTECTION,
                  "Queued verification for EPROCESS %p (%lu)",
                  EProcess,
                  HandleToULong(PsGetProcessId(EProcess)));

    //
    // Wait for completion or timeout
    //
    timeout.QuadPart = -((LONGLONG)KTE_VERIFY_TIMEOUT_MS * 10000LL);
    status = KeWaitForSingleObject(&workItem->CompletionEvent,
                                   Executive,
                                   KernelMode,
                                   FALSE,
                                   &timeout);

    if (status == STATUS_TIMEOUT)
    {
        //
        // Timeout occurred
        //

        KphTracePrint(TRACE_LEVEL_WARNING,
            PROTECTION,
            "Verification timeout for EPROCESS %p (%lu)",
            EProcess,
            HandleToULong(PsGetProcessId(EProcess)));

        InterlockedExchange(&workItem->Canceled, 1);
    }
    else
    {
        //
        // Verification completed
        //

        KphTracePrint(TRACE_LEVEL_VERBOSE,
            PROTECTION,
            "Verification completed for EPROCESS %p (%lu)",
            EProcess,
            HandleToULong(PsGetProcessId(EProcess)));

        if (Process) // transfer ownership back to caller
        {
            *Process = workItem->Process;
            workItem->Process = NULL;
        }
    }

    KtepDereferenceVerificationItem(workItem);
    
    return status;
}

#endif // IS_KTE
