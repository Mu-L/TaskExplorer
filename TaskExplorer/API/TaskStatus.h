#pragma once
#include "../taskcore_global.h"
#include "../../MiscHelpers/Common/Status.h"	// CStatus, STATUS_CODE and the ERROR_* natives

//
// What went wrong, as a code the viewer turns into a sentence.
//
// The core does not build error text. It cannot: the machine that fails is
// not necessarily the machine someone is reading, and a daemon has no locale
// worth speaking in. So it names the failure and supplies the values that go
// into it, and GUI/TaskStrings.cpp writes the sentence.
//
// Codes are part of the protocol: append, never renumber.
//
enum ETaskMsgCode
{
	//
	// The platform said something only it could say - a native status and the
	// wording that goes with it. Args[0] carries that wording, already in the
	// target's language, because nothing else can produce it.
	//
	TE_Generic = STATUS_CODE('TE', 1),

	// the target has no answer for this at all
	TE_NotSupported,

	//
	// A sentence the viewer wrote itself, carried so it can travel the same
	// path as everything else. Args[0] is the whole message. Nothing in the
	// core may use this - it would be a string crossing the wire.
	//
	TE_Message,

	TE_NoFileName,                    // No file name is available for this object.
	TE_NoProcSelected,                // No process selected.
	TE_CreatingCoreDump,              // Creating a core dump is not supported on this architecture.
	TE_CannotDumpSelf,                // TaskExplorer cannot dump its own process.
	TE_ProcExited,                    // The process has exited.
	TE_KernelThreadNoAddrSpace,       // Kernel threads have no user address space to dump.
	TE_Only64BitCoreDump,             // This is a 32-bit process; only 64-bit core dumps are supported.
	TE_CannotWrite,                   // Cannot write to %1: %2
	TE_ClosingFileDesc,               // Closing a file descriptor of another process is not supported on Linux.
	TE_NoTerminalEmulator,            // No terminal emulator could be started. Looked for: %1.
	TE_RestartElevatedWayland,        // Cannot restart elevated under a Wayland session: a compositor does not accept connect...
	TE_RestartElevatedNoDisplay,      // Cannot restart elevated: no X display is available.
	TE_RestartElevatedStarted,        // Cannot restart elevated: %1 could not be started.
	TE_RestartElevatedNoGraphical,    // Cannot restart elevated: no graphical privilege escalation helper was found. Install ...
	TE_ChangingMemoryProtection,      // Changing memory protection of another process is not supported on Linux.
	TE_NoOutputFile,                  // No output file.
	TE_OpenProcMemory,                // Failed to open process memory. This usually means ptrace access was denied; see /proc...
	TE_WriteDumpFile,                 // Failed to write the dump file.
	TE_ReadProcMemory,                // Failed to read process memory.
	TE_FreeingMemoryProc,             // Freeing memory of another process is not supported on Linux.
	TE_UnloadingModuleRunning,        // Unloading a module from a running process is not supported on Linux.
	TE_CannotDebugSelf,               // TaskExplorer cannot debug itself.
	TE_ProcAlreadyTraced,             // This process is already being traced.
	TE_NoDebuggerInstalled,           // No debugger is installed. Install gdb or lldb.
	TE_ProcTraced,                    // This process is not being traced.
	TE_DebuggerItselfDetach,          // Only the debugger itself can detach. This process is being traced by %1 (pid %2); qui...
	TE_PriorityBoostUnsupported,      // Priority boost is not supported on Linux.
	TE_SettingSchedulingPolicy,       // Setting the scheduling policy is not supported; use chrt(1).
	TE_PagePriorityUnsupported,       // Page priority is not supported on Linux.
	TE_OomAdjustmentRange,            // The OOM adjustment must be between -1000 and 1000.
	TE_LoweringOomAdjustment,         // Lowering the OOM adjustment requires root (CAP_SYS_RESOURCE).
	TE_AffinityMaskEmpty,             // The affinity mask must select at least one CPU.
	TE_EditingEnvironmentRunning,     // Editing the environment of a running process is not supported on Linux.
	TE_FlushingHeapsUnsupported,      // Flushing heaps is not supported on Linux.
	TE_ExecutablePathProc,            // The executable path of this process is not readable.
	TE_LoadingModuleRunning,          // Loading a module into a running process is not yet implemented on Linux.
	TE_AuthorisedNoInteractive,       // Not authorised to %1 %2, and no interactive authentication agent is available. Run Ta...
	TE_NotAuthorised,                 // Not authorised to %1 %2.
	TE_UnitNoLonger,                  // The unit %1 no longer exists.
	TE_UnitMaskedStarted,             // The unit %1 is masked and cannot be started.
	TE_OperationUnsupportedRunning,   // This operation is not supported by the running version of systemd.
	TE_TimedWaitingSystemd,           // Timed out waiting for systemd to %1 %2.
	TE_UnitActionFailed,              // Failed to %1 %2: %3
	TE_ConnectSystemBus,              // Cannot connect to the system bus.
	TE_JournalctlFoundSystem,         // journalctl was not found; this system does not use the systemd journal.
	TE_DeletingSystemdUnit,           // Deleting a systemd unit is not supported: the unit file usually belongs to a distribu...
	TE_ClosingSocketYet,              // Closing a socket is not yet implemented on Linux.
	TE_TerminatingIndividualThread,   // Terminating an individual thread is not supported on Linux.
	TE_SuspendingIndividualThread,    // Suspending an individual thread is not supported on Linux.
	TE_ResumingIndividualThread,      // Resuming an individual thread is not supported on Linux.
	TE_ChangeWindowVisibility,        // Failed to change the window visibility.
	TE_EnablingDisablingWindow,       // Enabling or disabling a window is not supported on X11.
	TE_ChangeAlwaysTop,               // Failed to change the always-on-top state.
	TE_SetWindowOpacity,              // Failed to set the window opacity.
	TE_ActivateWindow,                // Failed to activate the window.
	TE_HighlightWindow,               // Failed to highlight the window.
	TE_RestoreWindow,                 // Failed to restore the window.
	TE_MinimizeWindow,                // Failed to minimize the window.
	TE_MaximizeWindow,                // Failed to maximize the window.
	TE_CloseWindow,                   // Failed to close the window.
	TE_ReadMemoryProc,                // Cannot read memory of process %1
	TE_KernelDriverFile,              // The kernel driver file '%1' was not found.
	TE_AccessKernelDriver,            // Unable to access the kernel driver, Error: %1
	TE_MemoryOperation,               // Memory operation failed.
	TE_KernelDriverConnected,         // The kernel driver is not connected.
	TE_DeleteAtom,                    // Failed to delete atom
	TE_OpenProc2,                     // Unable to open the process.
	TE_AccessDumpFile,                // Unable to access the dump file
	TE_KProcessHackerUnavail,         // KProcessHacker is not available
	TE_SetHandleAttribute,            // Failed to set handle attribute
	TE_ConfirmCloseCriticalHandle,    // You are about to close one or more handles for a critical process with strict handle ...
	TE_CloseHandle,                   // Failed To close Handle
	TE_OpenProcHandle,                // Unable to open process handle
	TE_OpenDuplicateHandle,           // Unable to open duplicate handle
	TE_OpenJob,                       // Failed to open job
	TE_TerminateJob,                  // Failed to terminate job
	TE_JobFreezeUnavail,              // Job freezing is only available on windows 8 and later
	TE_UnFreezeJob,                   // Failed to (un)freeze job
	TE_AddProcJob,                    // Unable to add the process to the job
	TE_ChangeMemoryProtection,        // Unable to change memory protection
	TE_NotDumpableMemory,             // Not dumpable memory item
	TE_ConfirmUnloadModule,           // Unloading a module may cause the process to crash.
	TE_FindModuleUnload,              // Unable to find the module to unload.
	TE_UnloadModule,                  // Unable to unload the module.
	TE_ConfirmUnloadDriver,           // Unloading a driver may cause system instability.
	TE_UnloadDriver,                  // Unable to unload driver.
	TE_ConfirmUnmapSection,           // Unmapping a section view may cause the process to crash.
	TE_UnmapSectionView,              // Unable to unmap the section view at 0x%1
	TE_UnknownModuleType,             // Unknown module type!
	TE_SetProcExecution,              // Failed to set Process execution required
	TE_EnableWorkingSet,              // Unable to enable working set watch.
	TE_ReadWorkingSet,                // Failed to read working set watch data.
	TE_ConfirmEditEnvSuspended,       // Editing environment variable(s) of suspended processes is not supported.
	TE_SetEnvironmentVariable,        // Unable to set the environment variable.
	TE_DeleteEnvironmentVariable,     // Unable to delete the environment variable.
	TE_LocateDebugger,                // Unable to locate the debugger.
	TE_CreateDebuggerProc,            // Failed to create debugger process
	TE_ProcDebugged,                  // The process is not being debugged.
	TE_DetachDebugger,                // Failed to detach debugger
	TE_DriverFeatureUnsupported,      // The loaded driver does not support this feature.
	TE_ClientNotVerified,             // The client must be verifyed by the driver in order to unlock this feature.
	TE_ConfirmChangeProtection,       // Changing Process Protection Flags may impact system stability!
	TE_ClearProcProtection,           // Failed to Clear Process Protection flag
	TE_SetProcPriorityBoost,          // Failed to set Process priority boost
	TE_SetProcEfficiency,             // Failed to set Process efficiency
	TE_SetProcPriority,               // Failed to set Process priority
	TE_SetPagePriority,               // Failed to set Page priority
	TE_SetIoPriority,                 // Failed to set I/O priority
	TE_SetCpuAffinity,                // Failed to set CPU affinity
	TE_ConfirmTerminateCriticalProc,  // You are about to terminate one or more critical processes. This will shut down the op...
	TE_TerminateProc,                 // Failed to terminate process
	TE_SuspendProc,                   // Failed to suspend process
	TE_ResumeProc,                    // Failed to resume process
	TE_ProcAlreadyFrozen,             // Process already frozen
	TE_FreezeProc,                    // Failed to freeze process
	TE_ProcFrozen,                    // Process is not frozen
	TE_UnFreezeProc,                  // Failed to un-freeze process
	TE_ConfirmCriticalProcShutdown,   // If the process ends, the operating system will shut down immediately.
	TE_ChangeProcCritical,            // Unable to change the process critical status.
	TE_ReduceWorkingSet,              // Unable to reduce the working set of a process
	TE_LoadDllInto,                   // load the DLL into
	TE_FlushHeaps,                    // Failed Flush Heaps
	TE_NoProgramGiven,                // No program was given.
	TE_ObjectExposeSecurity,          // This object does not expose its security descriptor.
	TE_ChangingSecuritySam,           // Changing the security of a SAM account is not implemented.
	TE_BuildSecurityDesc,             // Failed to build a security descriptor.
	TE_AccountNotResolved,            // One of the entries names an account that could not be resolved.
	TE_ObjectAccessControl,           // This object has %1 access control entries of a kind this dialog does not understand, ...
	TE_NewOwnerResolved,              // The new owner could not be resolved.
	TE_ObjectAuditEntries,            // This object has %1 audit entries of a kind this dialog does not understand, and savin...
	TE_StartService,                  // Failed to start service
	TE_PauseService,                  // Failed to pause service
	TE_ContinueService,               // Failed to continue service
	TE_StopService,                   // Failed to stop service
	TE_ConfirmDeleteService,          // Deleting a service can prevent the system from starting or functioning properly.
	TE_DeleteService,                 // Failed to delete service
	TE_UnsupportedTypeState,          // Not supported type or state
	TE_SetThreadPriorityBoost,        // Failed to set Thread priority boost
	TE_SetThreadPriority,             // Failed to set Thread priority
	TE_ConfirmTerminateCriticalThread,// You are about to terminate one or more critical threads. This will shut down the oper...
	TE_TerminateThread,               // Failed to terminate thread
	TE_SuspendThread,                 // Failed to suspend thread
	TE_ResumeThread,                  // Failed to resume thread
	TE_ChangeThreadCritical,          // Unable to change the thread critical status.
	TE_NoSynchronousIo,               // There is no synchronous I/O to cancel.
	TE_CancelSynchronousIo,           // Unable to cancel synchronous I/O
	TE_SetProcVirtualization,         // Failed to set process virtualization
	TE_OpenToken,                     // Could not open token.
	TE_SetTokenInfo,                  // failed to Set Token Information
	TE_ConfirmRemovePrivileges,       // Removing privileges may reduce the functionality of the process, and is permanent for...
	TE_SetTokenPriv,                  // Unable to Set Token Privilege
	TE_SetTokenGroups,                // Unable to Set Token Groups
	TE_MatchStringMin2,               // Match String to short, min length 2
	TE_MatchStringMin4,               // Match String to short, min length 4
	TE_AllocationError,               // Allocation error
	TE_BackupService,                 // Unable to backup the service
	TE_ProcHackerKernel,              // The Process Hacker kernel driver '%1' was not found.
	TE_LoadKernelDriver,              // Unable to load the kernel driver, Error: 0x%1

	TE_UnsupportedWindowsVersion,     // This version of Windows is not supported.
	TE_DriverActivateFailed,          // Activating the kernel driver's dynamic data failed.
	TE_DriverNeedsAdmin,              // The kernel driver requires administrative rights.
	TE_DriverOnly64Bit,               // The kernel driver only supports 64-bit systems.
	TE_DriverNeedsReboot,             // The last driver update requires a reboot.
	TE_DriverConnectFailed,           // Connecting to the kernel driver failed.
	TE_DriverAccessDenied,            // Unable to access the kernel driver: %1.
	TE_RestartSelfFailed,             // Restarting TaskExplorer failed.
	TE_DriverServiceStopFailed,       // Stopping the kernel driver service failed.
	TE_DebugMonitorFailed,            // Debug output monitoring failed at %1.

	//
	// A memory dump reports its progress and its outcome through the same
	// channel as everything else, so a viewer watching a remote dump reads it
	// in its own language.
	//
	TE_DumpProcessingModule,          // Processing module %1...
	TE_DumpProcessingThread,          // Processing thread 0x%1...
	TE_DumpProcessingMemory,          // Processing memory regions
	TE_DumpProcessingKernel,          // Processing kernel minidump
	TE_DumpSuspendingThreads,         // Suspending threads...
	TE_DumpHelperSuspending,          // Asking the privileged helper to suspend threads...
	TE_DumpWritingMemory,             // Writing memory (%1 of %2)...

	TE_DumpHelper32Failed,            // Failed to start a 32-bit TaskHelper. A 64-bit dump will be created instead.
	TE_DumpHelper32Started,           // Started a 32-bit TaskHelper, to create a 32-bit dump file.
	TE_DumpHelper32Error,             // The 32-bit TaskHelper failed to create the memory dump, Error: %1 ...
	TE_DumpKernelNeedsAdmin,          // Unable to create kernel minidump. Kernel minidumps require administrative privileges.
	TE_DumpCompleted32,               // 32-bit memory dump completed.
	TE_DumpCompleted,                 // Memory dump completed.
	TE_DumpFailed,                    // Failed to create the dump.
	TE_DumpCanceled,                  // The dump was canceled.
	TE_DumpNoRegisterState,           // Could not stop the process (%1); the dump will have no register state.
	TE_DumpWriteFailed,               // Failed to write the dump: %1
	TE_CoreDumpCompleted,             // Core dump completed: %1 - with, optionally, what it is missing.

	//
	// What an errno failure was an attempt to do. ErrnoToStatus turns the errno
	// itself into Args[0] (the platform's own wording) and Args[1] (the number);
	// these say what was being attempted.
	//
	TE_SetProcessPriorityFailed,      // Failed to set process priority
	TE_SetThreadPriorityFailed,       // Failed to set thread priority
	TE_SetIoPriorityFailed,           // Failed to set the I/O priority
	TE_SetOomAdjustFailed,            // Failed to set the OOM adjustment
	TE_SetAffinityFailed,             // Failed to set the affinity mask
	TE_TerminateProcessFailed,        // Failed to terminate process
	TE_SuspendProcessFailed,          // Failed to suspend process
	TE_ResumeProcessFailed,           // Failed to resume process

	//
	// Stack traces, which fail in ways worth telling apart.
	//
	TE_HelperNotStarted,              // The TaskHelper process could not be started, so stacks cannot be unwound.
	TE_HelperNoAnswer,                // The TaskHelper process did not answer.
	TE_StackPtraceDenied,             // Cannot read this thread's stack: ptrace access was denied.
	TE_StackTraceFailed,              // Stack trace failed: %1
	TE_StackNoFrames,                 // No stack frames were returned.

	// Memory operations, which say which one was refused.
	TE_UnmapSectionViewFailed,        // Unable to unmap the section view
	TE_FreeMemoryFailed,              // Unable to free the memory region
	TE_DecommitMemoryFailed,          // Unable to decommit the memory region

	TE_KsiNotRunningForObject,        // The driver is not running and this object can only be reached through it.

	//
	// The user declined - a UAC prompt refused, an authentication dialog
	// dismissed. Not a fault, and the viewer usually wants to say nothing at
	// all rather than report it; it is a code so that it can tell the
	// difference without reading a native status.
	//
	TE_UserCanceled,                  // The operation was canceled.

	// TE_HelperNotStarted says the same thing about stack tracing specifically;
	// this is the general one, for any caller that needs the privileged helper.
	TE_HelperStartFailed,             // The privileged helper could not be started.

	//
	// The far side answered, but not as a TaskServer. Its own magic value was
	// missing or wrong, which means it is something else on that name entirely.
	//
	TE_NotATaskServer,                // The far side is not a TaskServer.
	//
	// It is one, but speaks a protocol this viewer does not. Both numbers are
	// carried so the message can say which is which rather than "incompatible".
	//
	TE_ProtocolMismatch,              // Protocol mismatch: the server speaks version %1, this viewer speaks version %2.

	//
	// The tunnel came up and the login did not. Separate from every transport
	// failure above, because the two mean opposite things to whoever is reading
	// it: the machine was reached, the transport key was right, and it is the
	// name or the password that is wrong.
	//
	// No reason is carried because the server sends none - "no such user" and
	// "wrong password" are one answer on the wire, so that a name list cannot be
	// enumerated by asking. %1 is how long until another attempt is allowed.
	//
	TE_LoginRefused,                  // The server refused the user name or password. Another attempt is allowed in %1 seconds.
	//
	// A server that will not say either way. An older one that has no login at
	// all lands here rather than being taken for a refusal.
	//
	TE_LoginNoAnswer,                 // The server did not answer the login.

	//
	// Setting up the server on this machine - see SVC/ServerSetup.h. Each of
	// these carries the platform’s own text as %1, because the useful half of
	// "the service could not be created" is the number the manager gave for it.
	//
	TE_ServerSetupNeedsAdmin,         // Setting up the server needs administrator rights.
	TE_ServerBinaryMissing,           // TaskServer was not found at %1.
	TE_ServerServiceFailed,           // The server could not be set up: %1
	TE_ServerKeyFileFailed,           // The key file could not be written: %1

	//
	// The store of saved connection keys - see SVC/CredentialStore.h.
	//
	// "Bad password" and "damaged" are separate codes but the store cannot
	// always tell them apart, and deliberately does not try: what distinguishes
	// them would be something checkable stored beside the key, and an attacker
	// gets to check it too.
	//
	//
	// The credential store's codes are MH_CredStore* now - it moved to
	// CoreHelpers and took them with it. Nothing is left here in their place:
	// a code is never renumbered, but these were never released under these
	// numbers either, and the whole range was rebased in the same change.
	//

	//
	// The far side answered and is not the machine this entry was saved for -
	// its id does not match the one learnt when the entry was made.
	//
	// The ids themselves are carried, but the sentence deliberately does not use
	// them: they are thirty-two hex characters that mean nothing to read, and
	// the one thing worth saying fits without them. Anything that wants to show
	// them - the dialog that offers to accept the new machine - takes them from
	// the arguments.
	//
	TE_MachineIdMismatch,             // The machine at %1 is not the one saved under this name.

	//
	// ---- acting on another machine ----
	//
	// The question never arrived, or no answer came back before the wait ran
	// out. Deliberately distinct from the action failing: "the machine did not
	// answer" and "the machine refused" send whoever reads it to two different
	// places, and a viewer that showed the second for the first would have
	// people looking at permissions when the network is down.
	//
	TE_MachineNoAnswer,               // The machine did not answer.

	//
	// The key completed the handshake and may watch, but may not change
	// anything. Said plainly rather than as a generic refusal, because it is
	// not a mistake - it is the key file doing what it was written to do, and
	// the fix is a line in that file rather than anything here.
	//
	TE_ActionNotPermitted,            // This connection may watch this machine but not change it.

	//
	// A verb the far side has never heard of, which is what an older server
	// looks like from a newer viewer. Named rather than folded into
	// TE_NotSupported: that one means "this target cannot do it", and this one
	// means "this server is older than you are".
	//
	TE_ActionUnknown,                 // The server does not know this action; it is probably older than this viewer.

	//
	// The key may act, but not on this: restarting a machine, ending somebody
	// else's session or starting a program on it are not anyone's own business,
	// and only an administrator key may ask.
	//
	// Separate from TE_ActionNotPermitted, which the machine verbs used to
	// share, because the two are fixed by different lines in the key file and a
	// message naming the wrong one sends the reader to the wrong place. The
	// distinction is a fact about the caller's own key and discloses nothing
	// about the machine - unlike the ownership rule, which stays deliberately
	// indistinguishable from "no such process".
	//
	TE_KeyNotAdmin,                   // This key is not an administrator of this machine.

	//
	// This build has no TaskRemote module, so it cannot connect to anything.
	//
	// Appended, like every code here: these are protocol. See the note at the
	// top - a viewer and a server of different vintages have to agree on what a
	// number means, so one is never reused and never renumbered.
	//
	TE_NoRemoteModule,                // This installation cannot connect to other machines.

	//
	// The operation exists and the caller is entitled to it, but not from where
	// it is asking. Reaching into another process's address space or code is
	// kept to somebody at the machine - see MayReachIntoProcess.
	//
	// Its own code rather than TE_ActionNotPermitted, which says the connection
	// may not act at all and sends the reader to the Actions line of the key
	// file. That would be the wrong place to look for this.
	//
	// Appended, like every code here: these are protocol.
	//
	TE_NotOverNetwork,                // This is only available to a viewer running on the machine itself.

	//
	// The module is there and answered, and refused: watching another machine is
	// a supporter feature and this installation has no certificate for it.
	//
	// Its own code rather than TE_NoRemoteModule, because "the module is
	// missing" and "the module will not do this" send whoever reads it to two
	// different places - one is a broken installation and the other is a page in
	// the settings window.
	//
	TE_NoCertificate,

	TE_LastMsgCode
};

//
// The words the platform has for a native failure, fetched on the machine that
// failed. Installed into CStatus at start-up; see CStatus::SetNativeFormatter.
//
TASKCORE_EXPORT QString FormatNativeStatus(long Status);

//
// Puts FormatNativeStatus behind CStatus::Native(). Called once, from
// CSystemAPI::InitLocalSystem.
//
TASKCORE_EXPORT void InstallNativeStatusFormatter();

//
// Tells CCredentialStore where this product keeps its keys. Called once, from
// CSystemAPI::InitLocalSystem, beside the formatter above.
//
TASKCORE_EXPORT void SetupCredentialStore();
