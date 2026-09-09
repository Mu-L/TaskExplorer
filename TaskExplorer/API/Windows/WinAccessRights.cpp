/*
 * The access rights each kind of Windows object understands.
 *
 * Restated from phlib/secdata.c so that the words are not baked in: the masks
 * keep the macro names the platform headers define - nothing here is a
 * transcribed number, so no constant can be silently wrong - and each entry
 * names its right with an EAccessRight rather than a string.
 *
 * The decomposition below is phlib's: sort the entries by how many bits they
 * cover, then take the widest ones that fit and suppress everything they
 * already imply, so FILE_GENERIC_READ is reported instead of the six bits it
 * stands for.
 */

#include "stdafx.h"
#include "WinAccessRights.h"
#include "ProcessHacker.h"
#include <wbemcli.h>
#include <wtsapi32.h>

#define ACCESS_ENTRIES(Type) static const SWinAccessEntry Win##Type##AccessEntries[] =
#define ACCESS_TYPE(Type, HasSynchronize) \
	{ L#Type, Win##Type##AccessEntries, RTL_NUMBER_OF(Win##Type##AccessEntries), HasSynchronize }


ACCESS_ENTRIES(Standard)
{
	{ eAccessSynchronize, SYNCHRONIZE, false, true },
	{ eAccessDelete, DELETE, false, true },
	{ eAccessReadPermissions, READ_CONTROL, false, true },
	{ eAccessChangePermissions, WRITE_DAC, false, true },
	{ eAccessTakeOwnership, WRITE_OWNER, false, true },
};

ACCESS_ENTRIES(AlpcPort)
{
	{ eAccessFullControl, PORT_ALL_ACCESS, true, true },
	{ eAccessConnect, PORT_CONNECT, true, true },
};

ACCESS_ENTRIES(DebugObject)
{
	{ eAccessFullControl, DEBUG_ALL_ACCESS, true, true },
	{ eAccessReadEvents, DEBUG_READ_EVENT, true, true },
	{ eAccessAssignProcesses, DEBUG_PROCESS_ASSIGN, true, true },
	{ eAccessQueryInformation, DEBUG_QUERY_INFORMATION, true, true },
	{ eAccessSetInformation, DEBUG_SET_INFORMATION, true, true },
};

ACCESS_ENTRIES(Desktop)
{
	{ eAccessFullControl, DESKTOP_ALL_ACCESS, true, true },
	{ eAccessRead, DESKTOP_GENERIC_READ, true, false },
	{ eAccessWrite, DESKTOP_GENERIC_WRITE, true, false },
	{ eAccessExecute, DESKTOP_GENERIC_EXECUTE, true, false },
	{ eAccessEnumerate, DESKTOP_ENUMERATE, false, true },
	{ eAccessReadObjects, DESKTOP_READOBJECTS, false, true },
	{ eAccessPlaybackJournals, DESKTOP_JOURNALPLAYBACK, false, true },
	{ eAccessWriteObjects, DESKTOP_WRITEOBJECTS, false, true },
	{ eAccessCreateWindows, DESKTOP_CREATEWINDOW, false, true },
	{ eAccessCreateMenus, DESKTOP_CREATEMENU, false, true },
	{ eAccessCreateWindowHooks, DESKTOP_HOOKCONTROL, false, true },
	{ eAccessRecordJournals, DESKTOP_JOURNALRECORD, false, true },
	{ eAccessSwitchDesktop, DESKTOP_SWITCHDESKTOP, false, true },
};

ACCESS_ENTRIES(Directory)
{
	{ eAccessFullControl, DIRECTORY_ALL_ACCESS, true, true },
	{ eAccessQuery, DIRECTORY_QUERY, true, true },
	{ eAccessTraverse, DIRECTORY_TRAVERSE, true, true },
	{ eAccessCreateObjects, DIRECTORY_CREATE_OBJECT, true, true },
	{ eAccessCreateSubdirectories, DIRECTORY_CREATE_SUBDIRECTORY, true, true },
};

ACCESS_ENTRIES(EtwConsumer)
{
	{ eAccessFullControl, WMIGUID_ALL_ACCESS, true, true },
	{ eAccessQuery, WMIGUID_QUERY, true, true },
	{ eAccessRead, WMIGUID_SET, true, true },
	{ eAccessNotification, WMIGUID_NOTIFICATION, true, true },
	{ eAccessReadDescription, WMIGUID_READ_DESCRIPTION, true, true },
	{ eAccessExecute, WMIGUID_EXECUTE, true, true },
	{ eAccessCreateRealtime, TRACELOG_CREATE_REALTIME, true, true },
	{ eAccessCreateLogfile, TRACELOG_CREATE_ONDISK, true, true },
	{ eAccessGUIDEnable, TRACELOG_GUID_ENABLE, true, true },
	{ eAccessAccessKernelLogger, TRACELOG_ACCESS_KERNEL_LOGGER, true, true },
	{ eAccessLogEvents, TRACELOG_LOG_EVENT, true, true },
	{ eAccessAccessRealtime, TRACELOG_ACCESS_REALTIME, true, true },
	{ eAccessRegisterGuids, TRACELOG_REGISTER_GUIDS, true, true },
	{ eAccessJoinGroup, TRACELOG_JOIN_GROUP, true, true },
};

ACCESS_ENTRIES(EtwRegistration)
{
	{ eAccessFullControl, WMIGUID_ALL_ACCESS, true, true },
	{ eAccessQuery, WMIGUID_QUERY, true, true },
	{ eAccessRead, WMIGUID_SET, true, true },
	{ eAccessNotification, WMIGUID_NOTIFICATION, true, true },
	{ eAccessReadDescription, WMIGUID_READ_DESCRIPTION, true, true },
	{ eAccessExecute, WMIGUID_EXECUTE, true, true },
	{ eAccessCreateRealtime, TRACELOG_CREATE_REALTIME, true, true },
	{ eAccessCreateLogfile, TRACELOG_CREATE_ONDISK, true, true },
	{ eAccessGUIDEnable, TRACELOG_GUID_ENABLE, true, true },
	{ eAccessAccessKernelLogger, TRACELOG_ACCESS_KERNEL_LOGGER, true, true },
	{ eAccessLogEvents, TRACELOG_LOG_EVENT, true, true },
	{ eAccessAccessRealtime, TRACELOG_ACCESS_REALTIME, true, true },
	{ eAccessRegisterGuids, TRACELOG_REGISTER_GUIDS, true, true },
	{ eAccessJoinGroup, TRACELOG_JOIN_GROUP, true, true },
};

ACCESS_ENTRIES(Event)
{
	{ eAccessFullControl, EVENT_ALL_ACCESS, true, true },
	{ eAccessQuery, EVENT_QUERY_STATE, true, true },
	{ eAccessModify, EVENT_MODIFY_STATE, true, true },
};

ACCESS_ENTRIES(EventPair)
{
	{ eAccessFullControl, EVENT_PAIR_ALL_ACCESS, true, true },
};

ACCESS_ENTRIES(File)
{
	{ eAccessFullControl, FILE_ALL_ACCESS, true, true },
	{ eAccessReadExecute, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, true, false },
	{ eAccessRead, FILE_GENERIC_READ, true, false },
	{ eAccessWrite, FILE_GENERIC_WRITE, true, false },
	{ eAccessTraverseFolderExecuteFile, FILE_EXECUTE, false, true },
	{ eAccessListFolderReadData, FILE_READ_DATA, false, true },
	{ eAccessReadAttributes, FILE_READ_ATTRIBUTES, false, true },
	{ eAccessReadExtendedAttributes, FILE_READ_EA, false, true },
	{ eAccessCreateFilesWriteData, FILE_WRITE_DATA, false, true },
	{ eAccessCreateFoldersAppendData, FILE_APPEND_DATA, false, true },
	{ eAccessWriteAttributes, FILE_WRITE_ATTRIBUTES, false, true },
	{ eAccessWriteExtendedAttributes, FILE_WRITE_EA, false, true },
	{ eAccessDeleteSubfoldersAndFiles, FILE_DELETE_CHILD, false, true },
};

ACCESS_ENTRIES(FilterConnectionPort)
{
	{ eAccessFullControl, FLT_PORT_ALL_ACCESS, true, true },
	{ eAccessConnect, FLT_PORT_CONNECT, true, true },
};

ACCESS_ENTRIES(IoCompletion)
{
	{ eAccessFullControl, IO_COMPLETION_ALL_ACCESS, true, true },
	{ eAccessQuery, IO_COMPLETION_QUERY_STATE, true, true },
	{ eAccessModify, IO_COMPLETION_MODIFY_STATE, true, true },
};

ACCESS_ENTRIES(Job)
{
	{ eAccessFullControl, JOB_OBJECT_ALL_ACCESS, true, true },
	{ eAccessQuery, JOB_OBJECT_QUERY, true, true },
	{ eAccessAssignProcesses, JOB_OBJECT_ASSIGN_PROCESS, true, true },
	{ eAccessSetAttributes, JOB_OBJECT_SET_ATTRIBUTES, true, true },
	{ eAccessSetSecurityAttributes, JOB_OBJECT_SET_SECURITY_ATTRIBUTES, true, true },
	{ eAccessTerminate, JOB_OBJECT_TERMINATE, true, true },
};

ACCESS_ENTRIES(Key)
{
	{ eAccessFullControl, KEY_ALL_ACCESS, true, true },
	{ eAccessRead, KEY_READ, true, false },
	{ eAccessWrite, KEY_WRITE, true, false },
	{ eAccessExecute, KEY_EXECUTE, true, false },
	{ eAccessEnumerateSubkeys, KEY_ENUMERATE_SUB_KEYS, false, true },
	{ eAccessQueryValues, KEY_QUERY_VALUE, false, true },
	{ eAccessNotify, KEY_NOTIFY, false, true },
	{ eAccessSetValues, KEY_SET_VALUE, false, true },
	{ eAccessCreateSubkeys, KEY_CREATE_SUB_KEY, false, true },
	{ eAccessCreateLinks, KEY_CREATE_LINK, false, true },
};

ACCESS_ENTRIES(KeyedEvent)
{
	{ eAccessFullControl, KEYEDEVENT_ALL_ACCESS, true, true },
	{ eAccessWait, KEYEDEVENT_WAIT, true, true },
	{ eAccessWake, KEYEDEVENT_WAKE, true, true },
};

ACCESS_ENTRIES(LsaAccount)
{
	{ eAccessFullControl, ACCOUNT_ALL_ACCESS, true, true },
	{ eAccessRead, ACCOUNT_READ, true, false },
	{ eAccessWrite, ACCOUNT_WRITE, true, false },
	{ eAccessExecute, ACCOUNT_EXECUTE, true, false },
	{ eAccessView, ACCOUNT_VIEW, false, true },
	{ eAccessAdjustPrivileges, ACCOUNT_ADJUST_PRIVILEGES, false, true },
	{ eAccessAdjustQuotas, ACCOUNT_ADJUST_QUOTAS, false, true },
	{ eAccessAdjustSystemAccess, ACCOUNT_ADJUST_SYSTEM_ACCESS, false, true },
};

ACCESS_ENTRIES(LsaPolicy)
{
	{ eAccessFullControl, POLICY_ALL_ACCESS | POLICY_NOTIFICATION, true, true },
	{ eAccessRead, POLICY_READ, true, false },
	{ eAccessWrite, POLICY_WRITE, true, false },
	{ eAccessExecute, POLICY_EXECUTE | POLICY_NOTIFICATION, true, false },
	{ eAccessViewLocalInformation, POLICY_VIEW_LOCAL_INFORMATION, false, true },
	{ eAccessViewAuditInformation, POLICY_VIEW_AUDIT_INFORMATION, false, true },
	{ eAccessGetPrivateInformation, POLICY_GET_PRIVATE_INFORMATION, false, true },
	{ eAccessAdministerTrust, POLICY_TRUST_ADMIN, false, true },
	{ eAccessCreateAccount, POLICY_CREATE_ACCOUNT, false, true },
	{ eAccessCreateSecret, POLICY_CREATE_SECRET, false, true },
	{ eAccessCreatePrivilege, POLICY_CREATE_PRIVILEGE, false, true },
	{ eAccessSetDefaultQuotaLimits, POLICY_SET_DEFAULT_QUOTA_LIMITS, false, true },
	{ eAccessSetAuditRequirements, POLICY_SET_AUDIT_REQUIREMENTS, false, true },
	{ eAccessAdministerAuditLog, POLICY_AUDIT_LOG_ADMIN, false, true },
	{ eAccessAdministerServer, POLICY_SERVER_ADMIN, false, true },
	{ eAccessLookupNames, POLICY_LOOKUP_NAMES, false, true },
	{ eAccessGetNotifications, POLICY_NOTIFICATION, false, true },
};

ACCESS_ENTRIES(LsaSecret)
{
	{ eAccessFullControl, SECRET_ALL_ACCESS, true, true },
	{ eAccessRead, SECRET_READ, true, false },
	{ eAccessWrite, SECRET_WRITE, true, false },
	{ eAccessExecute, SECRET_EXECUTE, true, false },
	{ eAccessSetValue, SECRET_SET_VALUE, false, true },
	{ eAccessQueryValue, SECRET_QUERY_VALUE, false, true },
};

ACCESS_ENTRIES(LsaTrusted)
{
	{ eAccessFullControl, TRUSTED_ALL_ACCESS, true, true },
	{ eAccessRead, TRUSTED_READ, true, false },
	{ eAccessWrite, TRUSTED_WRITE, true, false },
	{ eAccessExecute, TRUSTED_EXECUTE, true, false },
	{ eAccessQueryDomainName, TRUSTED_QUERY_DOMAIN_NAME, false, true },
	{ eAccessQueryControllers, TRUSTED_QUERY_CONTROLLERS, false, true },
	{ eAccessSetControllers, TRUSTED_SET_CONTROLLERS, false, true },
	{ eAccessQueryPOSIX, TRUSTED_QUERY_POSIX, false, true },
	{ eAccessSetPOSIX, TRUSTED_SET_POSIX, false, true },
	{ eAccessQueryAuthentication, TRUSTED_QUERY_AUTH, false, true },
	{ eAccessSetAuthentication, TRUSTED_SET_AUTH, false, true },
};

ACCESS_ENTRIES(Mutant)
{
	{ eAccessFullControl, MUTANT_ALL_ACCESS, true, true },
	{ eAccessQuery, MUTANT_QUERY_STATE, true, true },
};

ACCESS_ENTRIES(Partition)
{
	{ eAccessFullControl, MEMORY_PARTITION_ALL_ACCESS, true, true },
	{ eAccessQuery, MEMORY_PARTITION_QUERY_ACCESS, true, true },
	{ eAccessModify, MEMORY_PARTITION_MODIFY_ACCESS, true, true },
};

ACCESS_ENTRIES(Process)
{
	{ eAccessFullControl, STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xfff, true, true },
	{ eAccessQueryInformation, PROCESS_QUERY_INFORMATION, true, true },
	{ eAccessSetInformation, PROCESS_SET_INFORMATION, true, true },
	{ eAccessSetQuotas, PROCESS_SET_QUOTA, true, true },
	{ eAccessSetSessionID, PROCESS_SET_SESSIONID, true, true },
	{ eAccessCreateThreads, PROCESS_CREATE_THREAD, true, true },
	{ eAccessCreateProcesses, PROCESS_CREATE_PROCESS, true, true },
	{ eAccessModifyMemory, PROCESS_VM_OPERATION, true, true },
	{ eAccessReadMemory, PROCESS_VM_READ, true, true },
	{ eAccessWriteMemory, PROCESS_VM_WRITE, true, true },
	{ eAccessDuplicateHandles, PROCESS_DUP_HANDLE, true, true },
	{ eAccessSuspendResumeSetPort, PROCESS_SUSPEND_RESUME, true, true },
	{ eAccessTerminate, PROCESS_TERMINATE, true, true },
};

ACCESS_ENTRIES(Process60)
{
	{ eAccessFullControl, STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | SPECIFIC_RIGHTS_ALL, true, true },
	{ eAccessQueryLimitedInformation, PROCESS_QUERY_LIMITED_INFORMATION, true, true },
	{ eAccessQueryInformation, PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, true, true },
	{ eAccessSetInformation, PROCESS_SET_INFORMATION, true, true },
	{ eAccessSetLimitedInformation, PROCESS_SET_LIMITED_INFORMATION, true, true },
	{ eAccessSetQuotas, PROCESS_SET_QUOTA, true, true },
	{ eAccessSetSessionID, PROCESS_SET_SESSIONID, true, true },
	{ eAccessCreateThreads, PROCESS_CREATE_THREAD, true, true },
	{ eAccessCreateProcesses, PROCESS_CREATE_PROCESS, true, true },
	{ eAccessModifyMemory, PROCESS_VM_OPERATION, true, true },
	{ eAccessReadMemory, PROCESS_VM_READ, true, true },
	{ eAccessWriteMemory, PROCESS_VM_WRITE, true, true },
	{ eAccessDuplicateHandles, PROCESS_DUP_HANDLE, true, true },
	{ eAccessSuspendResumeSetPort, PROCESS_SUSPEND_RESUME, true, true },
	{ eAccessTerminate, PROCESS_TERMINATE, true, true },
};

ACCESS_ENTRIES(Profile)
{
	{ eAccessFullControl, PROFILE_ALL_ACCESS, true, true },
	{ eAccessControl, PROFILE_CONTROL, true, true },
};

ACCESS_ENTRIES(SamAlias)
{
	{ eAccessFullControl, ALIAS_ALL_ACCESS, true, true },
	{ eAccessRead, ALIAS_READ, true, false },
	{ eAccessWrite, ALIAS_WRITE, true, false },
	{ eAccessExecute, ALIAS_EXECUTE, true, false },
	{ eAccessReadInformation, ALIAS_READ_INFORMATION, false, true },
	{ eAccessWriteAccount, ALIAS_WRITE_ACCOUNT, false, true },
	{ eAccessAddMember, ALIAS_ADD_MEMBER, false, true },
	{ eAccessRemoveMember, ALIAS_REMOVE_MEMBER, false, true },
	{ eAccessListMembers, ALIAS_LIST_MEMBERS, false, true },
};

ACCESS_ENTRIES(SamDomain)
{
	{ eAccessFullControl, DOMAIN_ALL_ACCESS, true, true },
	{ eAccessRead, DOMAIN_READ, true, false },
	{ eAccessWrite, DOMAIN_WRITE, true, false },
	{ eAccessExecute, DOMAIN_EXECUTE, true, false },
	{ eAccessReadPasswordParameters, DOMAIN_READ_PASSWORD_PARAMETERS, false, true },
	{ eAccessWritePasswordParameters, DOMAIN_WRITE_PASSWORD_PARAMS, false, true },
	{ eAccessReadOtherParameters, DOMAIN_READ_OTHER_PARAMETERS, false, true },
	{ eAccessWriteOtherParameters, DOMAIN_WRITE_OTHER_PARAMETERS, false, true },
	{ eAccessCreateUser, DOMAIN_CREATE_USER, false, true },
	{ eAccessCreateGroup, DOMAIN_CREATE_GROUP, false, true },
	{ eAccessCreateAlias, DOMAIN_CREATE_ALIAS, false, true },
	{ eAccessGetAliasMembership, DOMAIN_GET_ALIAS_MEMBERSHIP, false, true },
	{ eAccessListAccounts, DOMAIN_LIST_ACCOUNTS, false, true },
	{ eAccessLookup, DOMAIN_LOOKUP, false, true },
	{ eAccessAdministerServer, DOMAIN_ADMINISTER_SERVER, false, true },
};

ACCESS_ENTRIES(SamGroup)
{
	{ eAccessFullControl, GROUP_ALL_ACCESS, true, true },
	{ eAccessRead, GROUP_READ, true, false },
	{ eAccessWrite, GROUP_WRITE, true, false },
	{ eAccessExecute, GROUP_EXECUTE, true, false },
	{ eAccessReadInformation, GROUP_READ_INFORMATION, false, true },
	{ eAccessWriteAccount, GROUP_WRITE_ACCOUNT, false, true },
	{ eAccessAddMember, GROUP_ADD_MEMBER, false, true },
	{ eAccessRemoveMember, GROUP_REMOVE_MEMBER, false, true },
	{ eAccessListMembers, GROUP_LIST_MEMBERS, false, true },
};

ACCESS_ENTRIES(SamServer)
{
	{ eAccessFullControl, SAM_SERVER_ALL_ACCESS, true, true },
	{ eAccessRead, SAM_SERVER_READ, true, false },
	{ eAccessWrite, SAM_SERVER_WRITE, true, false },
	{ eAccessExecute, SAM_SERVER_EXECUTE, true, false },
	{ eAccessConnect, SAM_SERVER_CONNECT, false, true },
	{ eAccessShutdown, SAM_SERVER_SHUTDOWN, false, true },
	{ eAccessInitialize, SAM_SERVER_INITIALIZE, false, true },
	{ eAccessCreateDomain, SAM_SERVER_CREATE_DOMAIN, false, true },
	{ eAccessEnumerateDomains, SAM_SERVER_ENUMERATE_DOMAINS, false, true },
	{ eAccessLookupDomain, SAM_SERVER_LOOKUP_DOMAIN, false, true },
};

ACCESS_ENTRIES(SamUser)
{
	{ eAccessFullControl, USER_ALL_ACCESS, true, true },
	{ eAccessRead, USER_READ, true, false },
	{ eAccessWrite, USER_WRITE, true, false },
	{ eAccessExecute, USER_EXECUTE, true, false },
	{ eAccessReadGeneral, USER_READ_GENERAL, false, true },
	{ eAccessReadPreferences, USER_READ_PREFERENCES, false, true },
	{ eAccessWritePreferences, USER_WRITE_PREFERENCES, false, true },
	{ eAccessReadLogon, USER_READ_LOGON, false, true },
	{ eAccessReadAccount, USER_READ_ACCOUNT, false, true },
	{ eAccessWriteAccount, USER_WRITE_ACCOUNT, false, true },
	{ eAccessChangePassword, USER_CHANGE_PASSWORD, false, true },
	{ eAccessForcePasswordChange, USER_FORCE_PASSWORD_CHANGE, false, true },
	{ eAccessListGroups, USER_LIST_GROUPS, false, true },
	{ eAccessReadGroupInformation, USER_READ_GROUP_INFORMATION, false, true },
	{ eAccessWriteGroupInformation, USER_WRITE_GROUP_INFORMATION, false, true },
};

ACCESS_ENTRIES(Section)
{
	{ eAccessFullControl, SECTION_ALL_ACCESS, true, true },
	{ eAccessQuery, SECTION_QUERY, true, true },
	{ eAccessMapForRead, SECTION_MAP_READ, true, true },
	{ eAccessMapForWrite, SECTION_MAP_WRITE, true, true },
	{ eAccessMapForExecute, SECTION_MAP_EXECUTE, true, true },
	{ eAccessMapForExecuteExplicit, SECTION_MAP_EXECUTE_EXPLICIT, true, true },
	{ eAccessExtendSize, SECTION_EXTEND_SIZE, true, true },
};

ACCESS_ENTRIES(Semaphore)
{
	{ eAccessFullControl, SEMAPHORE_ALL_ACCESS, true, true },
	{ eAccessQuery, SEMAPHORE_QUERY_STATE, true, true },
	{ eAccessModify, SEMAPHORE_MODIFY_STATE, true, true },
};

ACCESS_ENTRIES(Service)
{
	{ eAccessFullControl, SERVICE_ALL_ACCESS, true, true },
	{ eAccessQueryStatus, SERVICE_QUERY_STATUS, true, true },
	{ eAccessQueryConfiguration, SERVICE_QUERY_CONFIG, true, true },
	{ eAccessModifyConfiguration, SERVICE_CHANGE_CONFIG, true, true },
	{ eAccessEnumerateDependents, SERVICE_ENUMERATE_DEPENDENTS, true, true },
	{ eAccessStart, SERVICE_START, true, true },
	{ eAccessStop, SERVICE_STOP, true, true },
	{ eAccessPauseContinue, SERVICE_PAUSE_CONTINUE, true, true },
	{ eAccessInterrogate, SERVICE_INTERROGATE, true, true },
	{ eAccessUserDefinedControl, SERVICE_USER_DEFINED_CONTROL, true, true },
};

ACCESS_ENTRIES(SCManager)
{
	{ eAccessFullControl, SC_MANAGER_ALL_ACCESS, true, true },
	{ eAccessCreateService, SC_MANAGER_CREATE_SERVICE, true, true },
	{ eAccessConnect, SC_MANAGER_CONNECT, true, true },
	{ eAccessEnumerateServices, SC_MANAGER_ENUMERATE_SERVICE, true, true },
	{ eAccessLock, SC_MANAGER_LOCK, true, true },
	{ eAccessModifyBootConfig, SC_MANAGER_MODIFY_BOOT_CONFIG, true, true },
	{ eAccessQueryLockStatus, SC_MANAGER_QUERY_LOCK_STATUS, true, true },
};

ACCESS_ENTRIES(Session)
{
	{ eAccessFullControl, SESSION_ALL_ACCESS, true, true },
	{ eAccessQuery, SESSION_QUERY_ACCESS, true, true },
	{ eAccessModify, SESSION_MODIFY_ACCESS, true, true },
};

ACCESS_ENTRIES(SymbolicLink)
{
	{ eAccessFullControl, SYMBOLIC_LINK_ALL_ACCESS, true, true },
	{ eAccessFullControlExtended, SYMBOLIC_LINK_ALL_ACCESS_EX, true, true },
	{ eAccessQuery, SYMBOLIC_LINK_QUERY, true, true },
};

ACCESS_ENTRIES(Thread)
{
	{ eAccessFullControl, STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3ff, true, true },
	{ eAccessQueryInformation, THREAD_QUERY_INFORMATION, true, true },
	{ eAccessSetInformation, THREAD_SET_INFORMATION, true, true },
	{ eAccessGetContext, THREAD_GET_CONTEXT, true, true },
	{ eAccessSetContext, THREAD_SET_CONTEXT, true, true },
	{ eAccessSetToken, THREAD_SET_THREAD_TOKEN, true, true },
	{ eAccessAlert, THREAD_ALERT, true, true },
	{ eAccessImpersonate, THREAD_IMPERSONATE, true, true },
	{ eAccessDirectImpersonate, THREAD_DIRECT_IMPERSONATION, true, true },
	{ eAccessSuspendResume, THREAD_SUSPEND_RESUME, true, true },
	{ eAccessTerminate, THREAD_TERMINATE, true, true },
};

ACCESS_ENTRIES(Thread60)
{
	{ eAccessFullControl, STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | SPECIFIC_RIGHTS_ALL, true, true },
	{ eAccessQueryLimitedInformation, THREAD_QUERY_LIMITED_INFORMATION, true, true },
	{ eAccessQueryInformation, THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, true, true },
	{ eAccessSetLimitedInformation, THREAD_SET_LIMITED_INFORMATION, true, true },
	{ eAccessSetInformation, THREAD_SET_INFORMATION | THREAD_SET_LIMITED_INFORMATION, true, true },
	{ eAccessGetContext, THREAD_GET_CONTEXT, true, true },
	{ eAccessSetContext, THREAD_SET_CONTEXT, true, true },
	{ eAccessSetToken, THREAD_SET_THREAD_TOKEN, true, true },
	{ eAccessAlert, THREAD_ALERT, true, true },
	{ eAccessImpersonate, THREAD_IMPERSONATE, true, true },
	{ eAccessDirectImpersonate, THREAD_DIRECT_IMPERSONATION, true, true },
	{ eAccessSuspendResume, THREAD_SUSPEND_RESUME, true, true },
	{ eAccessTerminate, THREAD_TERMINATE, true, true },
};

ACCESS_ENTRIES(Timer)
{
	{ eAccessFullControl, TIMER_ALL_ACCESS, true, true },
	{ eAccessQuery, TIMER_QUERY_STATE, true, true },
	{ eAccessModify, TIMER_MODIFY_STATE, true, true },
};

ACCESS_ENTRIES(TmEn)
{
	{ eAccessFullControl, ENLISTMENT_ALL_ACCESS, true, true },
	{ eAccessRead, ENLISTMENT_GENERIC_READ, true, false },
	{ eAccessWrite, ENLISTMENT_GENERIC_WRITE, true, false },
	{ eAccessExecute, ENLISTMENT_GENERIC_EXECUTE, true, false },
	{ eAccessQueryInformation, ENLISTMENT_QUERY_INFORMATION, false, true },
	{ eAccessSetInformation, ENLISTMENT_SET_INFORMATION, false, true },
	{ eAccessRecover, ENLISTMENT_RECOVER, false, true },
	{ eAccessSubordinateRights, ENLISTMENT_SUBORDINATE_RIGHTS, false, true },
	{ eAccessSuperiorRights, ENLISTMENT_SUPERIOR_RIGHTS, false, true },
};

ACCESS_ENTRIES(TmRm)
{
	{ eAccessFullControl, RESOURCEMANAGER_ALL_ACCESS, true, true },
	{ eAccessRead, RESOURCEMANAGER_GENERIC_READ, true, false },
	{ eAccessWrite, RESOURCEMANAGER_GENERIC_WRITE, true, false },
	{ eAccessExecute, RESOURCEMANAGER_GENERIC_EXECUTE, true, false },
	{ eAccessQueryInformation, RESOURCEMANAGER_QUERY_INFORMATION, false, true },
	{ eAccessSetInformation, RESOURCEMANAGER_SET_INFORMATION, false, true },
	{ eAccessGetNotifications, RESOURCEMANAGER_GET_NOTIFICATION, false, true },
	{ eAccessEnlist, RESOURCEMANAGER_ENLIST, false, true },
	{ eAccessRecover, RESOURCEMANAGER_RECOVER, false, true },
	{ eAccessRegisterProtocols, RESOURCEMANAGER_REGISTER_PROTOCOL, false, true },
	{ eAccessCompletePropagation, RESOURCEMANAGER_COMPLETE_PROPAGATION, false, true },
};

ACCESS_ENTRIES(TmTm)
{
	{ eAccessFullControl, TRANSACTIONMANAGER_ALL_ACCESS, true, true },
	{ eAccessRead, TRANSACTIONMANAGER_GENERIC_READ, true, false },
	{ eAccessWrite, TRANSACTIONMANAGER_GENERIC_WRITE, true, false },
	{ eAccessExecute, TRANSACTIONMANAGER_GENERIC_EXECUTE, true, false },
	{ eAccessQueryInformation, TRANSACTIONMANAGER_QUERY_INFORMATION, false, true },
	{ eAccessSetInformation, TRANSACTIONMANAGER_SET_INFORMATION, false, true },
	{ eAccessRecover, TRANSACTIONMANAGER_RECOVER, false, true },
	{ eAccessRename, TRANSACTIONMANAGER_RENAME, false, true },
	{ eAccessCreateResourceManager, TRANSACTIONMANAGER_CREATE_RM, false, true },
	{ eAccessBindTransactions, TRANSACTIONMANAGER_BIND_TRANSACTION, false, true },
};

ACCESS_ENTRIES(TmTx)
{
	{ eAccessFullControl, TRANSACTION_ALL_ACCESS, true, true },
	{ eAccessRead, TRANSACTION_GENERIC_READ, true, false },
	{ eAccessWrite, TRANSACTION_GENERIC_WRITE, true, false },
	{ eAccessExecute, TRANSACTION_GENERIC_EXECUTE, true, false },
	{ eAccessQueryInformation, TRANSACTION_QUERY_INFORMATION, false, true },
	{ eAccessSetInformation, TRANSACTION_SET_INFORMATION, false, true },
	{ eAccessEnlist, TRANSACTION_ENLIST, false, true },
	{ eAccessCommit, TRANSACTION_COMMIT, false, true },
	{ eAccessRollback, TRANSACTION_ROLLBACK, false, true },
	{ eAccessPropagate, TRANSACTION_PROPAGATE, false, true },
};

ACCESS_ENTRIES(Token)
{
	{ eAccessFullControl, TOKEN_ALL_ACCESS, true, true },
	{ eAccessRead, TOKEN_READ, false, false },
	{ eAccessWrite, TOKEN_WRITE, false, false },
	{ eAccessExecute, TOKEN_EXECUTE, false, false },
	{ eAccessAdjustPrivileges, TOKEN_ADJUST_PRIVILEGES, true, true },
	{ eAccessAdjustGroups, TOKEN_ADJUST_GROUPS, true, true },
	{ eAccessAdjustDefaults, TOKEN_ADJUST_DEFAULT, true, true },
	{ eAccessAdjustSessionID, TOKEN_ADJUST_SESSIONID, true, true },
	{ eAccessAssignAsPrimaryToken, TOKEN_ASSIGN_PRIMARY, true, true },
	{ eAccessDuplicate, TOKEN_DUPLICATE, true, true },
	{ eAccessImpersonate, TOKEN_IMPERSONATE, true, true },
	{ eAccessQuery, TOKEN_QUERY, true, true },
	{ eAccessQuerySource, TOKEN_QUERY_SOURCE, false, true },
};

ACCESS_ENTRIES(TokenDefault)
{
	{ eAccessFullControl, GENERIC_ALL, true, true },
	{ eAccessRead, GENERIC_READ, true, true },
	{ eAccessWrite, GENERIC_WRITE, true, true },
	{ eAccessExecute, GENERIC_EXECUTE, true, true },
};

ACCESS_ENTRIES(TpWorkerFactory)
{
	{ eAccessFullControl, WORKER_FACTORY_ALL_ACCESS, true, true },
	{ eAccessReleaseWorker, WORKER_FACTORY_RELEASE_WORKER, false, true },
	{ eAccessReadyWorker, WORKER_FACTORY_READY_WORKER, false, true },
	{ eAccessWait, WORKER_FACTORY_WAIT, false, true },
	{ eAccessSetInformation, WORKER_FACTORY_SET_INFORMATION, false, true },
	{ eAccessQueryInformation, WORKER_FACTORY_QUERY_INFORMATION, false, true },
	{ eAccessShutdown, WORKER_FACTORY_SHUTDOWN, false, true },
};

ACCESS_ENTRIES(Type)
{
	{ eAccessFullControl, OBJECT_TYPE_ALL_ACCESS, true, true },
	{ eAccessCreate, OBJECT_TYPE_CREATE, true, true },
};

ACCESS_ENTRIES(WaitCompletionPacket)
{
	{ eAccessFullControl, OBJECT_TYPE_ALL_ACCESS, true, true },
	{ eAccessModifyState, OBJECT_TYPE_CREATE, true, true },
};

ACCESS_ENTRIES(Wbem)
{
	{ eAccessEnableAccount, WBEM_ENABLE, true, true },
	{ eAccessExecuteMethods, WBEM_METHOD_EXECUTE, true, true },
	{ eAccessFullWrite, WBEM_FULL_WRITE_REP, true, true },
	{ eAccessPartialWrite, WBEM_PARTIAL_WRITE_REP, true, true },
	{ eAccessProviderWrite, WBEM_WRITE_PROVIDER, true, true },
	{ eAccessRemoteEnable, WBEM_REMOTE_ACCESS, true, true },
	{ eAccessGetNotifications, WBEM_RIGHT_SUBSCRIBE, true, true },
	{ eAccessReadDescription, WBEM_RIGHT_PUBLISH, true, true },
};

ACCESS_ENTRIES(WindowStation)
{
	{ eAccessFullControl, WINSTA_ALL_ACCESS | STANDARD_RIGHTS_REQUIRED, true, true },
	{ eAccessRead, WINSTA_GENERIC_READ, true, false },
	{ eAccessWrite, WINSTA_GENERIC_WRITE, true, false },
	{ eAccessExecute, WINSTA_GENERIC_EXECUTE, true, false },
	{ eAccessEnumerate, WINSTA_ENUMERATE, false, true },
	{ eAccessEnumerateDesktops, WINSTA_ENUMDESKTOPS, false, true },
	{ eAccessReadAttributes, WINSTA_READATTRIBUTES, false, true },
	{ eAccessReadScreen, WINSTA_READSCREEN, false, true },
	{ eAccessAccessClipboard, WINSTA_ACCESSCLIPBOARD, false, true },
	{ eAccessAccessGlobalAtoms, WINSTA_ACCESSGLOBALATOMS, false, true },
	{ eAccessCreateDesktop, WINSTA_CREATEDESKTOP, false, true },
	{ eAccessWriteAttributes, WINSTA_WRITEATTRIBUTES, false, true },
	{ eAccessExitWindows, WINSTA_EXITWINDOWS, false, true },
};

ACCESS_ENTRIES(WmiGuid)
{
	{ eAccessFullControl, WMIGUID_ALL_ACCESS, true, true },
	{ eAccessRead, WMIGUID_GENERIC_READ, true, false },
	{ eAccessWrite, WMIGUID_GENERIC_WRITE, true, false },
	{ eAccessExecute, WMIGUID_GENERIC_EXECUTE, true, false },
	{ eAccessQueryInformation, WMIGUID_QUERY, false, true },
	{ eAccessSetInformation, WMIGUID_SET, false, true },
	{ eAccessGetNotifications, WMIGUID_NOTIFICATION, false, true },
	{ eAccessReadDescription, WMIGUID_READ_DESCRIPTION, false, true },
	{ eAccessExecute, WMIGUID_EXECUTE, false, true },
	{ eAccessCreateRealTimeLogs, TRACELOG_CREATE_REALTIME, false, true },
	{ eAccessCreateOnDiskLogs, TRACELOG_CREATE_ONDISK, false, true },
	{ eAccessEnableProviderGUIDs, TRACELOG_GUID_ENABLE, false, true },
	{ eAccessAccessKernelLogger, TRACELOG_ACCESS_KERNEL_LOGGER, false, true },
	{ eAccessLogEvents, TRACELOG_LOG_EVENT, false, true },
	{ eAccessAccessRealTimeEvents, TRACELOG_ACCESS_REALTIME, false, true },
	{ eAccessRegisterProviderGUIDs, TRACELOG_REGISTER_GUIDS, false, true },
};

ACCESS_ENTRIES(Rdp)
{
	{ eAccessFullControl, WTS_SECURITY_ALL_ACCESS, true, true },
	{ eAccessQueryInformation, WTS_SECURITY_QUERY_INFORMATION, true, true },
	{ eAccessSetInformation, WTS_SECURITY_SET_INFORMATION, true, true },
	{ eAccessReset, WTS_SECURITY_RESET, false, true },
	{ eAccessVirtualChannels, WTS_SECURITY_VIRTUAL_CHANNELS, false, true },
	{ eAccessRemoteControl, WTS_SECURITY_REMOTE_CONTROL, false, true },
	{ eAccessLogon, WTS_SECURITY_LOGON, false, true },
	{ eAccessLogoff, WTS_SECURITY_LOGOFF, false, true },
	{ eAccessMessage, WTS_SECURITY_MESSAGE, false, true },
	{ eAccessConnect, WTS_SECURITY_CONNECT, false, true },
	{ eAccessDisconnect, WTS_SECURITY_DISCONNECT, false, true },
	{ eAccessGuestAccess, WTS_SECURITY_GUEST_ACCESS, false, true },
	{ eAccessGuestAccessCurrent, WTS_SECURITY_CURRENT_GUEST_ACCESS, false, true },
	{ eAccessUserAccess, WTS_SECURITY_USER_ACCESS, false, true },
	{ eAccessUserAccessCurrent, WTS_SECURITY_SET_INFORMATION | WTS_SECURITY_RESET | WTS_SECURITY_VIRTUAL_CHANNELS | WTS_SECURITY_LOGOFF | WTS_SECURITY_DISCONNECT, false, true },
};

ACCESS_ENTRIES(ComAccess)
{
	{ eAccessFullControl, COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL | COM_RIGHTS_EXECUTE_REMOTE, true, true },
	{ eAccessExecute, COM_RIGHTS_EXECUTE, true, true },
	{ eAccessExecuteLocal, COM_RIGHTS_EXECUTE_LOCAL, true, true },
	{ eAccessExecuteRemote, COM_RIGHTS_EXECUTE_REMOTE, true, true },
};

ACCESS_ENTRIES(ComLaunch)
{
	{ eAccessFullControl, COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL | COM_RIGHTS_EXECUTE_REMOTE | COM_RIGHTS_ACTIVATE_LOCAL | COM_RIGHTS_ACTIVATE_REMOTE, true, true },
	{ eAccessExecute, COM_RIGHTS_EXECUTE, true, true },
	{ eAccessExecuteLocal, COM_RIGHTS_EXECUTE_LOCAL, true, true },
	{ eAccessExecuteRemote, COM_RIGHTS_EXECUTE_REMOTE, true, true },
	{ eAccessActivateLocal, COM_RIGHTS_ACTIVATE_LOCAL, true, true },
	{ eAccessActivateRemote, COM_RIGHTS_ACTIVATE_REMOTE, true, true },
};

//
// A file handle's open mode. Not one of the object types above - it is a
// different field entirely - but it is read the same way.
//
// FILE_MODE_INFORMATION has no flag for asynchronous I/O, so one is invented
// here and set only when neither synchronous flag is present.
//
#define PH_FILEMODE_ASYNC 0x01000000
#define PhFileModeUpdAsyncFlag(mode) (mode & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) ? mode &~ PH_FILEMODE_ASYNC: mode | PH_FILEMODE_ASYNC)

static const SWinAccessEntry WinFileModeAccessEntries[] =
{
	{ eAccessFILEFLAGOVERLAPPED, PH_FILEMODE_ASYNC, false, false },
	{ eAccessFILEFLAGWRITETHROUGH, FILE_WRITE_THROUGH, false, false },
	{ eAccessFILEFLAGSEQUENTIALSCAN, FILE_SEQUENTIAL_ONLY, false, false },
	{ eAccessFILEFLAGNOBUFFERING, FILE_NO_INTERMEDIATE_BUFFERING, false, false },
	{ eAccessFILESYNCHRONOUSIOALERT, FILE_SYNCHRONOUS_IO_ALERT, false, false },
	{ eAccessFILESYNCHRONOUSIONONALERT, FILE_SYNCHRONOUS_IO_NONALERT, false, false },
};

//
// Which table each object type uses, and whether the type's rights imply
// SYNCHRONIZE - the standard rights are appended to every one of them.
//
static const struct
{
	const wchar_t*			Type;
	const SWinAccessEntry*	Entries;
	size_t					Count;
	bool					bHasSynchronize;
}
WinAccessTypes[] =
{
	ACCESS_TYPE(AlpcPort, true),
	ACCESS_TYPE(DebugObject, true),
	ACCESS_TYPE(Desktop, false),
	ACCESS_TYPE(Directory, false),
	ACCESS_TYPE(EtwConsumer, false),
	ACCESS_TYPE(EtwRegistration, false),
	ACCESS_TYPE(Event, true),
	ACCESS_TYPE(EventPair, true),
	ACCESS_TYPE(File, true),
	ACCESS_TYPE(FilterConnectionPort, false),
	ACCESS_TYPE(IoCompletion, true),
	ACCESS_TYPE(Job, true),
	ACCESS_TYPE(Key, false),
	ACCESS_TYPE(KeyedEvent, false),
	ACCESS_TYPE(LsaAccount, false),
	ACCESS_TYPE(LsaPolicy, false),
	ACCESS_TYPE(LsaSecret, false),
	ACCESS_TYPE(LsaTrusted, false),
	ACCESS_TYPE(Mutant, true),
	ACCESS_TYPE(Partition, true),
	ACCESS_TYPE(Process, true),
	ACCESS_TYPE(Process60, true),
	ACCESS_TYPE(Profile, false),
	ACCESS_TYPE(SamAlias, false),
	ACCESS_TYPE(SamDomain, false),
	ACCESS_TYPE(SamGroup, false),
	ACCESS_TYPE(SamServer, false),
	ACCESS_TYPE(SamUser, false),
	ACCESS_TYPE(Section, false),
	ACCESS_TYPE(Semaphore, true),
	ACCESS_TYPE(Service, false),
	ACCESS_TYPE(SCManager, false),
	ACCESS_TYPE(Session, false),
	ACCESS_TYPE(SymbolicLink, false),
	ACCESS_TYPE(Thread, true),
	ACCESS_TYPE(Thread60, true),
	ACCESS_TYPE(Timer, true),
	ACCESS_TYPE(TmEn, false),
	ACCESS_TYPE(TmRm, false),
	ACCESS_TYPE(TmTm, false),
	ACCESS_TYPE(TmTx, false),
	ACCESS_TYPE(Token, false),
	ACCESS_TYPE(TokenDefault, false),
	ACCESS_TYPE(TpWorkerFactory, false),
	ACCESS_TYPE(Type, false),
	ACCESS_TYPE(WaitCompletionPacket, false),
	ACCESS_TYPE(Wbem, false),
	ACCESS_TYPE(WindowStation, false),
	ACCESS_TYPE(WmiGuid, true),
	ACCESS_TYPE(Rdp, false),
	ACCESS_TYPE(ComAccess, false),
	ACCESS_TYPE(ComLaunch, false),
};


//
// Several object types are asked about under a name that is not the one their
// table is filed under - the object manager reports "Port" for what the tables
// call an ALPC port, and "Process" and "Thread" have had a second set of rights
// since Vista that is the one worth showing.
//
static QString WinAccess__ResolveType(const QString& Type)
{
	if (Type.compare("ALPC Port", Qt::CaseInsensitive) == 0)		return "AlpcPort";
	if (Type.compare("Port", Qt::CaseInsensitive) == 0)				return "AlpcPort";
	if (Type.compare("WaitablePort", Qt::CaseInsensitive) == 0)		return "AlpcPort";
	if (Type.compare("Process", Qt::CaseInsensitive) == 0)			return "Process60";
	if (Type.compare("Thread", Qt::CaseInsensitive) == 0)			return "Thread60";
	if (Type.compare("FileObject", Qt::CaseInsensitive) == 0)		return "File";
	if (Type.compare("Device", Qt::CaseInsensitive) == 0)			return "File";
	if (Type.compare("Driver", Qt::CaseInsensitive) == 0)			return "File";
	if (Type.compare("PowerDefault", Qt::CaseInsensitive) == 0)		return "Key";
	if (Type.compare("RdpDefault", Qt::CaseInsensitive) == 0)		return "Rdp";
	if (Type.compare("WmiDefault", Qt::CaseInsensitive) == 0)		return "Wbem";
	return Type;
}

//
// The entries for a type, with the standard rights appended the way phlib does
// it: SYNCHRONIZE only for the types that support waiting.
//
static QVector<SWinAccessEntry> WinAccess__GetEntries(const QString& RawType)
{
	QVector<SWinAccessEntry> Entries;

	const QString Type = WinAccess__ResolveType(RawType);

	//
	// WBEM is the exception: it does not take the standard rights, so a type
	// asked about under that name gets its own table and nothing else.
	//
	const bool bWbem = RawType.compare("WmiDefault", Qt::CaseInsensitive) == 0;

	const std::wstring Name = Type.toStdWString();
	for (size_t i = 0; i < RTL_NUMBER_OF(WinAccessTypes); i++)
	{
		if (_wcsicmp(WinAccessTypes[i].Type, Name.c_str()) != 0)
			continue;

		for (size_t j = 0; j < WinAccessTypes[i].Count; j++)
			Entries.append(WinAccessTypes[i].Entries[j]);

		if (bWbem)
			return Entries;

		//
		// The standard rights come last. Synchronize is the first of them and
		// is left out for the types that cannot be waited on.
		//
		const size_t First = WinAccessTypes[i].bHasSynchronize ? 0 : 1;
		for (size_t j = First; j < RTL_NUMBER_OF(WinStandardAccessEntries); j++)
			Entries.append(WinStandardAccessEntries[j]);

		return Entries;
	}

	//
	// A type with no table of its own still has the rights every securable
	// object has.
	//
	for (size_t j = 0; j < RTL_NUMBER_OF(WinStandardAccessEntries); j++)
		Entries.append(WinStandardAccessEntries[j]);

	return Entries;
}

//
// Which rights a mask actually grants, widest first.
//
static QList<int> WinAccess__Decompose(quint32 Access, const QVector<SWinAccessEntry>& Entries)
{
	QList<int> Rights;
	if (Entries.isEmpty())
		return Rights;

	//
	// Sorted by how many bits each entry covers, so a wide right is considered
	// before the individual ones it contains.
	//
	QVector<int> Order;
	for (int i = 0; i < Entries.count(); i++)
		Order.append(i);

	std::stable_sort(Order.begin(), Order.end(), [&Entries](int a, int b) {
		return PhCountBits(Entries[a].Access) > PhCountBits(Entries[b].Access);
	});

	QVector<bool> Matched(Entries.count(), false);

	for (int i = 0; i < Order.count(); i++)
	{
		const SWinAccessEntry& Entry = Entries[Order[i]];

		if (Matched[i] || (Access & Entry.Access) != Entry.Access)
			continue;

		Rights.append(Entry.Right);

		//
		// Everything this right already implies is spoken for; reporting both
		// FILE_GENERIC_READ and FILE_READ_DATA would say the same thing twice.
		//
		for (int j = i; j < Order.count(); j++)
		{
			if ((Entry.Access | Entries[Order[j]].Access) == Entry.Access)
				Matched[j] = true;
		}
	}

	return Rights;
}

QList<int> WinAccess__GetGrantedRights(quint32 Access, const QString& Type)
{
	return WinAccess__Decompose(Access, WinAccess__GetEntries(Type));
}

QList<int> WinAccess__GetFileModeRights(quint32 Mode)
{
	QVector<SWinAccessEntry> Entries;
	for (size_t i = 0; i < RTL_NUMBER_OF(WinFileModeAccessEntries); i++)
		Entries.append(WinFileModeAccessEntries[i]);

	return WinAccess__Decompose(PhFileModeUpdAsyncFlag(Mode), Entries);
}

QList<SAccessRight> WinAccess__GetAccessRights(const QString& Type)
{
	QList<SAccessRight> Rights;

	foreach(const SWinAccessEntry& Entry, WinAccess__GetEntries(Type))
	{
		SAccessRight Right;
		Right.Right = Entry.Right;
		Right.Access = Entry.Access;
		Right.bGeneral = Entry.bGeneral;
		Right.bSpecific = Entry.bSpecific;
		Rights.append(Right);
	}

	return Rights;
}

