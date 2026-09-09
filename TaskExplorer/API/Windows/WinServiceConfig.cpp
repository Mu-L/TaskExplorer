/*
 * Task Explorer -
 *   reading and writing a service's configuration.
 *
 * This used to live in GUI/SystemInfo/WinSvcWindow.cpp, which opened its own
 * handles to the service control manager - so the properties dialog could only
 * ever describe a service on the machine the GUI was running on.
 *
 * Two things to keep in mind when reading the write paths:
 *
 *  - ChangeServiceConfig treats NULL as "leave this alone" and L"" as "set it to
 *    nothing". SConfig says which is meant through SetPassword / SetDependencies
 *    rather than relying on an empty string, because the two are not the same and
 *    getting it wrong silently blanks a service's account or dependency list.
 *
 *  - Every write falls back to the elevated worker on ERROR_ACCESS_DENIED, since
 *    an unprivileged GUI cannot reconfigure a service itself.
 */

#include "stdafx.h"
#include "WinService.h"
#include "WindowsAPI.h"
#include "ProcessHacker.h"
#include "ProcessHacker/PhSvc.h"
#include "../../SVC/TaskService.h"
#include "../../../MiscHelpers/Common/Settings.h"

//
// Reconfiguring a service needs privileges the GUI may not hold; the elevated
// worker does it on our behalf. Both helpers came across from the dialog.
//
static quint32 CWinService__SvcChangeConfig(const QString& ServiceName, quint32 ServiceType, quint32 StartType, quint32 ErrorControl,
	const QString& BinaryPathName, const QString& LoadOrderGroup, const QStringList* pDependencies,
	const QString& ServiceStartName, const QString& Password)
{
	QString SocketName = CTaskService::RunWorker();
	if (SocketName.isEmpty())
		return ERROR_ACCESS_DENIED;

	QVariantMap Parameters;
	Parameters["ServiceName"] = ServiceName;
	Parameters["ServiceType"] = ServiceType;
	Parameters["StartType"] = StartType;
	Parameters["ErrorControl"] = ErrorControl;
	if (!BinaryPathName.isNull())
		Parameters["BinaryPathName"] = BinaryPathName;
	if (!LoadOrderGroup.isNull())
		Parameters["LoadOrderGroup"] = LoadOrderGroup;
	if (pDependencies)
		Parameters["Dependencies"] = *pDependencies;
	if (!ServiceStartName.isNull())
		Parameters["ServiceStartName"] = ServiceStartName;
	if (!Password.isNull())
		Parameters["Password"] = Password;

	QVariantMap Request;
	Request["Command"] = "ChangeServiceConfig";
	Request["Parameters"] = Parameters;

	QVariant Response = CTaskService::SendCommand(SocketName, Request);

	if (Response.isNull())
		return WAIT_TIMEOUT;
	if (Response.typeId() == QMetaType::Int || Response.typeId() == QMetaType::UInt)
		return Response.toUInt();
	return ERROR_INVALID_PARAMETER;
}

static quint32 CWinService__SvcChangeConfig2(const QString& ServiceName, quint32 InfoLevel, const void* Info, size_t Size)
{
	QString SocketName = CTaskService::RunWorker();
	if (SocketName.isEmpty())
		return ERROR_ACCESS_DENIED;

	QVariantMap Parameters;
	Parameters["ServiceName"] = ServiceName;
	Parameters["InfoLevel"] = InfoLevel;
	Parameters["InfoData"] = QByteArray((char*)Info, Size);

	QVariantMap Request;
	Request["Command"] = "ChangeServiceConfig";
	Request["Parameters"] = Parameters;

	QVariant Response = CTaskService::SendCommand(SocketName, Request);

	if (Response.isNull())
		return WAIT_TIMEOUT;
	if (Response.typeId() == QMetaType::Int || Response.typeId() == QMetaType::UInt)
		return Response.toUInt();
	return ERROR_INVALID_PARAMETER;
}

// whether an access-denied failure should be retried through the worker
static bool CWinService__ShouldElevate(ULONG Win32Result)
{
	return Win32Result == ERROR_ACCESS_DENIED
		&& !theSystem->RootAvaiable()
		&& theConf->GetBool("Options/AutoElevate", true);
}

static STATUS CWinService__Win32Error(ULONG Win32Result)
{
	return ERR(TE_Generic, QVariantList() << CastPhString(PhGetWin32Message(Win32Result)), Win32Result);
}

//
// ---- general ----
//

bool CWinService::GetConfig(SConfig& Config) const
{
	Config.Type = GetType();
	Config.StartType = GetStartType();
	Config.ErrorControl = GetErrorControl();

	std::wstring Name = GetName().toStdWString();

	SC_HANDLE serviceHandle;
	if (!NT_SUCCESS(PhOpenService(&serviceHandle, SERVICE_QUERY_CONFIG, (wchar_t*)Name.c_str())))
		return false;

	LPQUERY_SERVICE_CONFIG config;
	if (NT_SUCCESS(PhGetServiceConfig(serviceHandle, &config)))
	{
		Config.LoadOrderGroup = QString::fromWCharArray(config->lpLoadOrderGroup);
		Config.BinaryPath = QString::fromWCharArray(config->lpBinaryPathName);
		Config.StartName = QString::fromWCharArray(config->lpServiceStartName);

		// the live values win over whatever the last enumeration reported
		Config.StartType = config->dwStartType;
		Config.ErrorControl = config->dwErrorControl;

		//
		// Dependencies come as a double-null-terminated list; entries starting
		// with the group marker are load-order groups, not services.
		//
		PWSTR dependency = config->lpDependencies;
		if (dependency)
		{
			for (;;)
			{
				ULONG dependencyLength = (ULONG)PhCountStringZ(dependency);
				if (dependencyLength == 0)
					break;

				if (dependency[0] != SC_GROUP_IDENTIFIER)
					Config.Dependencies.append(QString::fromWCharArray(dependency));

				dependency += dependencyLength + 1;
			}
		}

		PhFree(config);
	}

	PPH_STRING description;
	if (description = PhGetServiceDescription(serviceHandle))
		Config.Description = CastPhString(description);

	BOOLEAN delayedStart;
	if (PhGetServiceDelayedAutoStart(serviceHandle, &delayedStart))
		Config.DelayedStart = !!delayedStart;

	CloseServiceHandle(serviceHandle);

	PH_STRINGREF svcName;
	svcName.Buffer = (wchar_t*)Name.c_str();
	svcName.Length = Name.length() * sizeof(wchar_t);

	PPH_STRING serviceDll;
	if (NT_SUCCESS(PhGetServiceDllParameter(GetType(), &svcName, &serviceDll)))
	{
		Config.ServiceDll = CastPhString(serviceDll, false);
		PhDereferenceObject(serviceDll);
	}

	return true;
}

STATUS CWinService::SetConfig(const SConfig& Config)
{
	const QString Name = GetName();
	std::wstring NameStr = Name.toStdWString();
	std::wstring BinaryPath = Config.BinaryPath.toStdWString();
	std::wstring LoadOrderGroup = Config.LoadOrderGroup.toStdWString();
	std::wstring StartName = Config.StartName.toStdWString();
	std::wstring Password = Config.Password.toStdWString();

	//
	// Double-null-terminated, and only built at all when the caller means to
	// replace the list - passing NULL leaves it as it was.
	//
	std::wstring Dependencies;
	if (Config.SetDependencies)
	{
		foreach(const QString& Service, Config.Dependencies)
		{
			Dependencies.append(Service.toStdWString());
			Dependencies.push_back(L'\0');
		}
		Dependencies.push_back(L'\0');
	}

	ULONG win32Result = 0;

	SC_HANDLE serviceHandle;
	if (NT_SUCCESS(PhOpenService(&serviceHandle, SERVICE_CHANGE_CONFIG, (wchar_t*)NameStr.c_str())))
	{
		if (ChangeServiceConfig(
			serviceHandle,
			Config.Type,
			Config.StartType,
			Config.ErrorControl,
			BinaryPath.c_str(),
			LoadOrderGroup.c_str(),
			NULL,
			Config.SetDependencies ? Dependencies.c_str() : NULL,
			StartName.c_str(),
			Config.SetPassword ? Password.c_str() : NULL,
			NULL
			))
		{
			SERVICE_DELAYED_AUTO_START_INFO info;
			info.fDelayedAutostart = Config.DelayedStart;
			ChangeServiceConfig2(serviceHandle, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &info);
		}
		else
			win32Result = GetLastError();

		CloseServiceHandle(serviceHandle);
	}
	else
	{
		win32Result = GetLastError();
		if (CWinService__ShouldElevate(win32Result))
		{
			win32Result = CWinService__SvcChangeConfig(Name, Config.Type, Config.StartType, Config.ErrorControl,
				Config.BinaryPath, Config.LoadOrderGroup,
				Config.SetDependencies ? &Config.Dependencies : NULL,
				Config.StartName, Config.SetPassword ? Config.Password : QString());

			if (win32Result == 0)
			{
				SERVICE_DELAYED_AUTO_START_INFO info;
				info.fDelayedAutostart = Config.DelayedStart;
				CWinService__SvcChangeConfig2(Name, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &info, sizeof(info));
			}
		}
	}

	if (win32Result != 0)
		return CWinService__Win32Error(win32Result);
	return OK;
}

//
// ---- recovery ----
//

bool CWinService::GetRecovery(SRecovery& Recovery) const
{
	std::wstring Name = GetName().toStdWString();

	SC_HANDLE serviceHandle;
	if (!NT_SUCCESS(PhOpenService(&serviceHandle, SERVICE_QUERY_CONFIG, (wchar_t*)Name.c_str())))
		return false;

	bool bOk = false;

	LPSERVICE_FAILURE_ACTIONS failureActions;
	if (NT_SUCCESS(PhQueryServiceVariableSize(serviceHandle, SERVICE_CONFIG_FAILURE_ACTIONS, (PVOID*)&failureActions)))
	{
		bOk = true;

		Recovery.ActionCount = failureActions->cActions;
		Recovery.ResetPeriod = failureActions->dwResetPeriod;

		for (ULONG i = 0; i < failureActions->cActions; i++)
		{
			SRecoveryAction Action;
			Action.Type = failureActions->lpsaActions[i].Type;
			Action.Delay = failureActions->lpsaActions[i].Delay;
			Recovery.Actions.append(Action);
		}

		if (failureActions->lpRebootMsg && failureActions->lpRebootMsg[0] != 0)
			Recovery.RebootMessage = QString::fromWCharArray(failureActions->lpRebootMsg);

		Recovery.CommandLine = QString::fromWCharArray(failureActions->lpCommand);

		PhFree(failureActions);

		SERVICE_FAILURE_ACTIONS_FLAG failureActionsFlag;
		ULONG returnLength;
		if (QueryServiceConfig2(serviceHandle, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
			(BYTE*)&failureActionsFlag, sizeof(SERVICE_FAILURE_ACTIONS_FLAG), &returnLength))
		{
			Recovery.HasNonCrashFlag = true;
			Recovery.NonCrashFailures = !!failureActionsFlag.fFailureActionsOnNonCrashFailures;
		}
	}

	CloseServiceHandle(serviceHandle);
	return bOk;
}

STATUS CWinService::SetRecovery(const SRecovery& Recovery)
{
	const QString Name = GetName();
	std::wstring NameStr = Name.toStdWString();
	std::wstring RebootMsg = Recovery.RebootMessage.toStdWString();
	std::wstring Command = Recovery.CommandLine.toStdWString();

	SC_ACTION actions[3];
	memset(actions, 0, sizeof(actions));

	bool bEnableRestart = false;
	for (int i = 0; i < 3 && i < Recovery.Actions.count(); i++)
	{
		actions[i].Type = (SC_ACTION_TYPE)Recovery.Actions[i].Type;
		actions[i].Delay = Recovery.Actions[i].Delay;
		if (actions[i].Type == SC_ACTION_RESTART)
			bEnableRestart = true;
	}

	SERVICE_FAILURE_ACTIONS failureActions;
	failureActions.dwResetPeriod = Recovery.ResetPeriod;
	failureActions.lpRebootMsg = (wchar_t*)RebootMsg.c_str();
	failureActions.lpCommand = (wchar_t*)Command.c_str();
	failureActions.cActions = 3;
	failureActions.lpsaActions = actions;

	SERVICE_FAILURE_ACTIONS_FLAG failureActionsFlag;
	failureActionsFlag.fFailureActionsOnNonCrashFailures = Recovery.NonCrashFailures;

	ULONG win32Result = 0;

	// SC_ACTION_RESTART also needs the right to start the service
	SC_HANDLE serviceHandle;
	if (NT_SUCCESS(PhOpenService(&serviceHandle, SERVICE_CHANGE_CONFIG | (bEnableRestart ? SERVICE_START : 0), (wchar_t*)NameStr.c_str())))
	{
		if (ChangeServiceConfig2(serviceHandle, SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions))
		{
			if (Recovery.HasNonCrashFlag)
				ChangeServiceConfig2(serviceHandle, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &failureActionsFlag);
		}
		else
			win32Result = GetLastError();

		CloseServiceHandle(serviceHandle);
	}
	else
	{
		win32Result = GetLastError();
		if (CWinService__ShouldElevate(win32Result))
		{
			win32Result = CWinService__SvcChangeConfig2(Name, SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions, sizeof(failureActions));
			if (win32Result == 0 && Recovery.HasNonCrashFlag)
				CWinService__SvcChangeConfig2(Name, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &failureActionsFlag, sizeof(failureActionsFlag));
		}
	}

	if (win32Result != 0)
		return CWinService__Win32Error(win32Result);
	return OK;
}

//
// ---- dependents ----
//

QStringList CWinService::GetDependents() const
{
	QStringList List;

	std::wstring Name = GetName().toStdWString();

	SC_HANDLE serviceHandle;
	if (!NT_SUCCESS(PhOpenService(&serviceHandle, SERVICE_ENUMERATE_DEPENDENTS, (wchar_t*)Name.c_str())))
		return List;

	ULONG numberOfDependentServices;
	LPENUM_SERVICE_STATUS dependentServices = (LPENUM_SERVICE_STATUS)EsEnumDependentServices(serviceHandle, 0, &numberOfDependentServices);
	if (dependentServices)
	{
		for (ULONG i = 0; i < numberOfDependentServices; i++)
			List.append(QString::fromWCharArray(dependentServices[i].lpServiceName));

		PhFree(dependentServices);
	}

	CloseServiceHandle(serviceHandle);
	return List;
}

//
// ---- the remaining page ----
//

bool CWinService::GetExtras(SExtras& Extras) const
{
	std::wstring Name = GetName().toStdWString();

	PH_STRINGREF svcName;
	svcName.Buffer = (wchar_t*)Name.c_str();
	svcName.Length = Name.length() * sizeof(wchar_t);

	PPH_STRING Sid = EspGetServiceSidString(&svcName);
	if (Sid)
		Extras.SidString = CastPhString(Sid);

	SC_HANDLE serviceHandle;
	if (!NT_SUCCESS(PhOpenService(&serviceHandle, SERVICE_QUERY_CONFIG, (wchar_t*)Name.c_str())))
		return false;

	ULONG returnLength;

	SERVICE_PRESHUTDOWN_INFO preshutdownInfo;
	if (QueryServiceConfig2(serviceHandle, SERVICE_CONFIG_PRESHUTDOWN_INFO,
		(PBYTE)&preshutdownInfo, sizeof(SERVICE_PRESHUTDOWN_INFO), &returnLength))
	{
		Extras.HasPreShutdownTimeout = true;
		Extras.PreShutdownTimeout = preshutdownInfo.dwPreshutdownTimeout;
	}

	LPSERVICE_REQUIRED_PRIVILEGES_INFO requiredPrivilegesInfo;
	if (NT_SUCCESS(PhQueryServiceVariableSize(serviceHandle, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (PVOID*)&requiredPrivilegesInfo)))
	{
		Extras.HasPrivileges = true;

		PWSTR privilege = requiredPrivilegesInfo->pmszRequiredPrivileges;
		if (privilege)
		{
			for (;;)
			{
				ULONG privilegeLength = (ULONG)PhCountStringZ(privilege);
				if (privilegeLength == 0)
					break;

				Extras.Privileges.append(QString::fromWCharArray(privilege, privilegeLength));
				privilege += privilegeLength + 1;
			}
		}

		PhFree(requiredPrivilegesInfo);
	}

	SERVICE_SID_INFO sidInfo;
	if (QueryServiceConfig2(serviceHandle, SERVICE_CONFIG_SERVICE_SID_INFO,
		(PBYTE)&sidInfo, sizeof(SERVICE_SID_INFO), &returnLength))
	{
		Extras.HasSidType = true;
		Extras.SidType = sidInfo.dwServiceSidType;
	}

	SERVICE_LAUNCH_PROTECTED_INFO launchProtectedInfo;
	if (QueryServiceConfig2(serviceHandle, SERVICE_CONFIG_LAUNCH_PROTECTED,
		(PBYTE)&launchProtectedInfo, sizeof(SERVICE_LAUNCH_PROTECTED_INFO), &returnLength))
	{
		Extras.HasLaunchProtected = true;
		Extras.LaunchProtected = launchProtectedInfo.dwLaunchProtected;
	}

	CloseServiceHandle(serviceHandle);
	return true;
}

STATUS CWinService::SetExtras(const SExtras& Extras)
{
	const QString Name = GetName();
	std::wstring NameStr = Name.toStdWString();

	//
	// Each setting is written through the handle where we have one, and through
	// the elevated worker where we do not. The original had these two branches
	// the wrong way round, so it went to the worker whenever the handle opened
	// and called ChangeServiceConfig2 with NULL when it did not.
	//
	SC_HANDLE serviceHandle = NULL;
	ULONG win32Result = 0;
	if (!NT_SUCCESS(PhOpenService(&serviceHandle, SERVICE_CHANGE_CONFIG, (wchar_t*)NameStr.c_str())))
	{
		serviceHandle = NULL;
		win32Result = GetLastError();
		if (!CWinService__ShouldElevate(win32Result))
			return CWinService__Win32Error(win32Result);
		win32Result = 0;
	}

	auto Apply = [&](ULONG InfoLevel, void* Info, size_t Size) -> ULONG {
		if (serviceHandle)
			return ChangeServiceConfig2(serviceHandle, InfoLevel, Info) ? 0 : GetLastError();
		return CWinService__SvcChangeConfig2(Name, InfoLevel, Info, Size);
	};

	if (Extras.HasPreShutdownTimeout)
	{
		SERVICE_PRESHUTDOWN_INFO preshutdownInfo;
		preshutdownInfo.dwPreshutdownTimeout = Extras.PreShutdownTimeout;
		win32Result = Apply(SERVICE_CONFIG_PRESHUTDOWN_INFO, &preshutdownInfo, sizeof(preshutdownInfo));
	}

	if (Extras.HasPrivileges && win32Result == 0)
	{
		std::wstring sb;
		foreach(const QString& Privilege, Extras.Privileges)
		{
			sb.append(Privilege.toStdWString());
			sb.push_back(L'\0');
		}
		sb.push_back(L'\0');

		SERVICE_REQUIRED_PRIVILEGES_INFO requiredPrivilegesInfo;
		requiredPrivilegesInfo.pmszRequiredPrivileges = (wchar_t*)sb.c_str();
		win32Result = Apply(SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &requiredPrivilegesInfo, sizeof(requiredPrivilegesInfo));
	}

	if (Extras.HasSidType && win32Result == 0)
	{
		SERVICE_SID_INFO sidInfo;
		sidInfo.dwServiceSidType = Extras.SidType;
		win32Result = Apply(SERVICE_CONFIG_SERVICE_SID_INFO, &sidInfo, sizeof(sidInfo));
	}

	if (Extras.HasLaunchProtected && win32Result == 0)
	{
		SERVICE_LAUNCH_PROTECTED_INFO launchProtectedInfo;
		launchProtectedInfo.dwLaunchProtected = Extras.LaunchProtected;
		// as before: a failure to set protection is not reported
		Apply(SERVICE_CONFIG_LAUNCH_PROTECTED, &launchProtectedInfo, sizeof(launchProtectedInfo));
	}

	if (serviceHandle)
		CloseServiceHandle(serviceHandle);

	if (win32Result != 0)
		return CWinService__Win32Error(win32Result);
	return OK;
}

//
// ---- triggers ----
//

QList<CServiceInfo::STrigger> CWinService::GetTriggers() const
{
	QList<STrigger> Triggers;

	std::wstring Name = GetName().toStdWString();

	SC_HANDLE serviceHandle;
	if (!NT_SUCCESS(PhOpenService(&serviceHandle, SERVICE_QUERY_CONFIG, (wchar_t*)Name.c_str())))
		return Triggers;

	PSERVICE_TRIGGER_INFO triggerInfo;
	if (NT_SUCCESS(PhQueryServiceVariableSize(serviceHandle, SERVICE_CONFIG_TRIGGER_INFO, (PVOID*)&triggerInfo)))
	{
		for (ULONG i = 0; i < triggerInfo->cTriggers; i++)
		{
			PSERVICE_TRIGGER trigger = &triggerInfo->pTriggers[i];

			STrigger Trigger;
			Trigger.Type = trigger->dwTriggerType;
			Trigger.Action = trigger->dwAction;

			if (trigger->pTriggerSubtype)
			{
				PPH_STRING guid = PhFormatGuid(trigger->pTriggerSubtype);
				Trigger.Subtype = CastPhString(guid);
			}

			for (ULONG j = 0; j < trigger->cDataItems; j++)
			{
				PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM dataItem = &trigger->pDataItems[j];

				STriggerData Data;
				Data.Type = dataItem->dwDataType;

				switch (dataItem->dwDataType)
				{
				case SERVICE_TRIGGER_DATA_TYPE_STRING:
					//
					// A string item may hold several strings back to back; the
					// editor shows them one per line, as the original did.
					//
					if (dataItem->cbData >= sizeof(wchar_t))
					{
						PWSTR str = (PWSTR)dataItem->pData;
						ULONG chars = dataItem->cbData / sizeof(wchar_t);
						QStringList Parts;
						for (ULONG k = 0; k < chars; )
						{
							ULONG len = (ULONG)PhCountStringZ(str + k);
							if (len == 0)
								break;
							Parts.append(QString::fromWCharArray(str + k, len));
							k += len + 1;
						}
						Data.String = Parts.join("\n");
					}
					break;

				case SERVICE_TRIGGER_DATA_TYPE_BINARY:
					Data.Binary = QByteArray((char*)dataItem->pData, dataItem->cbData);
					break;

				case SERVICE_TRIGGER_DATA_TYPE_LEVEL:
					if (dataItem->cbData >= sizeof(UCHAR))
						Data.Number = *(UCHAR*)dataItem->pData;
					break;

				case SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY:
				case SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ALL:
					if (dataItem->cbData >= sizeof(ULONG64))
						Data.Number = *(ULONG64*)dataItem->pData;
					break;
				}

				Trigger.Data.append(Data);
			}

			Triggers.append(Trigger);
		}

		PhFree(triggerInfo);
	}

	CloseServiceHandle(serviceHandle);
	return Triggers;
}

STATUS CWinService::SetTriggers(const QList<STrigger>& Triggers, bool bHadTriggers)
{
	//
	// Writing an empty trigger set to a service that never had one is an error,
	// so do not ask.
	//
	if (!bHadTriggers && Triggers.isEmpty())
		return OK;

	const QString Name = GetName();
	std::wstring NameStr = Name.toStdWString();

	//
	// Everything the SERVICE_TRIGGER_INFO points at has to stay alive until
	// ChangeServiceConfig2 has read it, so the backing buffers are declared here
	// and not inside the loop.
	//
	QVector<SERVICE_TRIGGER> NativeTriggers(Triggers.count());
	QVector<GUID> Subtypes(Triggers.count());
	QVector<QVector<SERVICE_TRIGGER_SPECIFIC_DATA_ITEM> > NativeItems(Triggers.count());
	QVector<QVector<QByteArray> > ItemBuffers(Triggers.count());

	memset(NativeTriggers.data(), 0, NativeTriggers.count() * sizeof(SERVICE_TRIGGER));

	for (int i = 0; i < Triggers.count(); i++)
	{
		const STrigger& Trigger = Triggers[i];
		PSERVICE_TRIGGER pNative = &NativeTriggers[i];

		pNative->dwTriggerType = Trigger.Type;
		pNative->dwAction = Trigger.Action;

		if (!Trigger.Subtype.isEmpty())
		{
			std::wstring guid = Trigger.Subtype.toStdWString();
			PH_STRINGREF sr;
			sr.Buffer = (wchar_t*)guid.c_str();
			sr.Length = guid.length() * sizeof(wchar_t);
			if (NT_SUCCESS(PhStringToGuid(&sr, &Subtypes[i])))
				pNative->pTriggerSubtype = &Subtypes[i];
		}

		if (Trigger.Data.isEmpty())
			continue;

		NativeItems[i].resize(Trigger.Data.count());
		ItemBuffers[i].resize(Trigger.Data.count());
		memset(NativeItems[i].data(), 0, Trigger.Data.count() * sizeof(SERVICE_TRIGGER_SPECIFIC_DATA_ITEM));

		for (int j = 0; j < Trigger.Data.count(); j++)
		{
			const STriggerData& Data = Trigger.Data[j];
			PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM pItem = &NativeItems[i][j];
			QByteArray& Buffer = ItemBuffers[i][j];

			pItem->dwDataType = Data.Type;

			switch (Data.Type)
			{
			case SERVICE_TRIGGER_DATA_TYPE_STRING:
			{
				// back to a double-null-terminated run of strings
				foreach(const QString& Part, Data.String.split("\n", Qt::SkipEmptyParts))
				{
					std::wstring w = Part.toStdWString();
					Buffer.append((const char*)w.c_str(), (w.length() + 1) * sizeof(wchar_t));
				}
				Buffer.append(2, '\0');
				break;
			}
			case SERVICE_TRIGGER_DATA_TYPE_BINARY:
				Buffer = Data.Binary;
				break;
			case SERVICE_TRIGGER_DATA_TYPE_LEVEL:
			{
				UCHAR Level = (UCHAR)Data.Number;
				Buffer = QByteArray((char*)&Level, sizeof(UCHAR));
				break;
			}
			case SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY:
			case SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ALL:
			{
				ULONG64 Keyword = Data.Number;
				Buffer = QByteArray((char*)&Keyword, sizeof(ULONG64));
				break;
			}
			}

			pItem->cbData = Buffer.size();
			pItem->pData = (PBYTE)Buffer.data();
		}

		pNative->cDataItems = NativeItems[i].count();
		pNative->pDataItems = NativeItems[i].data();
	}

	SERVICE_TRIGGER_INFO triggerInfo;
	memset(&triggerInfo, 0, sizeof(SERVICE_TRIGGER_INFO));
	triggerInfo.cTriggers = Triggers.count();
	// pTriggers has to be NULL when there are none
	triggerInfo.pTriggers = Triggers.isEmpty() ? NULL : NativeTriggers.data();

	ULONG win32Result = 0;

	SC_HANDLE serviceHandle;
	if (NT_SUCCESS(PhOpenService(&serviceHandle, SERVICE_CHANGE_CONFIG, (wchar_t*)NameStr.c_str())))
	{
		if (!ChangeServiceConfig2(serviceHandle, SERVICE_CONFIG_TRIGGER_INFO, &triggerInfo))
			win32Result = GetLastError();

		CloseServiceHandle(serviceHandle);
	}
	else
	{
		win32Result = GetLastError();
		if (CWinService__ShouldElevate(win32Result))
			win32Result = CWinService__SvcChangeConfig2(Name, SERVICE_CONFIG_TRIGGER_INFO, &triggerInfo, sizeof(triggerInfo));
	}

	if (win32Result != 0)
		return CWinService__Win32Error(win32Result);
	return OK;
}

QList<CServiceInfo::STriggerSubtype> CWinService::GetTriggerSubtypes() const
{
	QList<STriggerSubtype> List;

	for (int i = 0; i < SubTypeEntryCount; i++)
	{
		if (!SubTypeEntries[i].Guid)
			continue;

		STriggerSubtype Subtype;
		Subtype.TriggerType = SubTypeEntries[i].Type;
		Subtype.Name = QString::fromWCharArray(SubTypeEntries[i].Name);

		PPH_STRING guid = PhFormatGuid((GUID*)SubTypeEntries[i].Guid);
		Subtype.Guid = CastPhString(guid);

		List.append(Subtype);
	}

	return List;
}

QList<QPair<QString, quint32> > CWinService::GetTriggerTypes() const
{
	QList<QPair<QString, quint32> > List;
	for (int i = 0; i < 8; i++)
		List.append(qMakePair(QString::fromWCharArray(TypeEntries[i].Name), (quint32)TypeEntries[i].Type));
	return List;
}

QStringList CWinService::GetEtwPublishers() const
{
	QStringList List;

	PETW_PUBLISHER_ENTRY entries;
	ULONG numberOfEntries;
	if (EspEnumerateEtwPublishers(&entries, &numberOfEntries))
	{
		for (ULONG i = 0; i < numberOfEntries; i++)
		{
			List.append(QString::fromWCharArray(entries[i].PublisherName->Buffer));
			PhDereferenceObject(entries[i].PublisherName);
		}
		PhFree(entries);
	}

	return List;
}

QString CWinService::GetEtwPublisherName(const QString& Guid) const
{
	std::wstring guid = Guid.toStdWString();
	PH_STRINGREF sr;
	sr.Buffer = (wchar_t*)guid.c_str();
	sr.Length = guid.length() * sizeof(wchar_t);

	GUID Subtype;
	if (!NT_SUCCESS(PhStringToGuid(&sr, &Subtype)))
		return QString();

	PPH_STRING publisherName = EspLookupEtwPublisherName(&Subtype);
	if (!publisherName)
		return QString();

	QString Name = QString::fromWCharArray(publisherName->Buffer);
	PhDereferenceObject(publisherName);
	return Name;
}

QString CWinService::GetEtwPublisherGuid(const QString& Name) const
{
	std::wstring name = Name.toStdWString();

	GUID Guid;
	if (!EspLookupEtwPublisherGuid((wchar_t*)name.c_str(), &Guid))
		return QString();

	PPH_STRING guid = PhFormatGuid(&Guid);
	return CastPhString(guid);
}

void CWinService::GetTriggerStrings(const STrigger& Trigger, QString& Description, QString& Action) const
{
	//
	// EspFormatTriggerInfo works on the platform structure, so build a throwaway
	// one from the portable trigger just to render it.
	//
	ES_TRIGGER_INFO Info;
	memset(&Info, 0, sizeof(ES_TRIGGER_INFO));

	GUID Subtype;
	Info.Type = Trigger.Type;
	Info.Action = Trigger.Action;

	if (!Trigger.Subtype.isEmpty())
	{
		std::wstring guid = Trigger.Subtype.toStdWString();
		PH_STRINGREF sr;
		sr.Buffer = (wchar_t*)guid.c_str();
		sr.Length = guid.length() * sizeof(wchar_t);
		if (NT_SUCCESS(PhStringToGuid(&sr, &Subtype)))
			Info.Subtype = &Subtype;
	}

	PWSTR triggerString = NULL;
	PWSTR actionString = NULL;
	PPH_STRING stringUsed = NULL;
	EspFormatTriggerInfo(&Info, &triggerString, &actionString, &stringUsed);

	if (triggerString)
		Description = QString::fromWCharArray(triggerString);
	if (actionString)
		Action = QString::fromWCharArray(actionString);

	if (stringUsed)
		PhDereferenceObject(stringUsed);
}

//
// ---- the dialog's combo box contents ----
//

static CServiceInfo::SLabeledValues CWinService__Pairs(PH_KEY_VALUE_PAIR* pPairs, int Count)
{
	//
	// These tables are declared with narrow literals - phlib's SIP macro does not
	// widen them - so the label is a char*, not a wchar_t*.
	//
	CServiceInfo::SLabeledValues List;
	for (int i = 0; i < Count; i++)
		List.append(qMakePair(QString::fromLatin1((const char*)pPairs[i].Key), (quint32)(quintptr)pPairs[i].Value));
	return List;
}

CServiceInfo::SLabeledValues CWinService::GetServiceTypes() const
{
	return CWinService__Pairs(PhpServiceTypePairs, 10);
}

CServiceInfo::SLabeledValues CWinService::GetStartTypes() const
{
	return CWinService__Pairs(PhpServiceStartTypePairs, 5);
}

CServiceInfo::SLabeledValues CWinService::GetErrorControlTypes() const
{
	return CWinService__Pairs(PhpServiceErrorControlPairs, 4);
}

CServiceInfo::SLabeledValues CWinService::GetRecoveryActionTypes() const
{
	return CWinService__Pairs(ServiceActionPairs, 4);
}

CServiceInfo::SLabeledValues CWinService::GetSidTypes() const
{
	return CWinService__Pairs(EspServiceSidTypePairs, 3);
}

CServiceInfo::SLabeledValues CWinService::GetLaunchProtectionTypes() const
{
	return CWinService__Pairs(EspServiceLaunchProtectedPairs, 4);
}

//
// The same tables as above, reached without a service object - the new
// service dialog needs them before there is anything to describe.
//
CServiceInfo::SLabeledValues CWindowsAPI::GetNewServiceTypes() const
{
	return CWinService__Pairs(PhpServiceTypePairs, 10);
}

CServiceInfo::SLabeledValues CWindowsAPI::GetNewServiceStartTypes() const
{
	return CWinService__Pairs(PhpServiceStartTypePairs, 5);
}

CServiceInfo::SLabeledValues CWindowsAPI::GetNewServiceErrorControlTypes() const
{
	return CWinService__Pairs(PhpServiceErrorControlPairs, 4);
}

void CWindowsAPI::SetMainWindow(quint64 Wnd)
{
	PhMainWndHandle = (HWND)Wnd;
}

STATUS CWindowsAPI::CreateNewService(const QString& Name, const QString& DisplayName, const QString& BinaryPath,
									 quint32 Type, quint32 StartType, quint32 ErrorControl)
{
	SC_HANDLE scManagerHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!scManagerHandle)
		return CWinService__Win32Error(GetLastError());

	//
	// The trailing L"" is the password for the (defaulted) LocalSystem account -
	// empty, not NULL, because NULL here means "do not change", which makes no
	// sense on a service that does not exist yet.
	//
	SC_HANDLE serviceHandle = CreateService(scManagerHandle,
		Name.toStdWString().c_str(), DisplayName.toStdWString().c_str(), SERVICE_CHANGE_CONFIG,
		Type, StartType, ErrorControl, BinaryPath.toStdWString().c_str(),
		NULL, NULL, NULL, NULL, L"");

	ULONG Win32Result = serviceHandle ? ERROR_SUCCESS : GetLastError();

	if (serviceHandle)
		CloseServiceHandle(serviceHandle);
	CloseServiceHandle(scManagerHandle);

	if (Win32Result != ERROR_SUCCESS)
		return CWinService__Win32Error(Win32Result);
	return OK;
}
