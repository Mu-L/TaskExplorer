#pragma once
#include "../../taskcore_global.h"

TASKCORE_EXPORT bool IsElevated();
TASKCORE_EXPORT int RunElevated(const std::wstring& Params, bool bGetCode = false);
//
// TimeoutMs bounds the wait when bGetCode is set. The default is what this
// always did; anything that puts a UAC prompt in front of real work wants
// longer, because the clock includes however long the person takes to answer
// it.
//
TASKCORE_EXPORT int RunElevated(const std::wstring& binaryPath, const std::wstring& Params, bool bGetCode = false, int TimeoutMs = 10000);
TASKCORE_EXPORT int RestartElevated(int &argc, char **argv);

TASKCORE_EXPORT bool IsAutorunEnabled();
TASKCORE_EXPORT bool AutorunEnable(bool is_enable);

TASKCORE_EXPORT int SkipUacRun(bool test_only = false);
TASKCORE_EXPORT bool SkipUacEnable(bool is_enable);

TASKCORE_EXPORT void create_process_as_trusted_installer(std::wstring command_line);