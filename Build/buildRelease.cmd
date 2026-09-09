@echo off
echo Current dir: %cd%
echo folder: %~dp0
echo arch: %1

call prepTools.cmd %*

echo build_arch: %build_arch%

IF NOT DEFINED build_arch (
  echo Usage: buildRelease.cmd [Win32,x64,ARM64]
  goto eof
)

rem echo on

call %~dp0.\buildModule.cmd qtsingleapp %~dp0..\QtSingleApp\qtsingleapp\qtsingleapp\qtsingleapp.qc.pro
if NOT EXIST %~dp0..\bin\%build_arch%\Release\qtsingleapp.dll goto :error

call %~dp0.\buildModule.cmd qtservice %~dp0..\qtservice\qtservice\qtservice\qtservice.qc.pro
if NOT EXIST %~dp0..\bin\%build_arch%\Release\qtservice.dll goto :error

call %~dp0.\buildModule.cmd qwt %~dp0..\qwt\qwt\qwt.qc.pro
if NOT EXIST %~dp0..\bin\%build_arch%\Release\qwt.dll goto :error

call %~dp0.\buildModule.cmd qhexedit %~dp0..\qhexedit\src\qhexedit.qc.pro
if NOT EXIST %~dp0..\bin\%build_arch%\Release\qhexedit.dll goto :error

call %~dp0.\buildModule.cmd qextwidgets %~dp0..\qextwidgets\qextwidgets.qc.pro
if NOT EXIST %~dp0..\bin\%build_arch%\Release\qextwidgets.dll goto :error

rem
rem CoreHelpers before GuiHelpers: GuiHelpers links it. What used to be one
rem MiscHelpers is these two, so that the collector can be built without
rem QtWidgets - see TODO.md, "The MiscHelpers split".
rem
call %~dp0.\buildModule.cmd CoreHelpers %~dp0..\MiscHelpers\CoreHelpers.qc.pro
if NOT EXIST %~dp0..\bin\%build_arch%\Release\CoreHelpers.dll goto :error

call %~dp0.\buildModule.cmd GuiHelpers %~dp0..\MiscHelpers\GuiHelpers.qc.pro
if NOT EXIST %~dp0..\bin\%build_arch%\Release\GuiHelpers.dll goto :error

rem
rem This builds a monolithic TaskExplorer.exe: TaskExplorer.pri lists the API
rem sources itself, so unlike the MSVC and CMake builds there is no TaskCore
rem library on this path and no step for one is missing.
rem
call %~dp0.\buildModule.cmd TaskExplorer %~dp0..\TaskExplorer\TaskExplorer.qc.pro
if NOT EXIST %~dp0..\bin\%build_arch%\Release\TaskExplorer.exe goto :error


rem dir .\bin
rem dir .\bin\%build_arch%
rem dir .\bin\%build_arch%\Release

goto :eof

:error
echo Failed
exit 1

:eof