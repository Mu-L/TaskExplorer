#include "stdafx.h"
#include "TaskExplorer.h"
#include "DesktopActions.h"

#include <QDesktopServices>
#include <QProcess>
#include <QSettings>
#include <QUrl>

#ifdef WIN32
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#endif

//
// The one thing every action here has to establish first.
//
static STATUS RequireLocal(CSystemAPI* pSystem)
{
	if (pSystem && !pSystem->IsLocal())
	{
		return ERR(TE_Message, QVariantList() << CTaskExplorer::tr(
			"This can only be done on the machine TaskExplorer is running on, "
			"and the target is another one."));
	}
	return OK;
}

STATUS ExploreFile(CSystemAPI* pSystem, const QString& Path)
{
	STATUS Status = RequireLocal(pSystem);
	if (Status.IsError())
		return Status;

	if (Path.isEmpty())
		return ERR(TE_NoFileName);

	const QFileInfo Info(Path);

#ifdef WIN32
	//
	// Explorer can select the file inside its folder, which is more useful than
	// opening the folder and leaving the user to find it. The path is quoted
	// because /select, takes the rest of the line as one argument.
	//
	if (Info.exists())
	{
		const QString Native = QDir::toNativeSeparators(Info.absoluteFilePath());
		if (QProcess::startDetached("explorer.exe", QStringList() << ("/select," + Native)))
			return OK;
	}
#endif

	//
	// Everywhere else, and as the fallback: open the containing directory.
	// There is no portable equivalent of "select this file" across file
	// managers, so the file is left to be spotted.
	//
	const QString Directory = Info.absolutePath();
	if (Directory.isEmpty())
		return ERR(TE_NoFileName);

	if (!QDesktopServices::openUrl(QUrl::fromLocalFile(Directory)))
		return ERR(TE_Message, QVariantList() << CTaskExplorer::tr("No file manager could be started."));

	return OK;
}

STATUS OpenRegistryKey(CSystemAPI* pSystem, const QString& KeyPath)
{
	STATUS Status = RequireLocal(pSystem);
	if (Status.IsError())
		return Status;

	if (KeyPath.isEmpty())
		return ERR(TE_NotSupported);

#ifdef WIN32
	//
	// regedit has no command line for "open at this key". It reopens wherever
	// it was last left, and where that was is a value it reads on startup - so
	// the way to send it somewhere is to write that value first.
	//
	QSettings Regedit("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit",
					  QSettings::NativeFormat);
	Regedit.setValue("LastKey", KeyPath);
	Regedit.sync();

	if (!QProcess::startDetached("regedit.exe", QStringList()))
		return ERR(TE_Message, QVariantList() << CTaskExplorer::tr("The registry editor could not be started."));

	return OK;
#else
	Q_UNUSED(KeyPath);
	return ERR(TE_NotSupported);
#endif
}

STATUS ShowCertificate(CSystemAPI* pSystem, const QString& FilePath)
{
	STATUS Status = RequireLocal(pSystem);
	if (Status.IsError())
		return Status;

	if (FilePath.isEmpty())
		return ERR(TE_NoFileName);

#ifdef WIN32
	//
	// The shell's own file properties dialog, opened on its signatures page.
	//
	// This shows the signature embedded in the file. A packaged application is
	// signed through its package catalog instead, and that dialog does not know
	// to look there - the previous version of this reached into phlib's catalog
	// verification, which the viewer deliberately cannot call any more. For a
	// Store app the page will therefore be empty even though the app is signed.
	//
	const std::wstring Native = QDir::toNativeSeparators(FilePath).toStdWString();
	const HRESULT Result = SHObjectProperties(NULL, SHOP_FILEPATH,
											  Native.c_str(), L"Digital Signatures");
	if (FAILED(Result))
		return ERR(TE_Message, QVariantList() << CTaskExplorer::tr("The signature dialog could not be shown."));

	return OK;
#else
	Q_UNUSED(FilePath);
	return ERR(TE_NotSupported);
#endif
}
