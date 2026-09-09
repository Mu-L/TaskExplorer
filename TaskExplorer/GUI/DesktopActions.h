#pragma once
#include "../API/SystemAPI.h"

//
// Things that happen on the desk in front of the person looking.
//
// Opening a folder, pointing a registry editor at a key, showing a certificate
// dialog - none of these are questions about a machine, they are actions on a
// desktop. The collector used to do them, which was harmless while it only ever
// watched the machine it ran on, and becomes wrong the moment it does not: a
// daemon has no desktop to open anything on, and opening a folder on the server
// is not what anyone asking meant.
//
// So the collector reports what to open - a path, a key - and these do the
// opening, here, on this machine. When the target is not this machine there is
// nothing sensible to do, and each of them says so rather than acting on the
// wrong one.
//

//
// Reveal a file in the system's file manager. Where the platform can select the
// file inside its folder it does; where it cannot, the folder is opened and the
// file is left to be spotted.
//
STATUS ExploreFile(CSystemAPI* pSystem, const QString& Path);

//
// Point the registry editor at a key. Windows only; elsewhere there is no
// registry and no editor for one.
//
STATUS OpenRegistryKey(CSystemAPI* pSystem, const QString& KeyPath);

//
// Show the platform's own signature dialog for a file.
//
STATUS ShowCertificate(CSystemAPI* pSystem, const QString& FilePath);
