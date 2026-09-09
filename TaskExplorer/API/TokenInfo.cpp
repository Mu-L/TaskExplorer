#include "stdafx.h"
#include "TokenInfo.h"

//
// Attribute predicates for tokens.
//
// These are pure questions about the attribute bitmasks carried in SGroup and
// SPrivilege, so they belong with the types rather than with any one backend.
// A group's or privilege's attributes arrive over the wire as plain numbers and
// are read without any Win32 header in sight; how they are worded is the
// viewer's business, and lives in GUI/TaskStrings.cpp.
//

bool CTokenInfo::IsPrivilegeEnabled(quint32 Attributes)
{
	return (Attributes & ePrivilegeEnabled) != 0;
}

bool CTokenInfo::IsPrivilegeModified(quint32 Attributes)
{
	return ((Attributes & ePrivilegeEnabled) != 0) != ((Attributes & ePrivilegeEnabledByDefault) != 0);
}

bool CTokenInfo::IsGroupEnabled(quint32 Attributes)
{
	return (Attributes & eGroupEnabled) != 0;
}

bool CTokenInfo::IsGroupModified(quint32 Attributes)
{
	//
	// An integrity group is enabled by the level it stands for, not by anything
	// anyone did to it, so it is never "modified".
	//
	if ((Attributes & (eGroupIntegrity | eGroupIntegrityEnabled)) != 0 && (Attributes & eGroupEnabled) != 0)
		return false;

	return ((Attributes & eGroupEnabled) != 0) != ((Attributes & eGroupEnabledByDefault) != 0);
}
