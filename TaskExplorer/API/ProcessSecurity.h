#pragma once
#include "../taskcore_global.h"
#include <QString>

//
// What a process is allowed to do, and what it has been isolated from.
//
// These were `ProcFs::SNamespaces` and `ProcFs::SProcSecurity`, and the
// security view read them by calling ProcFs itself - so it asked its own /proc
// about a pid that may belong to another machine entirely, and would not have
// compiled on Windows at all. They are values now, and a process hands them
// over already read.
//
// Both are described in Linux terms because that is where they come from, but
// the shape is not Linux-specific: a capability mask is what a Windows token
// privilege set is, and a namespace inode is one way of saying "this process
// sees a different world from the host". A backend that has neither leaves
// Valid false and the view says so.
//

//
// The inode number of each of a process's namespaces, or 0 where the link
// could not be read - which needs ptrace access for another user's process.
//
// Comparing these against pid 1's is how a container or sandbox is detected:
// anything differing means the process is isolated from the host in that
// dimension. Ask the *system* for the host's set, not the local machine.
//
struct SProcessNamespaces
{
	quint64	Pid = 0, Net = 0, Mnt = 0, User = 0;
	quint64	Uts = 0, Ipc = 0, CGroup = 0, Time = 0;
};

struct SProcessSecurity
{
	bool	Valid = false;

	// Capability sets, as bit masks. Inheritable, permitted, effective,
	// bounding and ambient respectively.
	quint64	CapInh = 0, CapPrm = 0, CapEff = 0, CapBnd = 0, CapAmb = 0;

	// The LSM label: an AppArmor profile ("snap.firefox.firefox (enforce)") or
	// an SELinux context. Empty when no LSM is active; "unconfined" when one is
	// but this process is not confined by it.
	QString	Confinement;

	int		Seccomp = 0;			// 0 disabled, 1 strict, 2 filter
	quint64	SeccompFilters = 0;
	bool	NoNewPrivs = false;
};
