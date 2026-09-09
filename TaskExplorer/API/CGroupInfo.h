#pragma once
#include "../taskcore_global.h"
#include <QString>
#include <QStringList>

//
// Resource control accounting, as values rather than as a place to read them.
//
// These structures were `ProcFs::SCGroupStats` and `ProcFs::SPressure`, which
// put them in the Linux backend - and the cgroup view read them by calling
// ProcFs directly from the GUI. That works exactly once: on the machine the
// window is running on. A viewer watching a daemon would have gone to its own
// /sys/fs/cgroup and shown numbers belonging to the wrong computer, and a
// viewer on Windows would not have compiled at all.
//
// So they live here, and a process hands them over already read. ProcFs still
// does the reading; it is the collector's business, and CLinuxProcess is a
// collector.
//
// The names are deliberately not Linux ones. A cgroup is where these come from
// today, but the notions - how much memory this group of tasks is using, how
// long it spent stalled waiting for a resource - are not specific to it, and a
// Windows job object reports several of the same things.
//

//
// Pressure stall information: what fraction of the time something was blocked
// waiting for a resource.
//
// "Some" is any task stalled, "full" is every task stalled - the second being
// the more serious of the two. The averages are percentages over the last 10,
// 60 and 300 seconds; the totals are cumulative microseconds.
//
struct SResourcePressure
{
	float	SomeAvg10 = 0, SomeAvg60 = 0, SomeAvg300 = 0;
	float	FullAvg10 = 0, FullAvg60 = 0, FullAvg300 = 0;
	quint64	SomeTotal = 0, FullTotal = 0;
	bool	Valid = false;
};

//
// What a resource-control group is accounting for.
//
// Valid says whether anything was readable at all; a caller that shows these
// must check it, because zero is a legitimate value for most of the rest.
//
struct SCGroupStats
{
	bool		Valid = false;

	quint64		MemoryCurrent = 0;
	quint64		MemoryPeak = 0;
	quint64		MemoryMax = 0;			// 0 = unlimited
	quint64		MemoryHigh = 0;			// throttling threshold, 0 = unset
	quint64		MemorySwapCurrent = 0;
	quint64		MemorySwapMax = 0;

	// microseconds
	quint64		CpuUsageUs = 0;
	quint64		CpuUserUs = 0;
	quint64		CpuSystemUs = 0;

	// Throttling, present only when a cpu limit is set.
	quint64		NrPeriods = 0;
	quint64		NrThrottled = 0;
	quint64		ThrottledUs = 0;

	quint64		PidsCurrent = 0;
	quint64		PidsMax = 0;			// 0 = unlimited

	// summed over all block devices
	quint64		IoReadBytes = 0;
	quint64		IoWriteBytes = 0;

	QStringList	Controllers;
};
