#pragma once

#include "../SystemAPI.h"
#include "LinuxProcess.h"
#include "LinuxSocket.h"
#include "LinuxService.h"
#include "LinuxDriver.h"
#include "ProcFs.h"
#include "UdevMonitor.h"

//
// The Linux system backend.
//
// This is the counterpart of CWindowsAPI and the single entry point the rest of
// the application uses; CSystemAPI::InitAPI() picks between the two.
//
// Data sources, by area:
//   processes  /proc/<pid>/{stat,statm,status,cmdline,exe,cwd,io}
//   threads    /proc/<pid>/task/<tid>/{stat,comm}
//   handles    /proc/<pid>/fd + fdinfo
//   sockets    sock_diag netlink, falling back to /proc/net/*
//   services   systemd over the D-Bus system bus
//   drivers    /proc/modules + /sys/module
//   sys stats  /proc/{stat,meminfo,uptime,loadavg}
//
class CLinuxAPI : public CSystemAPI
{
	Q_OBJECT

	TRACK_OBJECT(CLinuxAPI)
public:
	CLinuxAPI(QObject *parent = nullptr);
	virtual ~CLinuxAPI();


	virtual bool			RootAvaiable();

	//
	// pid 1's namespaces, read once. Nothing short of a reboot changes them,
	// and every process shown is compared against them.
	//
	virtual SProcessNamespaces	GetHostNamespaces() const;

	virtual EOsType GetOsType() const					{ return eOsLinux; }
	virtual quint64 GetCpuTimeDivider() const;   // CPU_TIME_DIVIDER, defined below the class
	virtual bool HasCapability(ECapability Capability) const;

	virtual bool			UpdateAll();
	virtual bool			UpdateSysStats();
	//
	// Pair Wine's Windows process ids with the Linux ones. Opt-in and
	// throttled; see the implementation for why both.
	//
	void					UpdateWineIds();
	quint64					m_LastWineQuery = 0;
	static const quint64	c_WineQueryMaxAge = 60000;

	virtual bool			UpdateProcessList();
	virtual bool			UpdateSocketList();
	virtual bool			UpdateOpenFileList();
	virtual bool			UpdateServiceList(bool bRefresh = false);
	//
	// What kinds of thing a descriptor can be here. The indexes are
	// CLinuxHandle::EHandleType, which is what GetTypeIndex returns, so the
	// handle view can filter on them without knowing what platform answered.
	//
	virtual QList<SHandleType> GetHandleTypes() const;
	virtual int				GetHandleTypeGroup(int Index) const;

	//
	// Which of them the Files views mean by "a file". Without this the base
	// returns -1 - every type - and those views listed sockets, pipes and
	// eventfds alongside the files, which is the one thing they exist not to do.
	//
	virtual int				GetFileHandleTypeIndex() const;

	virtual bool			UpdateDriverList();

	//
	// Fetches, in one batched request to an elevated TaskHelper, the I/O counters
	// of processes whose /proc/<pid>/io this user cannot read.
	//
	void					UpdateHelperProcIo();

	virtual void			ClearPersistence();

	virtual quint64			GetUpTime() const;
	virtual QList<SUser>	GetUsers() const;

	//
	// Starting programs - see LinuxRun.cpp. None of this was overridden, so the
	// base class refused and the run dialogs offered empty boxes above a button
	// that could not work.
	//
	virtual QStringList		GetRunHistory() const;
	virtual STATUS			RunProgram(const SRunOptions& Options);
	virtual SRunAsChoices	GetRunAsChoices() const;
	virtual bool			IsServiceAccount(const QString& UserName) const;
	virtual STATUS			RunProgramAs(const SRunAsOptions& Options);

protected:
	void					AddRunHistory(const QString& Program);
public:

	//
	// Unaltered: systemd unit names are case sensitive - see the note on the
	// base - and this backend files them exactly as systemd gave them.
	//
	virtual QString			CanonicalServiceName(const QString& Name) const { return Name; }

	virtual QMultiMap<QString, CDnsCacheEntryPtr>	GetDnsEntryList() const;
	virtual bool			UpdateDnsCache();
	virtual void			FlushDnsCache();

	//
	// Permits one further interactive polkit prompt for the cache dump.
	//
	// Reading the cache is an auth_admin_keep action, so the prompt has to be
	// rationed: the view refreshes on a timer and must not raise a password
	// dialog every few seconds. But a prompt that was cancelled should be
	// retryable without restarting the application.
	//
	// The DNS cache view calls this when it becomes visible, which makes
	// "navigate back to the tab" the way to try again. Once authentication has
	// succeeded no prompt appears at all, because the non-interactive call keeps
	// working for as long as polkit remembers it.
	//
	void					AllowDnsAuthPrompt()	{ m_bDnsAuthAttempted = false; }
	virtual void			AllowAuthPrompt()		{ AllowDnsAuthPrompt(); }

	// ---- Linux specifics ----

	//
	// Pressure Stall Information: the share of time work was stalled waiting
	// for cpu, memory or I/O. Valid is false when the kernel does not provide
	// it, which callers should treat as "nothing to show" rather than zero.
	//
	//
	// ProcFs parses into its own struct; the API publishes the platform
	// independent one so the graph bar never names a Linux type. The fields
	// are the same, so this is a copy rather than a translation.
	//
	static SPressure ToApiPressure(const ProcFs::SPressure& P)
	{
		SPressure R;
		R.SomeAvg10 = P.SomeAvg10;  R.SomeAvg60 = P.SomeAvg60;  R.SomeAvg300 = P.SomeAvg300;
		R.FullAvg10 = P.FullAvg10;  R.FullAvg60 = P.FullAvg60;  R.FullAvg300 = P.FullAvg300;
		R.SomeTotal = P.SomeTotal;  R.FullTotal = P.FullTotal;  R.Valid = P.Valid;
		return R;
	}

	virtual SPressure	GetCpuPressure() const		{ QReadLocker Locker(&m_StatsMutex); return ToApiPressure(m_CpuPressure); }
	virtual SPressure	GetMemoryPressure() const	{ QReadLocker Locker(&m_StatsMutex); return ToApiPressure(m_MemoryPressure); }
	virtual SPressure	GetIoPressure() const		{ QReadLocker Locker(&m_StatsMutex); return ToApiPressure(m_IoPressure); }

	// Distribution name and kernel release, for the system info panel.
	virtual QString			GetDistroName() const	{ QReadLocker Locker(&m_Mutex); return m_SystemName; }
	virtual QString			GetKernelVersion() const { QReadLocker Locker(&m_Mutex); return m_SystemVersion; }

	// Whether this build can see other users' processes in full detail, which
	// depends on being root or holding CAP_SYS_PTRACE.
	virtual bool			HasFullProcessAccess() const { return m_bFullAccess; }

private slots:
	virtual bool			Init();
	virtual void			OnHardwareChanged();

protected:
	// Reads the one-shot host facts: hostname, distro, kernel, cpu model and
	// topology, installed memory.
	virtual bool			InitSystemInfo();
	virtual bool			InitCpuInfo();

	// Samples /proc/stat and updates the aggregate and per-cpu usage figures.
	// Returns the total cpu ticks elapsed since the previous sample, which is
	// the divisor for per-process cpu percentages.
	virtual quint64			UpdateCpuStats();

	// Samples /proc/meminfo and /proc/swaps into the m_*Memory fields.
	virtual void			UpdateMemStats();

	// Previous /proc/stat sample, for the cpu usage deltas.
	ProcFs::SSysStat		m_LastSysStat;

	bool					m_bFullAccess;

	// Hotplug watch; null when the uevent socket could not be opened.
	class CUdevMonitor*	m_pUdevMonitor;

	//
	// Running totals of the per-process logical I/O deltas; see UpdateSysStats
	// for why these accumulate rather than being summed fresh each cycle.
	//
	quint64					m_TotalIoRead = 0;
	quint64					m_TotalIoReadOps = 0;
	quint64					m_TotalIoWrite = 0;
	quint64					m_TotalIoWriteOps = 0;

	//
	// System-wide Pressure Stall Information, sampled in UpdateSysStats.
	// Guarded by m_StatsMutex like the other counters.
	//
	ProcFs::SPressure		m_CpuPressure;
	ProcFs::SPressure		m_MemoryPressure;
	ProcFs::SPressure		m_IoPressure;

	//
	// The DNS cache, as last read from systemd-resolved. Keyed by host name,
	// multi-valued because one name commonly has several records.
	//
	mutable QReadWriteLock	m_DnsMutex;
	QMultiMap<QString, CDnsCacheEntryPtr>	m_DnsCache;

	// Whether the one interactive polkit prompt for the cache dump has already
	// been offered this run; see UpdateDnsCache.
	bool					m_bDnsAuthAttempted;
};

//
// The Windows backend measures cpu time in 100ns units; on Linux the /proc
// counters are in clock ticks, so this is sysconf(_SC_CLK_TCK) rather than a
// fixed constant.
//
#define CPU_TIME_DIVIDER (ProcFs::ClockTicksPerSec())
