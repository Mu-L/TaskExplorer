#pragma once
#include <qwidget.h>
#include "../../API/ProcessInfo.h"
#include "../../../MiscHelpers/Common/TreeItemModel.h"

class CProcessModel : public CTreeItemModel
{
    Q_OBJECT

public:
	//
	// What grouping by account groups by: the account on Linux, the logon
	// session on Windows. See the definition.
	//
	// Public and static because CProcessModel is not the only thing that has to
	// agree with it - SameUser decides whether a child continues its parent's
	// chain and has to ask exactly the same question.
	//
	static QString			GetGroupKey(const CProcessPtr& pProcess);
	static QString			GroupDisplayName(const QString& Key, const QString& Resolved);

    CProcessModel(QObject *parent = 0);
	~CProcessModel();

	void			SetUseDescr(int iDescr)	{ m_iUseDescr = iDescr; }

	//
	// Group the list by the account each process runs as.
	//
	// Orthogonal to tree/list: in list mode the processes become leaves under
	// their user, in tree mode each user's branch holds the part of the process
	// tree that belongs to it. A child that runs as somebody else moves to that
	// somebody's branch and loses its line to its parent - which is a real
	// loss, and deliberate: the alternative is nesting whole subtrees under
	// whoever started them, which would put half of Windows under System and
	// make the grouping useless. "Go to parent" is how you follow the link that
	// is no longer drawn.
	//
	void			SetMultiUser(bool bSet);
	bool			IsMultiUser() const		{ return m_bMultiUser; }

	//
	// Group by the machine each process was observed on.
	//
	// The third independent axis. With it on, every path starts with the
	// machine - so a cluster reads machine, then account if grouping by user is
	// on too, then the process tree if that is on. The local machine gets a
	// branch like any other rather than sitting loose at the root, because a
	// list where one machine is implicit and the rest are labelled is a list
	// nobody can read.
	//
	void			SetMultiMachine(bool bSet);
	bool			IsMultiMachine() const	{ return m_bMultiMachine; }

	//
	// A machine keeps its row whether or not it currently has processes under
	// it. It is there because somebody asked for it to be there, and it goes
	// when they say so - not when the machine stops answering.
	//
	// Which is exactly why this asks whether the machine is still in view rather
	// than only whether the branch looks like a machine: once it has been
	// disconnected there is no machine behind the id, and a pinned branch with
	// nothing to name it would sit there as a blank row for ever.
	//
	virtual bool	IsBranchPinned(const QVariant& Id) const;

	//
	// Which wire fields the columns currently shown are built from - see
	// API_REQ_FIELDS. Only the ones a target actually sends appear here; a
	// column drawn from something that is not on the wire has nothing to ask
	// for and is simply blank against a remote machine.
	//
	QSet<quint32>			GetWantedFields() const;

	//
	// One list per machine, not one merged list.
	//
	// SProcessUID is a pid and a creation time: unique on one machine and not
	// across several. Merging loses every row whose key another machine also
	// has - which, with a server on the same machine, is all of them - and
	// makes a process look up its parent among another machine's.
	//
	QSet<quint64>	Sync(const QList<QMap<SProcessUID, CProcessPtr> >& Lists);

	//
	// For the views that only ever show one machine's processes - the picker,
	// the job view - where a single list is the whole set.
	//
	QSet<quint64>	Sync(const QMap<SProcessUID, CProcessPtr>& List)
					{ return Sync(QList<QMap<SProcessUID, CProcessPtr> >() << List); }

	CProcessPtr		GetProcess(const QModelIndex &index) const;

	//
	// What kind of row this is. A branch has no process behind it, so anything
	// that would act on one has to ask first.
	//
	enum ERowKind
	{
		eProcessRow = 0,
		eMachineRow,
		eUserRow
	};
	ERowKind		GetRowKind(const QModelIndex &index, QString* pKey = NULL) const;

	//
	// The system a machine branch stands for, so that a menu on it can act on
	// that machine. Null for anything else.
	//
	CSystemAPI*		GetBranchSystem(const QModelIndex &index) const;

	//
	// The row a machine's branch is drawn as, or an invalid index where there
	// is no machine level or that machine has no row yet.
	//
	QModelIndex			FindMachineBranch(CSystemAPI* pSystem);

	//
	// The machine a branch id names, or null once it has gone. See
	// MkMachineBranch: the id is the system pointer written out, and this checks
	// it against the machines currently in view rather than casting it back.
	//
	static CSystemAPI* SystemFromBranchId(const QString& Key);

    int				columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant		headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;

	QString			GetColumHeader(int column) const;

	//
	// Column identities, in the order they appear in the header menu.
	//
	// The menu is built from ranges of this enum - see AddHeaderSubMenu in
	// ProcessTree.cpp - so each group has to stay contiguous, and the order
	// here is the order the user sees. Groups run roughly from "what is this
	// process" through the numbers people watch, to the genuinely niche.
	//
	// Every column exists against every target; whether one is worth offering
	// is decided at runtime from GetOsType()/HasCapability(), not here.
	//
	enum EColumns
	{
		eProcess = 0,

		// ---- identity (shown ungrouped at the top of the header menu) ----
		ePID,
		eDescription,			// what actually names an unfamiliar process
		eStatus,
		eUserName,
		eServices,
		eSessionID,
		eParentPID,
		eConsolePID,
		eElevation,
		eStartTime,
		eUpTime,
		eCommandLine,			// last: unbounded width

		// ---- CPU ----
		eCPU,
		eTotalCPU_Time,
		eKernelCPU_Time,
		eUserCPU_Time,
		eContextSwitches,
		eContextSwitchesDelta,
		eCycles,
		eCyclesDelta,

		// ---- memory ----
		ePrivateBytes,
		ePrivateBytesDelta,
		ePeakPrivateBytes,
		eWorkingSet,
		ePeakWS,
		ePrivateWS,
		eSharedWS,
		eShareableWS,
		eMinimumWS,
		eMaximumWS,
		eVirtualSize,
		ePeakVirtualSize,
		eShareableCommit,
		ePageFaults,
		ePageFaultsDelta,
		eHardFaults,
		eHardFaultsDelta,
		ePagedPool,
		ePeakPagedPool,
		eNonPagedPool,
		ePeakNonPagedPool,
		eTLS,

		// ---- disk I/O ----
		eDisk_TotalRate,
		eReads,
		eWrites,
		eReadBytes,
		eWriteBytes,
		eReadsDelta,
		eWritesDelta,
		eReadBytesDelta,
		eWriteBytesDelta,
		eReadRate,
		eWriteRate,

		// ---- network I/O ----
		eNet_TotalRate,
		eNetUsage,
		eReceives,
		eSends,
		eReceiveBytes,
		eSendBytes,
		eReceivesDelta,
		eSendsDelta,
		eReceiveBytesDelta,
		eSendBytesDelta,
		eReceiveRate,
		eSendRate,

		// ---- file I/O ----
		eIO_TotalRate,
		eIO_Reads,
		eIO_Writes,
		eIO_Other,
		eIO_ReadBytes,
		eIO_WriteBytes,
		eIO_OtherBytes,
		eIO_ReadsDelta,
		eIO_WritesDelta,
		eIO_OtherDelta,
		eIO_ReadBytesDelta,
		eIO_WriteBytesDelta,
		eIO_OtherBytesDelta,
		eIO_ReadRate,
		eIO_WriteRate,
		eIO_OtherRate,

		// ---- GPU ----
		eGPU_Usage,
		eGPU_Shared,
		eGPU_Dedicated,
		eGPU_Adapter,

		// ---- objects ----
		eHandles,
		ePeakHandles,
		eThreads,
		ePeakThreads,
		eWND_Handles,
		eGDI_Handles,
		eUSER_Handles,

		// ---- scheduling ----
		ePriorityClass,
		eBasePriority,
		ePagePriority,
		eIO_Priority,
		ePriorityBoost,
		eAffinity,

		// ---- lifetime and responsiveness ----
		eRunningTime,
		eSuspendedTime,
		eHangCount,
		eGhostCount,
		ePowerThrottling,

		// ---- graphs ----
		eCPU_History,
		eMEM_History,
		eIO_History,
		eNET_History,
		eGPU_History,
		eVMEM_History,

		// ---- file info ----
		eFileName,
		eCompanyName,
		eVersion,
		eTimeStamp,
		eFileModifiedTime,
		eFileSize,

		//
		// ---- security ----
		//
		// Both platforms' trust and confinement columns. Windows reports an
		// integrity level, a signature and mitigations; Linux an LSM profile, a
		// container and the OOM killer's view of the process.
		//
		eIntegrity,
		eVirtualized,
		eVerificationStatus,
		eVerifiedSigner,
		eMitigations,
		eImageCoherency,
		eProtection,
		eCritical,
		eConfinement,
		eContainer,
		eOomScore,
		eOomScoreAdj,

		//
		// ---- platform ----
		//
		// The genuinely system-specific remainder, which used to share the
		// "Other" bucket with everything else.
		//
		ePID_LXSS,
		ePackageName,
		eAppID,
		eDPI_Awareness,
		eJobObjectID,
		eDesktop,
		eWindowTitle,
		eWindowStatus,
		eOS_Context,
		eErrorMode,
		eCodePage,
		eReferences,
		eGrantedAccess,
		eCGroup,
		eInotifyWatches,

		// ---- other ----
		eArchitecture,
		eSubsystem,
		eDebugTotal,
		eSequenceNumber,
		eStartKey,

		eCount
	};

protected:
	struct SProcessNode: STreeNode
	{
		SProcessNode(const QVariant& Id) : STreeNode(Id), iColor(0) { }

		CProcessPtr			pProcess;

		int					iColor;

		QSet<int>			Bold;
	};

	virtual QVariant		NodeData(STreeNode* pNode, int role, int section) const;

	virtual STreeNode*		MkNode(const QVariant& Id) { return new SProcessNode(Id); }

	//
	// The user branches are virtual nodes - nothing in the process list
	// corresponds to them, they exist because a path names them. This is where
	// they get something to show.
	//
	virtual STreeNode*		MkVirtualNode(const QVariant& Id, STreeNode* pParent);

	//
	// Fill in the branches that are already there - label, state and numbers.
	//
	// The label has to be redone every round because MkVirtualNode runs once,
	// when a branch is created, and on Windows the name is not known yet at
	// that moment: CSidResolver answers "Resolving..." and finishes the lookup
	// asynchronously. Without this every account first seen while the tree was
	// being built would keep that word as its heading for the life of the
	// window.
	//
	// The columns are done here for a different reason: a branch is not in the
	// process loop in Sync at all, so this is the only thing that ever writes
	// to one.
	//
	void					UpdateBranches(STreeNode* pParent, bool bClearZeros);
	void					FillBranch(STreeNode* pNode, bool bClearZeros);

	//
	// Which columns a branch may add up. See the note above the definition for
	// what is deliberately not in the list.
	//
	static bool				IsSummableColumn(int section);

	//
	// The rows underneath, added up, and what the machine says about itself.
	// The second overrides the first where the machine's own figure is the
	// better answer rather than merely a different one.
	//
	void					SumSubtree(STreeNode* pNode, QVector<double>& Sums, QSet<int>& NotAvailable) const;
	void					FillMachineColumns(CSystemAPI* pSystem, QVector<QVariant>& New) const;

	QVariant				FormatBranchValue(int section, const QVariant& Value, bool bClearZeros) const;

	//
	// The id of a user's branch. A string, so it can never collide with a
	// process node's id, which is always the numeric SProcessUID.
	//
	//
	// Where a row belongs, in whichever combination of the two modes is on.
	//
	// The account branch and the parent/child nesting are independent: turning
	// the tree off drops the nesting and nothing else, so in list mode with
	// grouping on a process still sits under its account rather than at the
	// root. MakeProcPath/TestProcPath below handle the tree half only.
	//
	QList<QVariant>			MakePath(const CProcessPtr& pProcess, const QMap<SProcessUID, CProcessPtr>& ProcessList);
	bool					TestPath(const QList<QVariant>& Path, const CProcessPtr& pProcess, const QMap<SProcessUID, CProcessPtr>& ProcessList);

	QVariant				MkUserBranch(const QString& UserKey, CSystemAPI* pSystem) const;
	static bool				IsUserBranch(const QVariant& Id, QString* pUserKey = NULL);


	static QVariant			MkMachineBranch(CSystemAPI* pSystem);
	static bool				IsMachineBranch(const QVariant& Id);

	bool					m_bMultiUser;
	bool					m_bMultiMachine;

	//
	// Branch id to display name, for machines as m_UserNames is for accounts.
	//
	QMap<QString, QString>	m_MachineNames;
	QMap<QString, QString>	m_MachineStates;

	//
	// Key to display name, gathered while walking the process list so that the
	// branches can be labelled when they are created afterwards.
	//
	QMap<QString, QString>	m_UserNames;
		
	QList<QVariant>			MakeProcPath(const CProcessPtr& pProcess, const QMap<SProcessUID, CProcessPtr>& ProcessList);
	bool					TestProcPath(const QList<QVariant>& Path, const CProcessPtr& pProcess, const QMap<SProcessUID, CProcessPtr>& ProcessList, int Index = 0, int Head = 0);
	
	int						m_iUseDescr;

	virtual QVariant GetDefaultIcon() const;
};