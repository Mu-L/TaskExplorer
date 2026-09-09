#include "stdafx.h"
#include "LinuxHandle.h"
#include "LinuxHelper.h"
#include "ProcFs.h"

#include <QFileInfo>

#include <fcntl.h>

//
// The open(2) flags are not numbered the same on every Linux architecture:
// arm64 has O_DIRECT and O_DIRECTORY the other way round from x86_64, and the
// less common ports differ more widely still. CHandleInfo::EOpenFlag has to be
// one fixed set of values regardless, because the viewer reading a handle can
// be running on a different machine than the target that reported it - so what
// fdinfo says is translated into that set rather than passed through. On
// x86_64, whose numbering EOpenFlag follows, the translation is the identity.
//
// The access mode is a two-bit field rather than a flag and is numbered alike
// everywhere on Linux, so it takes no entry below - only a guard.
//
static_assert(CHandleInfo::eOpenAccessMask   == O_ACCMODE,   "open access mask");
static_assert(CHandleInfo::eOpenReadOnly     == O_RDONLY,    "open read only");
static_assert(CHandleInfo::eOpenWriteOnly    == O_WRONLY,    "open write only");
static_assert(CHandleInfo::eOpenReadWrite    == O_RDWR,      "open read write");

static const struct { quint32 Local; quint32 Canonical; } g_OpenFlagMap[] =
{
	{ O_CLOEXEC,   CHandleInfo::eOpenCloseOnExec },
	{ O_APPEND,    CHandleInfo::eOpenAppend      },
	{ O_NONBLOCK,  CHandleInfo::eOpenNonBlock    },
	{ O_SYNC,      CHandleInfo::eOpenSync        },  // O_DSYNC | __O_SYNC, hence not a single bit
	{ O_DSYNC,     CHandleInfo::eOpenDSync       },
	{ O_ASYNC,     CHandleInfo::eOpenAsync       },
	{ O_DIRECT,    CHandleInfo::eOpenDirect      },
	{ O_DIRECTORY, CHandleInfo::eOpenDirectory   },
	{ O_NOATIME,   CHandleInfo::eOpenNoAtime     },
	{ O_PATH,      CHandleInfo::eOpenPath        },
};

//
// Which bits move is decided against the value read, never against what has
// been built so far - on an architecture that merely swaps two flags, undoing
// the first translation while applying the second would otherwise lose it.
//
// Bits with no name of their own (O_LARGEFILE, and whatever a later kernel
// starts reporting) stay where they are: nothing reads them by name, and
// keeping them leaves the raw mask a view shows the whole story.
//
static quint32 CanonicalOpenFlags(quint32 Flags)
{
	quint32 Translated = 0;
	quint32 Named = 0;
	for (size_t i = 0; i < sizeof(g_OpenFlagMap) / sizeof(g_OpenFlagMap[0]); i++)
	{
		if ((Flags & g_OpenFlagMap[i].Local) != g_OpenFlagMap[i].Local)
			continue;
		Named |= g_OpenFlagMap[i].Local;
		Translated |= g_OpenFlagMap[i].Canonical;
	}
	return (Flags & ~Named) | Translated;
}


CLinuxHandle::CLinuxHandle(QObject *parent)
	: CHandleInfo(parent)
{
	m_Type = eUnknown;
	m_Inode = 0;
	m_Flags = 0;
}

CLinuxHandle::~CLinuxHandle()
{
}

bool CLinuxHandle::InitStaticData(quint64 Pid, quint64 Fd)
{
	//
	// The fd symlink resolves either to a path (regular files, directories,
	// devices) or to a pseudo target naming the kernel object kind:
	//   socket:[12345]  pipe:[12345]  anon_inode:[eventfd]  anon_inode:inotify
	// The number in brackets is the inode, which is how a socket fd is later
	// joined against the sock_diag/proc/net tables.
	//
	const QString Target = ProcFs::ReadLink(ProcFs::ProcPath(Pid, QString("fd/%1").arg(Fd)));
	if (Target.isEmpty())
		return false; // closed already, or not permitted

	// fdinfo gives the current offset and the open flags.
	const QByteArray FdInfo = ProcFs::ReadFile(ProcFs::ProcPath(Pid, QString("fdinfo/%1").arg(Fd)));

	return InitStaticData(Pid, Fd, Target, FdInfo);
}

bool CLinuxHandle::InitStaticData(quint64 Pid, quint64 Fd, const QString& Target, const QByteArray& FdInfo)
{
	if (Target.isEmpty())
		return false;

	EHandleType Type = eUnknown;
	quint64 Inode = 0;

	auto BracketInode = [](const QString& Text) -> quint64 {
		const int Open = Text.indexOf('[');
		const int Close = Text.lastIndexOf(']');
		if (Open < 0 || Close <= Open)
			return 0;
		return Text.mid(Open + 1, Close - Open - 1).toULongLong();
	};

	if (Target.startsWith("socket:"))
	{
		Type = eSocket;
		Inode = BracketInode(Target);
	}
	else if (Target.startsWith("pipe:"))
	{
		Type = ePipe;
		Inode = BracketInode(Target);
	}
	else if (Target.startsWith("anon_inode:"))
	{
		Type = eAnonInode;
	}
	else
	{
		// A real path. Statting it says whether it is a directory or a device;
		// this can fail for a deleted file, which keeps eFile.
		Type = eFile;
		QFileInfo Info(Target);
		if (Info.isDir())
			Type = eDirectory;
		else if (Target.startsWith("/dev/"))
			Type = eCharDevice;
	}

	quint64 Position = 0;
	quint32 Flags = 0;
	for (const QByteArray& Line : FdInfo.split('\n'))
	{
		const int Sep = Line.indexOf(':');
		if (Sep < 0)
			continue;
		const QByteArray Key = Line.left(Sep).trimmed();
		const QByteArray Value = Line.mid(Sep + 1).trimmed();

		if (Key == "pos")
			Position = Value.toULongLong();
		else if (Key == "flags")
			Flags = Value.toUInt(nullptr, 8); // octal, as the kernel prints it
		else if (Key == "ino" && Inode == 0)
			Inode = Value.toULongLong();
	}

	QWriteLocker Locker(&m_Mutex);

	m_ProcessId = Pid;
	m_HandleId = Fd;
	m_FileName = Target;
	m_Type = Type;
	m_Inode = Inode;
	m_Flags = CanonicalOpenFlags(Flags);
	m_Position = Position;

	// Only meaningful for regular files; a socket or pipe has no size.
	if (Type == eFile)
	{
		QFileInfo Info(Target);
		if (Info.exists())
			m_Size = Info.size();
	}

	return true;
}

bool CLinuxHandle::UpdateDynamicData()
{
	const quint64 Pid = GetProcessId();
	const quint64 Fd = GetHandleId();

	return UpdateDynamicData(ProcFs::ReadFile(ProcFs::ProcPath(Pid, QString("fdinfo/%1").arg(Fd))));
}

bool CLinuxHandle::UpdateDynamicData(const QByteArray& FdInfo)
{
	quint64 Position = 0;
	if (FdInfo.isEmpty())
		return false;

	for (const QByteArray& Line : FdInfo.split('\n'))
	{
		if (!Line.startsWith("pos:"))
			continue;
		Position = Line.mid(4).trimmed().toULongLong();
		break;
	}

	QWriteLocker Locker(&m_Mutex);
	const bool bChanged = (m_Position != Position);
	m_Position = Position;
	return bChanged;
}

quint32 CLinuxHandle::GetTypeIndex() const
{
	QReadLocker Locker(&m_Mutex);
	return (quint32)m_Type;
}

QString CLinuxHandle::GetTypeName() const
{
	QReadLocker Locker(&m_Mutex);
	switch (m_Type)
	{
		case eFile:		return "File";
		case eDirectory:	return "Directory";
		case eSocket:		return "Socket";
		case ePipe:		return "Pipe";
		case eAnonInode:	return "AnonInode";
		case eCharDevice:	return "CharDevice";
		case eBlockDevice:	return "BlockDevice";
		default:		break;
	}
	return "Unknown";
}
quint32 CLinuxHandle::GetGrantedAccess() const
{
	QReadLocker Locker(&m_Mutex);
	return m_Flags;
}
STATUS CLinuxHandle::Close(bool bForce)
{
	// Linux has no equivalent of DuplicateHandle(DUPLICATE_CLOSE_SOURCE); an fd
	// belonging to another process can only be closed by ptrace-attaching and
	// issuing close() in its context.
	return ERR(TE_ClosingFileDesc);
}
