#pragma once
#include "../HandleInfo.h"
#include "../SystemAPI.h"

class CVariant;

//
// One entry from the object table of a process running under Wine.
//
// A Wine process holds two unrelated sets of handles. The kernel gave it file
// descriptors - the socket to wineserver, the mapped files, the pipes - and
// those are in /proc/<pid>/fd like any other process's. The program itself
// opened events, mutexes, keys and sections, and those are wineserver objects
// that the kernel has never heard of and /proc cannot show. This is one of the
// second kind; CLinuxHandle is one of the first, and a Wine process's list has
// both in it.
//
// The numbering keeps them apart. Linux type indexes are CLinuxHandle's enum,
// counted from zero; these start at c_TypeBase, so a filter set to "Event" can
// never match a descriptor and one set to "Socket" can never match a wineserver
// object. Both sets travel in the handshake, tagged with which is which, and
// the viewer offers the second only while a Wine process is selected.
//
//
// Where a Wine handle sits in a process's handle map.
//
// The map is keyed by the descriptor number for the Linux half, and a Windows
// handle value is a small number too - 4, 8, 0x1c. Without an offset the two
// would collide and take turns overwriting each other every round. Above every
// descriptor a process can have: the ceiling is a per-process limit measured in
// thousands, not billions.
//
static const quint64 c_WineHandleKey = 0x0000000100000000ull;

class CWineHandle : public CHandleInfo
{
	Q_OBJECT
public:
	CWineHandle(QObject* parent = NULL);

	//
	// Fill from one entry of a "Handles" reply. False for an entry that carried
	// no handle value, which is the only part that has to be there.
	//
	bool					Apply(quint64 Pid, const CVariant& Entry);

	virtual quint32			GetTypeIndex() const			{ QReadLocker Locker(&m_Mutex); return m_TypeIndex; }
	virtual QString			GetTypeName() const				{ QReadLocker Locker(&m_Mutex); return m_TypeName; }
	virtual quint32			GetGrantedAccess() const		{ QReadLocker Locker(&m_Mutex); return m_Access; }
	virtual quint32			GetAttributes() const			{ QReadLocker Locker(&m_Mutex); return m_Attributes; }
	virtual bool			IsInherited() const				{ QReadLocker Locker(&m_Mutex); return (m_Attributes & eObjInherit) != 0; }
	virtual bool			IsProtected() const				{ QReadLocker Locker(&m_Mutex); return (m_Attributes & eObjProtectClose) != 0; }
	virtual quint64			GetObjectAddress() const		{ QReadLocker Locker(&m_Mutex); return m_Object; }

	//
	// Not from here. Closing a wineserver handle means reaching into another
	// process's table from inside the prefix, which the helper does not do and
	// which the Linux side could not do at all.
	//
	virtual STATUS			Close(bool bForce = false);

	//
	// Where this numbering starts. Above CLinuxHandle::eMax with room to spare,
	// so that the two sets can be told apart by eye in a log as well as by the
	// tables below.
	//
	enum { c_TypeBase = 0x100 };

	//
	// The object kinds wineserver can produce, which is a fixed list: they are
	// compiled into it, not discovered from loaded drivers the way a real
	// Windows object table is. That is what makes it safe to send this once with
	// the handshake and never revisit it.
	//
	static QList<CSystemAPI::SHandleType>	GetTypes();

	// The index this type name gets, for the filter to match on.
	static int				TypeIndex(const QString& Name);

protected:
	QString					m_TypeName;
	quint32					m_TypeIndex = c_TypeBase;
	quint32					m_Access = 0;
	quint32					m_Attributes = 0;
	quint64					m_Object = 0;
};

typedef QSharedPointer<CWineHandle> CWineHandlePtr;
