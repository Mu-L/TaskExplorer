#pragma once
#include "Placeholders.h"
#include "../taskcore_global.h"
#include <qobject.h>
#include <QAtomicInteger>
#include <QSharedPointer>
#include "../../MiscHelpers/Common/Common.h"

class CSystemAPI;

//
// Spelled here as well as in SystemAPI.h, which cannot be included from this
// header - it includes this one. Identical typedefs are legal and this is the
// one place that needs the name without the class.
//
typedef QSharedPointer<CSystemAPI> CSystemPtr;

class TASKCORE_EXPORT CAbstractInfo : public QObject
{
	Q_OBJECT

public:
	CAbstractInfo(QObject *parent = nullptr);
	virtual ~CAbstractInfo() {}

	//
	// A number no other live object has, and no dead one ever had.
	//
	// Everything the process, service, socket, handle and thread lists are made
	// of ends up here, and none of them has a natural identity that survives
	// being looked at twice. A pid, a thread id and a handle value are all
	// recycled by the operating system, often within seconds; a socket is a
	// five-tuple that can legitimately recur. Anything keyed by one of those
	// will sooner or later be told that a new thing is an old thing.
	//
	// Taking it from the constructor is what makes it true rather than merely
	// probable: the number belongs to the object, so it lasts exactly as long as
	// the object does and can be reused only after the counter has wrapped,
	// which at one new object per nanosecond takes some five hundred years.
	//
	// The collectors update the objects they already hold and construct only
	// what is genuinely new - CWindowsAPI takes the old entry out of its map and
	// allocates only on a miss - so this stays put across a refresh for anything
	// that is still there, which is what makes it usable as a cache key.
	//
	// Read without the lock: it is set once, before anyone else can hold a
	// pointer to the object, and never written again.
	//
	// Named for the object and not just "uid": CProcessInfo::GetUid() is the
	// POSIX *user* id and CLinuxProcess has an m_Uid to match. A GetUid() here
	// is hidden by that one without a word from the compiler - the process list
	// simply collapses to one entry per user, which is how this was found.
	//
	quint64						GetObjectUid() const				{ return m_ObjectUid; }

	//
	// The system this object was observed on.
	//
	// Anything that resolves something related to an object - a parent process, a
	// service by name, whether ETW data is available - must go through this rather
	// than through the global, or it will silently answer for the wrong machine as
	// soon as more than one is connected.
	//
	// Held weakly and handed out strongly.
	//
	// Weakly, because the system owns the objects (QMap<SProcessUID, CProcessPtr>
	// and friends) and an owning back pointer would close a reference cycle so
	// that nothing was ever released.
	//
	// It used to be a raw pointer, on the stated reasoning that objects do not
	// outlive the system that collected them. They do: a panel showing a process
	// holds a CProcessPtr, and that reference keeps the object alive after its
	// machine has been disconnected and destroyed. Every back pointer then became
	// wild, and the next refresh read through one:
	//
	//     Access violation reading location 0xFFFFFFFFFFFFFFFF
	//     CProcessView::ShowProcess -> pProcess->GetSystem()->GetProcessByID(...)
	//
	// Strongly, because knowing the system was alive a moment ago is not the same
	// as it being alive for the duration of the call. A pointer that merely goes
	// null on destruction - a QPointer - answers the first question and leaves the
	// second one open: the system is destroyed on its own thread, so a null check
	// followed by a use is two facts with a gap between them. Returning a
	// CSystemPtr closes the gap by keeping the system alive as long as the caller
	// holds the answer.
	//
	// **GetSystem() may return null**, and that means the machine this object came
	// from is gone. Callers must ask.
	//
	CSystemPtr					GetSystem() const;
	//
	// Takes the shared pointer, not a raw one.
	//
	// A raw pointer would have to be turned back into a shared one here, and the
	// only way to do that is to ask the system for its own reference - which
	// answers null, silently, for a system that is not owned by a CSystemPtr yet.
	// Requiring the caller to have one makes that impossible to get wrong: there
	// is no way to set a system that nobody owns.
	//
	void						SetSystem(const CSystemPtr& pSystem);

	mutable QReadWriteLock		m_Mutex;

protected:
	QWeakPointer<CSystemAPI>	m_pSystem;

	const quint64				m_ObjectUid;

	//
	// Process wide, because that is the scope over which the objects coexist.
	// A viewer connected to two machines sees two servers each counting from
	// one, and never compares them: uids travel as a per-connection handle
	// rather than as themselves. See CVariantCacheT.
	//
	static QAtomicInteger<quint64>	m_NextObjectUid;
};


class TASKCORE_EXPORT CAbstractInfoEx : public CAbstractInfo
{
	Q_OBJECT

public:
	CAbstractInfoEx(QObject *parent = nullptr);
	virtual ~CAbstractInfoEx();

	static void					SetHighlightTime(quint64 time)		{ m_HighlightTime = time; }
	static quint64				GetHighlightTime()					{ return m_HighlightTime; }
	virtual quint64				GetCreateTimeStamp() const			{ QReadLocker Locker(&m_Mutex); return m_CreateTimeStamp; }
	virtual bool				IsNewlyCreated() const;
	
	static void					SetPersistenceTime(quint64 time)	{ m_PersistenceTime = time; }
	static quint64				GetPersistenceTime()				{ return m_PersistenceTime; }
	virtual void				InitTimeStamp()						{ QWriteLocker Locker(&m_Mutex); m_CreateTimeStamp = GetTime() * 1000; }
	virtual void				MarkForRemoval()					{ QWriteLocker Locker(&m_Mutex); m_RemoveTimeStamp = GetCurTick(); }
	virtual bool				IsMarkedForRemoval() const			{ QReadLocker Locker(&m_Mutex); return m_RemoveTimeStamp != 0; }
	virtual bool				CanBeRemoved() const;
	virtual void				ClearPersistence();

protected:
	volatile mutable bool		m_NewlyCreated;
	quint64						m_CreateTimeStamp;

	quint64						m_RemoveTimeStamp;

	static volatile quint64		m_PersistenceTime;
	static volatile quint64		m_HighlightTime;
};