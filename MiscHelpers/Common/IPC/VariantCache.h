#pragma once

#include "../../corehelpers_global.h"
#include "../Variant.h"

#include <QMap>
#include <QList>
#include <QString>

//
// Remembers what has already been sent, so that only what changed is sent again.
//
// A process list is a couple of hundred entries of a dozen fields, most of which
// do not change from one refresh to the next: a name never changes, a path never
// changes, a thread count changes rarely. Sending all of it every second is
// affordable across a pipe on one machine and wasteful across a network. Handle
// and file lists are worse - thousands of entries, almost all of them static.
//
// Modelled on CoreServer's SStateCache/UPDATE() from NeoLoader, generalised: it
// knows about ids, field ids and values, and nothing about processes, files or
// any particular field. Anything expressible as "a set of entries, each a set of
// fields" can use it, which is every list this protocol will carry.
//
// ---- identity, and what actually travels ----
//
// The key a caller uses has to identify a thing *for as long as anyone might
// remember it*, which is not the same as identifying it right now. A pid, a
// thread id and a handle value are all recycled by the operating system, often
// within seconds. Key a delta by one of those and a new thing that inherits a
// dead thing's number is merged into the dead thing's entry - and because a
// delta carries only what changed, every field the two happen to share keeps
// the dead one's value forever. A full resend heals itself on the next round;
// this does not, which is what makes it worth care here and nowhere else.
//
// So callers key by something reuse-proof. In this tree that is
// CAbstractInfo::GetObjectUid - a number taken from a global counter in the
// constructor, so it belongs to the object rather than to whatever the system
// happens to be calling it, and lasts exactly as long as the object does. This
// class only requires that the key be unique for as long as the reader might
// remember it; where it comes from is the caller's business.
//
// That uid does not travel. VAR_TYPE_INDEX keys are uint32 and a uid is 64
// bits, so what goes on the wire is a **session handle** - a number assigned
// here on first sight, unique for the life of the cache and never reused. The
// reader keys its own map by the handle and takes the real identity, the pid or
// the tid, from a field inside the entry.
//
// Deliberately not the object's memory address, which is the tempting cheap uid
// and is wrong twice over. Allocators hand back recently-freed blocks in
// preference to fresh ones, so a new object very commonly lands on a dead one's
// address - that is the aliasing above, made likely rather than rare. And a
// server that puts the addresses of its own live objects on the wire tells
// every client where its heap is, which for a server that may be running as
// SYSTEM is a defence given away for nothing.
//
// ---- two key types ----
//
// Some lists are identified by a number and some by a name, because that is
// what identifies them: a service is its name and a driver is its name. The two
// are the same mechanism and differ only in how the key reaches the wire:
//
//   CVariantCache     quint64 uids, an index of session handles
//   CVariantCacheStr  QString names, a map under the name itself
//
// Names need no handle. A name is not recycled to mean something else the way a
// number is, and it is already the identity rather than a stand-in for it.
//
// The index is the cheaper of the two and is why it is the default. A map costs
// the characters of every key on every entry it sends - but it only sends
// *changed* entries, so after the first round that is almost nothing, and a
// service list is hundreds of entries rather than thousands.
//
// ---- how a round works ----
//
//     Cache.BeginRound();
//     foreach (thing)
//     {
//         Cache.Write(thing.Id, API_X_NAME, CVariant(thing.Name));
//         Cache.Write(thing.Id, API_X_SIZE, CVariant(thing.Size));
//     }
//     QList<TWireKey> Removed;
//     CVariant Changed = Cache.FinishRound(Removed);
//
// `Changed` holds only those entries with at least one field differing from what
// was last sent, and within each only those fields. An entry with nothing
// changed does not appear. `Removed` is every entry the cache knew that this
// round did not mention, named the way the reader knows it - by handle for a
// numeric cache, by name for a string one.
//
// The caller assembles those two into a message, because how a delta is spelt on
// the wire is the protocol's business and this class has no vocabulary - see
// TaskExplorer/API/ApiDefs.h for the identifiers that name them.
//
// ---- what the reader has to do ----
//
// Apply, not replace. A viewer keeps its own copy and merges each delta into it:
// a field that is absent has not changed, and an entry that is absent has not
// changed either. That is the whole point, and it means a reader that throws its
// copy away has to say so - see Clear().
//
// ---- lifetime ----
//
// One of these per subscription: per connection and per list. NeoLoader handed
// the client an opaque token and expired unused caches on a timer, because its
// transport did not keep a connection. Here the connection *is* the
// subscription, so a cache lives and dies with its socket and there is nothing
// to expire, nothing to guess and no token on the wire.
//
//
// What the reader knows an entry by: a session handle for numeric caches, the
// name itself for string ones.
//
template <class TKey> struct SWireKeyOf			{ typedef quint32 TType; };
template <>           struct SWireKeyOf<QString>	{ typedef QString TType; };

template <class TKey>
class CVariantCacheT
{
public:
	typedef typename SWireKeyOf<TKey>::TType TWireKey;

	CVariantCacheT() : m_bInRound(false) {}
	~CVariantCacheT() {}

	//
	// Starts a round. Every entry still wanted must be written before
	// FinishRound, or it will be reported as removed.
	//
	// ---- scopes ----
	//
	// A round can cover part of the cache instead of all of it, which is what
	// the per-process lists need. One connection asks for the threads of pid
	// 500, then of pid 900, then of 500 again; all of it belongs in one cache,
	// because the entries are keyed by a uid that is unique across the whole
	// machine and there is nothing to be gained by splitting them up. But a
	// round for 500 must not conclude that 900's threads have all exited merely
	// because it did not mention them.
	//
	// So an entry remembers which scope it was written under, and a round
	// touches only its own: it marks only those entries unseen and reports only
	// those as removed. Scope 0 is everything, which is what the system-wide
	// lists use and why they did not have to change.
	//
	// The alternative - a whole cache per process - was considered and is worse:
	// a map of caches to create, find and eventually expire, one lifetime rule
	// per list, and the wire keys no longer unique across the connection. This
	// is one extra quint64 per entry and one comparison per round.
	//
	void BeginRound(quint64 Scope = 0)
	{
		m_Changed.clear();
		m_Scope = Scope;
		for (typename QMap<TKey, SEntry>::iterator I = m_Entries.begin(); I != m_Entries.end(); ++I)
		{
			if (I->Scope == Scope)
				I->bSeen = false;
		}
		m_bInRound = true;
	}

	//
	// Says an entry is still present without offering any field for it. Only
	// needed when every field is conditional; Write() already does this.
	//
	void Keep(const TKey& Id)
	{
		SEntry& Entry = m_Entries[Id];
		Entry.bSeen = true;
		Entry.Scope = m_Scope;
	}

	//
	// Records one field of one entry. It reaches the output only if it differs
	// from what was last sent, and mentioning an entry at all is what keeps it
	// from being reported as removed - so a field that never changes still has
	// to be written every round.
	//
	// The value is copied into the cache and must own its bytes: a variant that
	// merely points into a buffer would be compared against freed memory next
	// round. Anything built with CVariant's own constructors does.
	//
	void Write(const TKey& Id, quint32 Field, const CVariant& Value)
	{
		SEntry& Entry = m_Entries[Id];
		Entry.bSeen = true;

		//
		// An entry belongs to the scope that last wrote it. A thread that moved
		// between processes - which cannot happen - would simply follow.
		//
		Entry.Scope = m_Scope;

		//
		// The comparison is the whole mechanism, and it works on any type
		// because CVariant compares its own payload - this class never learns
		// what a field means.
		//
		typename QMap<quint32, CVariant>::const_iterator I = Entry.Fields.constFind(Field);
		if (I != Entry.Fields.constEnd() && I.value().CompareTo(Value))
			return;		// unchanged, so it does not travel

		//
		// Emptied before being assigned to, which is not a nicety.
		//
		// CVariant::Assign refuses to overwrite a variant whose access is not
		// eReadWrite:
		//
		//     if(m_Variant && m_Variant->Access != eReadWrite)
		//         throw CException(L"variant access violation; Assign");
		//
		// and anything built with BeginList()/BeginIMap() and then Finish() is
		// eReadOnly. So a plain "Fields[Field] = Value" throws for exactly the
		// values that are containers - and only on the round where one of them
		// first *changes*, which is a long way from where it was stored, and
		// which is why a per-cpu list survived two rounds before killing the
		// server on the third.
		//
		// Clear() sets the pointer to null, so the guard above no longer
		// applies and the assignment attaches cleanly. This class promises to
		// take any CVariant and compare it by payload; without this the promise
		// quietly held for scalars only.
		//
		StoreField(Entry.Fields, Field, Value);
		StoreField(m_Changed[Id], Field, Value);
	}

	//
	// Ends the round. Returns the changed entries and fills Removed with the
	// entries that were not mentioned - by the name the *reader* knows them by,
	// not by the caller's uid, which never travelled.
	//
	CVariant FinishRound(QList<TWireKey>& Removed)
	{
		Removed.clear();

		//
		// Anything the round did not mention is gone. Reported once and
		// forgotten, so a reader is told exactly once and a re-appearing key
		// starts fresh.
		//
		for (typename QMap<TKey, SEntry>::iterator I = m_Entries.begin(); I != m_Entries.end(); )
		{
			if (I->bSeen || I->Scope != m_Scope)
				++I;
			else
			{
				//
				// Only if it ever travelled. An entry that was Keep()ed and
				// never written has no handle, so the reader has never heard of
				// it and telling it something was removed would be a lie.
				//
				TWireKey Key;
				if (TakeWireKey(I.key(), Key))
					Removed.append(Key);
				I = m_Entries.erase(I);
			}
		}

		CVariant Changed;
		BeginContainer(Changed);
		for (typename QMap<TKey, QMap<quint32, CVariant> >::const_iterator I = m_Changed.constBegin();
			I != m_Changed.constEnd(); ++I)
		{
			CVariant Entry;
			Entry.BeginIMap();
			for (QMap<quint32, CVariant>::const_iterator J = I.value().constBegin();
				J != I.value().constEnd(); ++J)
				Entry.WriteVariant(J.key(), J.value());
			Entry.Finish();

			//
			// The key is the key and is not repeated inside the entry: a reader
			// walking the container already has it, and on a long list the
			// duplicate would be one of the larger fields.
			//
			WriteEntry(Changed, I.key(), Entry);
		}
		Changed.Finish();

		m_Changed.clear();
		m_bInRound = false;
		return Changed;
	}

	//
	// Forgets everything, so the next round sends every field of every entry.
	// For when a reader has lost its copy and says so.
	//
	//
	// With a scope, forgets only that part - a viewer that has just opened the
	// thread tab of one process needs everything about that process and nothing
	// about the others, which are very likely still on screen.
	//
	void Clear(quint64 Scope)
	{
		for (typename QMap<TKey, SEntry>::iterator I = m_Entries.begin(); I != m_Entries.end(); )
		{
			if (I->Scope != Scope)
				++I;
			else
			{
				m_WireKeys.remove(I.key());
				I = m_Entries.erase(I);
			}
		}
		m_Changed.clear();
	}

	//
	// Whether this cache has ever sent anything.
	//
	// A cache lives as long as one client's connection, so an empty one means
	// that client holds nothing of ours - which is the one thing the reader
	// cannot always work out for itself. A transport that reconnects underneath
	// it leaves it believing it still has a copy while the server has started a
	// fresh cache and is numbering from the beginning again.
	//
	bool IsEmpty() const { return m_Entries.isEmpty(); }

	void Clear()
	{
		m_Entries.clear();
		m_Changed.clear();
		m_WireKeys.clear();
		//
		// The handle counter is deliberately not reset. A reader that lost its
		// copy may still be holding old handles, and handing those same numbers
		// to different things is precisely the aliasing this exists to prevent.
		//
		m_bInRound = false;
	}

	int GetEntryCount() const { return m_Entries.count(); }

protected:
	static void StoreField(QMap<quint32, CVariant>& Fields, quint32 Field, const CVariant& Value)
	{
		CVariant& Slot = Fields[Field];
		Slot.Clear();
		Slot = Value;
	}

	//
	// The only things the two key types differ in. Specialised below.
	//
	void BeginContainer(CVariant& Container);
	void WriteEntry(CVariant& Container, const TKey& Id, const CVariant& Entry);
	TWireKey WireKey(const TKey& Id);
	bool TakeWireKey(const TKey& Id, TWireKey& Key);

	struct SEntry
	{
		QMap<quint32, CVariant>	Fields;
		bool					bSeen = false;

		//
		// Which round this entry answers to; see BeginRound. Zero for the
		// system-wide lists, the pid for the per-process ones.
		//
		quint64					Scope = 0;
	};

	QMap<TKey, SEntry>			m_Entries;

	//
	// uid -> what the reader knows it by. Only the numeric form uses this; a
	// name is its own wire key and needs no translation.
	//
	QMap<TKey, quint32>			m_WireKeys;
	quint32						m_NextWireKey = 0;

	//
	// This round's changes, collected as they are written and turned into a
	// variant at the end. Building it incrementally is not possible: CVariant's
	// containers are written once and finished.
	//
	QMap<TKey, QMap<quint32, CVariant> >	m_Changed;
	bool						m_bInRound;
	quint64						m_Scope = 0;
};

//
// Numeric uids: an index of session handles, four bytes per key and no length.
//
template <> inline void CVariantCacheT<quint64>::BeginContainer(CVariant& Container)
{
	Container.BeginIMap();
}

//
// A handle on first sight, the same one ever after. Monotonic and never reused,
// which is what makes a recycled pid or handle value harmless here: the
// operating system may hand the number back, but this will not.
//
// Wrapping after four billion assignments would take a machine churning a
// thousand new processes a second some seven weeks of one unbroken connection,
// and the counter is per cache rather than per server.
//
template <> inline quint32 CVariantCacheT<quint64>::WireKey(const quint64& Id)
{
	QMap<quint64, quint32>::const_iterator I = m_WireKeys.constFind(Id);
	if (I != m_WireKeys.constEnd())
		return I.value();

	const quint32 Key = ++m_NextWireKey;
	m_WireKeys.insert(Id, Key);
	return Key;
}

template <> inline bool CVariantCacheT<quint64>::TakeWireKey(const quint64& Id, quint32& Key)
{
	QMap<quint64, quint32>::iterator I = m_WireKeys.find(Id);
	if (I == m_WireKeys.end())
		return false;
	Key = I.value();
	m_WireKeys.erase(I);
	return true;
}

template <> inline void CVariantCacheT<quint64>::WriteEntry(CVariant& Container, const quint64& Id, const CVariant& Entry)
{
	Container.WriteVariant(WireKey(Id), Entry);
}

//
// Name keys: a dictionary, and the name is its own wire key. More expensive per
// entry, but only changed entries carry a key at all, and the things identified
// by name - services, drivers - are counted in hundreds.
//
template <> inline void CVariantCacheT<QString>::BeginContainer(CVariant& Container)
{
	Container.BeginMap();
}

template <> inline QString CVariantCacheT<QString>::WireKey(const QString& Id)
{
	return Id;
}

template <> inline bool CVariantCacheT<QString>::TakeWireKey(const QString& Id, QString& Key)
{
	Key = Id;
	return true;
}

template <> inline void CVariantCacheT<QString>::WriteEntry(CVariant& Container, const QString& Id, const CVariant& Entry)
{
	Container.WriteVariant(Id.toUtf8().constData(), Entry);
}

typedef CVariantCacheT<quint64>	CVariantCache;
typedef CVariantCacheT<QString>	CVariantCacheStr;
