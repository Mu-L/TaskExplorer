#pragma once
#include "AccessRights.h"
#include "../taskcore_global.h"
#include "../../MiscHelpers/Common/Status.h"

#include <QSharedPointer>
#include <QString>
#include <QList>

//
// A securable object's access control, as data.
//
// Windows' own editor (PhEditSecurity) drives a live handle through a callback
// that re-opens the object whenever it wants to read or write. Nothing about
// that survives a network hop, so the model here is the descriptor itself: who
// owns the object, and who may do what to it. A backend fills it in, the dialog
// shows it, and the same structure goes back the other way to apply changes.
//
// SIDs are carried as strings ("S-1-5-32-544"). The resolved name travels
// beside the SID rather than replacing it: the name is what the viewer reads,
// the SID is what the target acts on, and only the target can resolve one into
// the other.
//

//
// One right the object understands, with the wording its platform uses. On
// Windows these come from phlib's per-type tables - the same tables the native
// dialog uses - so "Terminate" on a process and "Start" on a service both land
// here without the GUI knowing either.
//
struct SAccessRight
{
	SAccessRight() : Right(eAccessNone), Access(0), bGeneral(false), bSpecific(false) {}

	int		Right;			// which right it is; see EAccessRight
	quint32	Access;			// the bit(s) it stands for

	//
	// General rights are the handful shown first (Full control, Read, Write);
	// specific ones are the individual bits behind them. An entry can be
	// neither, in which case it is a plain alias worth listing but not offering.
	//
	bool	bGeneral;
	bool	bSpecific;
};

//
// One entry in an access control list.
//
struct SAce
{
	enum EType
	{
		eAllow = 0,
		eDeny,
		eAudit,
	};

	//
	// Inheritance, as flag bits. These match the platform's own numbering so a
	// descriptor can round-trip unchanged through a viewer that does not offer
	// to edit them.
	//
	enum EFlags
	{
		eObjectInherit		= 0x01,
		eContainerInherit	= 0x02,
		eNoPropagate		= 0x04,
		eInheritOnly		= 0x08,
		eInherited			= 0x10,
		eAuditSuccess		= 0x40,
		eAuditFailure		= 0x80,
	};

	SAce() : Type(eAllow), Mask(0), Flags(0) {}
	SAce(EType type, const QString& sid, quint32 mask)
		: Type(type), Sid(sid), Mask(mask), Flags(0) {}

	bool IsInherited() const			{ return (Flags & eInherited) != 0; }

	EType	Type;
	QString	Sid;			// the identity that is acted on
	QString	Name;			// how the target renders it, for display only
	quint32	Mask;
	quint32	Flags;
};

//
// The descriptor as a whole.
//
struct SSecurityInfo
{
	SSecurityInfo()
		: bDaclPresent(false), bDaclProtected(false)
		, bSaclPresent(false), bSaclProtected(false)
		, SkippedAces(0), SkippedAuditAces(0), bSetOwner(false) {}

	QString	OwnerSid;
	QString	OwnerName;

	//
	// Set only when the owner is meant to be written. Every read fills OwnerSid
	// in, so its presence says nothing about intent - and taking an object over
	// needs WRITE_OWNER, a far higher bar than the WRITE_DAC a permission
	// change needs. Asking for it unconditionally would make ordinary edits
	// fail on objects that are perfectly editable.
	//
	bool	bSetOwner;
	QString	GroupSid;
	QString	GroupName;

	//
	// "Protected" means the object does not take inherited entries from its
	// parent. Absent DACL and empty DACL are different things - absent grants
	// everyone everything, empty grants nobody anything - so presence is
	// carried explicitly rather than inferred from the list being empty.
	//
	bool	bDaclPresent;
	bool	bDaclProtected;
	bool	bSaclPresent;
	bool	bSaclProtected;

	QList<SAce>	Dacl;
	QList<SAce>	Sacl;

	//
	// Entries the model does not describe - object ACEs, and the conditional
	// and callback kinds. They are counted rather than carried, because a
	// viewer that cannot show one certainly cannot edit it.
	//
	// Counted per list, because the guard is about rewriting: a list that is
	// written back must not be rebuilt from an incomplete picture, and the two
	// lists are written at different times. The audit list in particular
	// almost always holds something unmodelled - the integrity label is an
	// ACE type of its own - so a single count would make every object look
	// unwritable the moment the audit list could be read at all.
	//
	// Whoever writes is responsible for refusing; CWinSecurityObject::SetSecurity
	// checks SkippedAces before touching the DACL.
	//
	int			SkippedAces;
	int			SkippedAuditAces;
};

//
// What the dialog is handed.
//
// Anything securable produces one of these: a process, a service, an LSA
// account. The implementation holds whatever the backend needs to reach the
// object again - on Windows an opener callback and its context - so the dialog
// itself never learns what kind of thing it is editing.
//
class TASKCORE_EXPORT CSecurityEditable
{
public:
	virtual ~CSecurityEditable() {}

	//
	// What the object is, for the dialog's title.
	//
	// GetTypeName() is a stable identifier, not a word - it is what selects the
	// access-right table too. GetName() is the part the platform supplied and
	// only that: a process's image name, a service's display name, the file a
	// handle refers to. Kinds that have no such name return nothing and are
	// titled by their type alone; how the two are put together is the viewer's.
	//
	virtual QString	GetName() const = 0;
	virtual QString	GetTypeName() const = 0;

	// A pid or a tid, where one is part of what identifies the object.
	virtual quint64	GetObjectId() const					{ return 0; }

	// the rights this kind of object understands
	virtual QList<SAccessRight> GetAccessRights() const = 0;

	//
	// Auditing needs a privilege the caller may not hold, so it is asked for
	// separately and may come back missing even when the rest succeeded.
	//
	virtual STATUS	GetSecurity(SSecurityInfo& Info, bool bWithAudit = false) const = 0;
	virtual STATUS	SetSecurity(const SSecurityInfo& Info, bool bWithAudit = false) = 0;
};

typedef QSharedPointer<CSecurityEditable> CSecurityEditablePtr;
