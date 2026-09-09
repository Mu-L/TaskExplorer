#pragma once
#include "../corehelpers_global.h"

#include <QVariantList>
#include <QString>
#include <atomic>
#include <type_traits>

//
// What went wrong, as a code somebody else turns into a sentence.
//
// This does not build error text and cannot: the machine that fails is not
// necessarily the machine someone is reading, and a daemon has no locale worth
// speaking in. So it names the failure and supplies the values that go into it,
// and one place in the front end writes the sentence.
//
// ---- why there is only one of these ----
//
// There were two: CStatus here, carrying a finished QString, and CStatus
// in TaskCore, carrying a code and its arguments. Two status types in one
// program is two habits, and the one that carries a sentence is the one that
// cannot cross a machine boundary. This is the second design, moved down to
// where the first one lived so that everything can reach it - including code
// below TaskCore, which is what let the credential store keep its error codes.
//

//
// The native side of a failure - an errno, an NTSTATUS, a Win32 error. Zero
// means the code above is the whole story.
//
#define ERROR_UNDEFINED (1)
#define ERROR_CONFIRM (2)
#define ERROR_INTERNAL (3)
#define ERROR_PARAMS (4)

//
// ---- message codes, and who they belong to ----
//
// A code carries its origin in its top sixteen bits: 'TE' for TaskExplorer's
// own, 'MH' for the helper library's. Two characters for the same reason
// ApiDefs.h uses four - a code reads as 0x5445'0007 in a log and says where it
// came from - and because it means a new subsystem can be given a range without
// asking what numbers are already taken.
//
// A two-character literal is implementation-defined, so it is checked rather
// than assumed, the same way the four-character ones are.
//
// Zero is not a code and never will be: it is what GetMsgCode() answers when
// there is no error at all, so numbering within a group starts at one.
//
#define STATUS_CODE(Prefix, Num)	((quint32)((((quint32)(Prefix)) << 16) | ((quint32)(Num) & 0xFFFF)))
#define STATUS_GROUP(Code)			((quint32)(Code) >> 16)
#define STATUS_NONE					((quint32)0)

static_assert('TE' == 0x5445, "two-character literals are not packed as expected");
static_assert('MH' == 0x4D48, "two-character literals are not packed as expected");

//
// ---- this library's own codes ----
//
// The credential store's, and one for a bare platform failure. Everything else
// in MiscHelpers reports failure by returning false.
//
enum EMiscMsgCode
{
	MH_Native = STATUS_CODE('MH', 1),	// a platform failure with no code of our own

	MH_CredStoreUnavailable,			// Saved keys need encryption this build could not set up: %1
	MH_CredStoreLocked,					// The saved keys are locked.
	MH_CredStoreBadPassword,			// That password did not open the saved keys.
	MH_CredStoreDamaged,				// The saved keys could not be read: %1
	MH_CredStoreWriteFailed,			// The saved keys could not be written: %1
	MH_CredStoreNoPlatformKey,			// This machine cannot remember the password for you.

	//
	// The file is a credential store, and not one this build can read: a version
	// it does not know. Separate from Damaged because the answer is different -
	// damaged is a loss to report, this is a question to ask, and the only thing
	// that can be done about it is to start again.
	//
	// Appended, never renumbered: these codes are protocol.
	//
	MH_CredStoreVersion,				// The saved keys were written by another version of this program (%1).

	MH_LastMsgCode
};

//
// A message code, in a wrapper that a native status cannot be mistaken for.
//
// The constructor takes enumerations only. That is the whole point of it: every
// code is a value of some E...MsgCode enum, and a bare long is a *native* status
// and belongs in the other argument. Without this an ERR(SomeWin32Error) would
// compile and mean "message code 0x00000005", which is a wrong sentence rather
// than a failure to build.
//
struct SMsgCode
{
	quint32 v;

	template <class E, class = typename std::enable_if<std::is_enum<E>::value>::type>
	SMsgCode(E Code) : v((quint32)Code) {}

	explicit SMsgCode(quint32 Code) : v(Code) {}
};

class COREHELPERS_EXPORT CStatus
{
public:
	//
	// Turns a native status into the words the platform has for it. Installed
	// by whoever knows the platform - see CStatus::SetNativeFormatter - because
	// the wording has to be fetched on the machine that failed and travel as an
	// argument, not be rendered later somewhere else.
	//
	typedef QString (*FNativeFormatter)(long Status);
	static void SetNativeFormatter(FNativeFormatter pFn);

	CStatus()
	{
		m = NULL;
	}

	CStatus(SMsgCode MsgCode, const QVariantList& Args = QVariantList(), long Status = ERROR_UNDEFINED) : CStatus()
	{
		SMsg* p = new SMsg();
		p->MsgCode = MsgCode.v;
		p->Args = Args;
		p->Status = Status;
		Attach(p);
	}

	CStatus(SMsgCode MsgCode, long Status) : CStatus(MsgCode, QVariantList(), Status)
	{
	}

	//
	// A bare native failure, with no code of our own to describe it.
	//
	// A named factory rather than a constructor: CStatus(long) and
	// CStatus(SMsgCode) cannot both exist, because an enumeration converts to
	// long by a standard conversion and would win against the wrapper every
	// time - silently turning every ERR(TE_Something) into a native status.
	//
	static CStatus Native(long Status);

	CStatus(const CStatus& other) : CStatus()
	{
		if (other.m != NULL)
			Attach(other.m);
	}

	~CStatus()
	{
		Detach();
	}

	CStatus& operator=(const CStatus& other)
	{
		Attach(other.m);
		return *this;
	}

	__inline bool			IsError() const		{ return m != NULL; }
	__inline quint32		GetMsgCode() const	{ return m ? m->MsgCode : STATUS_NONE; }
	__inline QVariantList	GetArgs() const		{ return m ? m->Args : QVariantList(); }
	__inline long			GetStatus() const	{ return m ? m->Status : 0; }

	operator bool() const						{ return !IsError(); }

protected:
	struct SMsg
	{
		quint32			MsgCode;
		QVariantList	Args;
		long			Status;

		mutable std::atomic<int> aRefCnt;
	} *m;

	void Attach(SMsg* p)
	{
		Detach();

		if (p != NULL)
		{
			p->aRefCnt.fetch_add(1);
			m = p;
		}
	}

	void Detach()
	{
		if (m != NULL)
		{
			if (m->aRefCnt.fetch_sub(1) == 1)
				delete m;
			m = NULL;
		}
	}
};

typedef CStatus STATUS;
#define OK CStatus()
#define ERR CStatus
