#pragma once
#include "../corehelpers_global.h"
#include "Status.h"
#include "Credentials.h"

#include <QString>
#include <QMap>

//
// The keys a viewer has been told, kept so they need not be retyped.
//
// ---- what is encrypted with what ----
//
// A random 256-bit **master key** encrypts the entries, and nothing else ever
// touches them. The master key is then wrapped - twice, if asked:
//
//   * by a key derived from the store password (PBKDF2-HMAC-SHA512), which is
//     what makes the file portable: the same file opens on any machine by
//     somebody who knows the password;
//   * optionally by the platform - DPAPI on Windows - which is bound to this
//     user on this machine and travels nowhere. Purely a convenience so the
//     password is not asked every session.
//
// Wrapping the *key* rather than the file is the whole design, and it is what
// lets both of those exist at once. Both wrappings unwrap the same master key,
// so the encrypted body is byte-identical whichever was used, changing the
// password rewrites forty bytes of header and leaves the body alone, and
// turning the convenience on or off does not re-encrypt anything.
//
// ---- what this does not do ----
//
// It does not protect the keys from something already running as this user with
// the store unlocked - nothing can. It protects the file at rest: on a backup,
// on a stolen disk, in a synced profile directory.
//
class COREHELPERS_EXPORT CCredentialStore
{
public:
	//
	// One per process, made on first use beside the settings. Not a global
	// created in main() like theConf: three programs would each have to
	// remember to make it, and the one that forgot would silently save nothing.
	//
	static CCredentialStore*	Instance();

	QString			FilePath() const					{ return m_Path; }
	bool			Exists() const;

	//
	// Whether anything here can work at all. False when libcrypto is missing or
	// its known-answer tests failed - see MiscHelpers/Common/Crypto.h - and then
	// every call below fails with MH_CredStoreUnavailable rather than quietly
	// storing keys in the clear.
	//
	bool			IsAvailable(QString* pWhy = nullptr) const;

	bool			IsUnlocked() const					{ return !m_Master.isEmpty(); }

	//
	// Opens it without asking anybody anything, using the platform wrapping if
	// this store has one. True when it is now open.
	//
	// Called before every prompt: a store the platform can open should never
	// produce one, including from the reconnection timer of 5.3, which has no
	// user in front of it.
	//
	bool			TryUnlock();

	STATUS			Unlock(const QString& Password);
	void			Lock();

	//
	// Makes a new, empty store. Refuses to overwrite one that is already there -
	// that would discard keys, and a caller that wants them gone should say
	// Forget().
	//
	STATUS			Create(const QString& Password, bool bPlatformUnlock);

	STATUS			ChangePassword(const QString& Password);

	bool			HasPlatformUnlock() const			{ return !m_PlatformWrapped.isEmpty(); }
	STATUS			SetPlatformUnlock(bool bOn);

	QStringList		Targets() const;
	bool			Get(const QString& Target, SCredentials* pCred) const;
	STATUS			Set(const QString& Target, const SCredentials& Cred);
	STATUS			Remove(const QString& Target);

	//
	// Deletes the file. The only way to lose the keys, and deliberately not
	// something any other operation does as a side effect.
	//
	//
	// Whether this build can read the file at all - the header only, no password
	// asked for. MH_CredStoreVersion means it cannot and never will.
	//
	STATUS			Probe();

	//
	// Deletes the file so a new one can be made in its place. Destructive and
	// unrecoverable; only for the version case, and only when the user said so.
	//
	STATUS			Discard();

	STATUS			Forget();

	//
	// Where the one store lives, decided by the program and told to this once.
	//
	// This library has no product of its own and no opinion about directories.
	// Which file the keys go in is a question about *this* product - one store
	// per user, shared by all three of its executables, named for the product
	// rather than for whichever executable is asking - and that is the caller's
	// to answer. See CTaskExplorer's use of it.
	//
	// Unset, Instance() has nowhere to put a file and says so through
	// IsAvailable() rather than guessing; a guess would be a second store the
	// other programs cannot see.
	//
	static void		Setup(const QString& FilePath);

	//
	// A store at a path of its own. Public because a test needs one that is not
	// the user’s - Instance() is only the convenience for the usual file.
	//
	CCredentialStore(const QString& Path);
	~CCredentialStore();

protected:

	STATUS			Load();
	STATUS			Save();

	QString			m_Path;

	//
	// Read from the file on first touch and kept, because changing the password
	// must not change them - the body was sealed under this salt and these
	// iterations and would stop verifying.
	//
	QByteArray		m_Salt;
	quint32			m_Iterations = 0;
	QByteArray		m_PasswordWrapped;
	QByteArray		m_PlatformWrapped;
	QByteArray		m_BodyNonce;
	QByteArray		m_Body;
	bool			m_bLoaded = false;

	//
	// Present only while unlocked, and wiped on the way out.
	//
	QByteArray		m_Master;
	QMap<QString, SCredentials>	m_Entries;
};
