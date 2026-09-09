#include "stdafx.h"
#include "CredentialStore.h"
#include "Crypto.h"

#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QDataStream>
#include <QSaveFile>

#ifndef WIN32
#include <sys/stat.h>
#endif

//
// The file, in one place so the reader and the writer cannot drift.
//
//   "TECRED\0" magic, then a version, then:
//     salt, iterations, the master key wrapped by the password,
//     the master key wrapped by the platform (may be empty),
//     the body nonce, the sealed body.
//
// The version is its own field rather than part of the magic so that a file
// from a later build is refused with something better than "not a credential
// store".
//
#define CRED_MAGIC		"TECRED\0"
//
// 2: an entry is a transport secret, a user name and a password, where it used
// to be an identity and a key. A version 1 file cannot be read into the new
// shape - the two fields it holds are not two of the three - and is refused
// rather than half-interpreted. It is a cache of things the user can retype.
//
#define CRED_VERSION	2

//
// 600,000, from measuring: 200,000 cost 140 ms on this machine, so this is
// around four tenths of a second - long enough to be worth an attacker's while
// per guess, short enough that nobody notices it at a prompt.
//
// Written into the file rather than assumed, so it can be raised later without
// stranding anything written today.
//
#define CRED_ITERATIONS	600000

#define CRED_KEYLEN		32
#define CRED_NONCELEN	12

//
// The context every seal is bound to.
//
// It stops a blob being lifted out of one field of this file and pasted into
// another - the two wrappings hold the same 32 bytes, and without this the
// password-wrapped copy would verify perfectly well in the platform slot.
//
static QByteArray WrapAad(const QByteArray& Salt, quint32 Iterations)
{
	QByteArray Aad(CRED_MAGIC, 7);
	Aad.append((char)CRED_VERSION);
	Aad.append("pw");
	Aad.append(Salt);
	Aad.append(QByteArray::number((qulonglong)Iterations));
	return Aad;
}

//
// Deliberately *not* the whole header.
//
// The body must stay verifiable when the password changes, and a password
// change rewrites the salt and the wrapped key. Binding the body to those would
// mean re-encrypting every entry to change a password - which is exactly the
// thing "wrap the master key, not the file" exists to avoid.
//
// Nothing is lost by it: an altered header cannot produce accepted plaintext,
// because producing any plaintext at all requires the master key.
//
static QByteArray BodyAad()
{
	QByteArray Aad(CRED_MAGIC, 7);
	Aad.append((char)CRED_VERSION);
	Aad.append("body");
	return Aad;
}

//
// One store per user, not one per program.
//
// The keys belong to whoever is sitting there, not to whichever of the three
// executables they happened to type. A viewer and a console that each kept
// their own would mean two files, two passwords, and a key saved in one that
// the other cannot see - and the user has no way to know which was which.
//
// A portable installation already shares one directory between all three, so
// there is nothing to redirect; only the per-application layout needs the last
// component replaced.
//
static QString g_FilePath;

void CCredentialStore::Setup(const QString& FilePath)
{
	g_FilePath = FilePath;
}

CCredentialStore* CCredentialStore::Instance()
{
	static CCredentialStore* pStore = NULL;
	if (!pStore)
		pStore = new CCredentialStore(g_FilePath);
	return pStore;
}

CCredentialStore::CCredentialStore(const QString& Path)
	: m_Path(Path)
{
}

CCredentialStore::~CCredentialStore()
{
	Lock();
}

bool CCredentialStore::Exists() const
{
	return QFile::exists(m_Path);
}

bool CCredentialStore::IsAvailable(QString* pWhy) const
{
	//
	// No path means nobody said where the store goes - see
	// Setup. Reported rather than guessed, because a guess would put
	// the keys somewhere the other programs do not look.
	//
	if (m_Path.isEmpty())
	{
		if (pWhy)
			*pWhy = QObject::tr("no location for the key store was set");
		return false;
	}

	return CCrypto::IsAvailable(pWhy);
}

void CCredentialStore::Lock()
{
	CCrypto::Wipe(m_Master);

	foreach(const QString& Target, m_Entries.keys())
	{
		CCrypto::Wipe(m_Entries[Target].Psk);
		CCrypto::Wipe(m_Entries[Target].User);
		CCrypto::Wipe(m_Entries[Target].Password);
	}
	m_Entries.clear();
}

STATUS CCredentialStore::Load()
{
	if (m_bLoaded)
		return OK;

	QFile File(m_Path);
	if (!File.open(QIODevice::ReadOnly))
		return ERR(MH_CredStoreDamaged, QVariantList() << File.errorString());

	QDataStream Stream(&File);
	Stream.setVersion(QDataStream::Qt_5_15);

	char Magic[8] = {};
	if (Stream.readRawData(Magic, 7) != 7 || memcmp(Magic, CRED_MAGIC, 7) != 0)
		return ERR(MH_CredStoreDamaged, QVariantList() << QString("not a credential store"));

	quint32 Version = 0;
	Stream >> Version;
	if (Version != CRED_VERSION)
		return ERR(MH_CredStoreVersion, QVariantList() << Version);

	Stream >> m_Salt >> m_Iterations >> m_PasswordWrapped >> m_PlatformWrapped
		   >> m_BodyNonce >> m_Body;

	if (Stream.status() != QDataStream::Ok)
		return ERR(MH_CredStoreDamaged, QVariantList() << QString("the file ends early"));

	m_bLoaded = true;
	return OK;
}

//
// The entries, decoded once the master key is in hand.
//
static bool DecodeEntries(const QByteArray& Plain, QMap<QString, SCredentials>* pEntries)
{
	QDataStream Stream(Plain);
	Stream.setVersion(QDataStream::Qt_5_15);

	quint32 Count = 0;
	Stream >> Count;

	//
	// A plaintext that decrypted under a verified tag cannot be arbitrary, so
	// this is not a hostile-input path - but a truncated write would land here
	// too, and losing the lot to a bad length is worse than losing one entry.
	//
	for (quint32 i = 0; i < Count && Stream.status() == QDataStream::Ok; i++)
	{
		QString Target;
		SCredentials Entry;
		Stream >> Target >> Entry.Psk >> Entry.User >> Entry.Password;
		if (!Target.isEmpty())
			pEntries->insert(Target, Entry);
	}
	return Stream.status() == QDataStream::Ok;
}

static QByteArray EncodeEntries(const QMap<QString, SCredentials>& Entries)
{
	QByteArray Plain;
	QDataStream Stream(&Plain, QIODevice::WriteOnly);
	Stream.setVersion(QDataStream::Qt_5_15);

	Stream << (quint32)Entries.count();
	for (QMap<QString, SCredentials>::const_iterator I = Entries.constBegin();
		I != Entries.constEnd(); ++I)
		Stream << I.key() << I.value().Psk << I.value().User << I.value().Password;

	return Plain;
}

bool CCredentialStore::TryUnlock()
{
	if (IsUnlocked())
		return true;
	if (!Exists() || !IsAvailable())
		return false;
	if (Load().IsError())
		return false;
	if (m_PlatformWrapped.isEmpty())
		return false;

	//
	// The blob holds the master key itself. There is nothing to unwrap a second
	// time: the platform *is* the second wrapping, and encrypting it again under
	// a key the platform also held would be circular.
	//
	// What checks it is the body: if the wrong 32 bytes come back - a blob from
	// another store, a file whose header was edited - the tag fails and the
	// store stays locked rather than opening onto rubbish.
	//
	QByteArray Master = CCrypto::PlatformUnwrap(m_PlatformWrapped);
	if (Master.size() != CRED_KEYLEN)
	{
		CCrypto::Wipe(Master);
		return false;
	}

	m_Master = Master;

	bool bOk = false;
	QByteArray Plain = CCrypto::Decrypt(m_Master, m_BodyNonce, m_Body, BodyAad(), &bOk);
	if (!bOk || !DecodeEntries(Plain, &m_Entries))
	{
		CCrypto::Wipe(Plain);
		Lock();
		return false;
	}
	CCrypto::Wipe(Plain);
	return true;
}

STATUS CCredentialStore::Unlock(const QString& Password)
{
	QString Why;
	if (!IsAvailable(&Why))
		return ERR(MH_CredStoreUnavailable, QVariantList() << Why);

	if (!Exists())
		return ERR(MH_CredStoreDamaged, QVariantList() << QString("there is no store yet"));

	STATUS Status = Load();
	if (Status.IsError())
		return Status;

	QByteArray Kek = CCrypto::DeriveKey(Password.toUtf8(), m_Salt, (int)m_Iterations, CRED_KEYLEN);
	if (Kek.isEmpty())
		return ERR(MH_CredStoreUnavailable, QVariantList() << QString("the key derivation failed"));

	//
	// The wrapped master carries its own nonce in front of it.
	//
	bool bOk = false;
	QByteArray Master;
	if (m_PasswordWrapped.size() > CRED_NONCELEN)
	{
		Master = CCrypto::Decrypt(Kek, m_PasswordWrapped.left(CRED_NONCELEN),
			m_PasswordWrapped.mid(CRED_NONCELEN), WrapAad(m_Salt, m_Iterations), &bOk);
	}
	CCrypto::Wipe(Kek);

	//
	// A wrong password and a damaged file are indistinguishable here, and the
	// message says the likely one. Telling them apart would need something
	// checkable stored beside the key, which is a hint an attacker gets too.
	//
	if (!bOk || Master.size() != CRED_KEYLEN)
	{
		CCrypto::Wipe(Master);
		return ERR(MH_CredStoreBadPassword);
	}

	m_Master = Master;

	QByteArray Plain = CCrypto::Decrypt(m_Master, m_BodyNonce, m_Body, BodyAad(), &bOk);
	if (!bOk)
	{
		Lock();
		return ERR(MH_CredStoreDamaged, QVariantList() << QString("the entries did not verify"));
	}

	m_Entries.clear();
	DecodeEntries(Plain, &m_Entries);
	CCrypto::Wipe(Plain);
	return OK;
}

STATUS CCredentialStore::Create(const QString& Password, bool bPlatformUnlock)
{
	QString Why;
	if (!IsAvailable(&Why))
		return ERR(MH_CredStoreUnavailable, QVariantList() << Why);

	if (Exists())
		return ERR(MH_CredStoreDamaged, QVariantList() << QString("a store is already there"));

	m_Salt = CCrypto::Random(16);
	m_Iterations = CRED_ITERATIONS;
	m_Master = CCrypto::Random(CRED_KEYLEN);
	m_PlatformWrapped.clear();
	m_Entries.clear();
	m_bLoaded = true;

	STATUS Status = ChangePassword(Password);
	if (Status.IsError())
		return Status;

	if (bPlatformUnlock)
	{
		Status = SetPlatformUnlock(true);
		if (Status.IsError())
			return Status;
	}

	return Save();
}

STATUS CCredentialStore::ChangePassword(const QString& Password)
{
	if (!IsUnlocked())
		return ERR(MH_CredStoreLocked);

	//
	// A new salt every time, so that two files protected by the same password
	// share no derived key and one cracked password does not answer the other.
	//
	// The body is untouched: it was sealed under the master key, and the master
	// key has not changed. That is the point of wrapping the key rather than
	// the file.
	//
	m_Salt = CCrypto::Random(16);
	m_Iterations = CRED_ITERATIONS;

	QByteArray Kek = CCrypto::DeriveKey(Password.toUtf8(), m_Salt, (int)m_Iterations, CRED_KEYLEN);
	if (Kek.isEmpty())
		return ERR(MH_CredStoreUnavailable, QVariantList() << QString("the key derivation failed"));

	const QByteArray Nonce = CCrypto::Random(CRED_NONCELEN);
	const QByteArray Sealed = CCrypto::Encrypt(Kek, Nonce, m_Master, WrapAad(m_Salt, m_Iterations));
	CCrypto::Wipe(Kek);

	if (Sealed.isEmpty())
		return ERR(MH_CredStoreUnavailable, QVariantList() << QString("the master key could not be wrapped"));

	m_PasswordWrapped = Nonce + Sealed;
	return Save();
}

STATUS CCredentialStore::SetPlatformUnlock(bool bOn)
{
	if (!bOn)
	{
		//
		// Told to let go of it, not merely forgotten about. On Windows the
		// wrapping is the file’s own bytes and this does nothing; elsewhere it is
		// an entry in the user’s keyring that would otherwise sit there for ever
		// with nothing pointing at it.
		//
		CCrypto::PlatformForget(m_PlatformWrapped);
		m_PlatformWrapped.clear();
		return m_bLoaded ? Save() : OK;
	}

	if (!IsUnlocked())
		return ERR(MH_CredStoreLocked);

	if (!CCrypto::PlatformSecretAvailable())
		return ERR(MH_CredStoreNoPlatformKey);

	//
	// Any earlier one goes first. Turning this on twice would otherwise leave the
	// first entry behind with nothing referring to it.
	//
	CCrypto::PlatformForget(m_PlatformWrapped);

	m_PlatformWrapped = CCrypto::PlatformWrap(m_Master);
	if (m_PlatformWrapped.isEmpty())
		return ERR(MH_CredStoreNoPlatformKey);

	return Save();
}

STATUS CCredentialStore::Save()
{
	if (!IsUnlocked())
		return ERR(MH_CredStoreLocked);

	QByteArray Plain = EncodeEntries(m_Entries);
	m_BodyNonce = CCrypto::Random(CRED_NONCELEN);
	m_Body = CCrypto::Encrypt(m_Master, m_BodyNonce, Plain, BodyAad());
	CCrypto::Wipe(Plain);

	if (m_Body.isEmpty())
		return ERR(MH_CredStoreUnavailable, QVariantList() << QString("the entries could not be sealed"));

	QDir().mkpath(QFileInfo(m_Path).absolutePath());

	//
	// QSaveFile: the old store stays intact until the new one is completely
	// written. Half a credential file is not recoverable from, and the failure
	// would only be discovered on the next start.
	//
	QSaveFile File(m_Path);
	if (!File.open(QIODevice::WriteOnly))
		return ERR(MH_CredStoreWriteFailed, QVariantList() << File.errorString());

	QDataStream Stream(&File);
	Stream.setVersion(QDataStream::Qt_5_15);
	Stream.writeRawData(CRED_MAGIC, 7);
	Stream << (quint32)CRED_VERSION;
	Stream << m_Salt << m_Iterations << m_PasswordWrapped << m_PlatformWrapped
		   << m_BodyNonce << m_Body;

	if (!File.commit())
		return ERR(MH_CredStoreWriteFailed, QVariantList() << File.errorString());

#ifndef WIN32
	//
	// Defence in depth only - the contents are encrypted - but a file of keys
	// that anybody on the machine may read is a bad look even when reading it
	// buys them nothing.
	//
	chmod(m_Path.toLocal8Bit().constData(), S_IRUSR | S_IWUSR);
#endif

	m_bLoaded = true;
	return OK;
}

QStringList CCredentialStore::Targets() const
{
	return m_Entries.keys();
}

bool CCredentialStore::Get(const QString& Target, SCredentials* pCred) const
{
	QMap<QString, SCredentials>::const_iterator I = m_Entries.constFind(Target);
	if (I == m_Entries.constEnd())
		return false;

	if (pCred)
		*pCred = I.value();
	return true;
}

STATUS CCredentialStore::Set(const QString& Target, const SCredentials& Cred)
{
	if (!IsUnlocked())
		return ERR(MH_CredStoreLocked);

	m_Entries.insert(Target, Cred);

	return Save();
}

STATUS CCredentialStore::Remove(const QString& Target)
{
	if (!IsUnlocked())
		return ERR(MH_CredStoreLocked);

	if (m_Entries.remove(Target) == 0)
		return OK;

	return Save();
}

//
// Whether the file on disk is one this build can read, asked without a
// password.
//
// Everything Load() checks - the magic, the version, the shape - is in the
// clear; only the entries are not. So the question "can this be opened at all"
// can be answered before anybody is asked to type anything, which is the
// difference between telling somebody their store is unreadable and letting
// them find out after three password attempts.
//
STATUS CCredentialStore::Probe()
{
	if (m_bLoaded)
		return OK;
	if (!Exists())
		return OK;
	return Load();
}

//
// Throws the file away so that Create() can start again.
//
// Only ever the caller's decision - see MH_CredStoreVersion, which is the one
// condition where there is nothing else to be done. It is not a recovery: what
// was in the file is gone, and every machine it held a key for has to be told
// its key again.
//
STATUS CCredentialStore::Discard()
{
	Lock();
	m_Entries.clear();
	m_bLoaded = false;
	m_Salt.clear();
	m_PasswordWrapped.clear();
	m_PlatformWrapped.clear();
	m_BodyNonce.clear();
	m_Body.clear();

	if (QFile::exists(m_Path) && !QFile::remove(m_Path))
		return ERR(MH_CredStoreWriteFailed, QVariantList() << m_Path);

	return OK;
}

STATUS CCredentialStore::Forget()
{
	//
	// Before the fields are cleared, or there is nothing left to name it by.
	//
	CCrypto::PlatformForget(m_PlatformWrapped);

	Lock();

	m_bLoaded = false;
	m_Salt.clear();
	m_PasswordWrapped.clear();
	m_PlatformWrapped.clear();
	m_BodyNonce.clear();
	m_Body.clear();

	if (QFile::exists(m_Path) && !QFile::remove(m_Path))
		return ERR(MH_CredStoreWriteFailed, QVariantList()
			<< QString("could not delete %1").arg(m_Path));

	return OK;
}
