#include "stdafx.h"
#include "Crypto.h"

#include <QLibrary>
#include <QRandomGenerator>
#include <QCoreApplication>

// For the deadline on the keyring probe; see LoadLibSecret.
#include <thread>
#include <atomic>
#include <chrono>
#include <memory>
#include <QDir>
#include <QMutex>

#ifdef WIN32
#include <windows.h>
#include <wincrypt.h>

//
// Named here rather than in the project files. Crypt32 is wanted by exactly one
// pair of functions in one file, and a linker input added three build systems
// away from the only code that needs it is one nobody will connect to it later.
//
#pragma comment(lib, "crypt32.lib")
#endif

//
// ---- the resolved entry points ----
//
// Opaque everywhere it can be: none of these types is ever dereferenced here, so
// declaring them as void* costs nothing and removes any chance of this file and
// OpenSSL disagreeing about a layout.
//
namespace {

typedef void* (*Fn_EVP_CIPHER_CTX_new)();
typedef void  (*Fn_EVP_CIPHER_CTX_free)(void*);
typedef int   (*Fn_EVP_CIPHER_CTX_ctrl)(void*, int, int, void*);
typedef const void* (*Fn_EVP_aes_256_gcm)();
typedef int   (*Fn_EVP_EncryptInit_ex)(void*, const void*, void*, const unsigned char*, const unsigned char*);
typedef int   (*Fn_EVP_EncryptUpdate)(void*, unsigned char*, int*, const unsigned char*, int);
typedef int   (*Fn_EVP_EncryptFinal_ex)(void*, unsigned char*, int*);
typedef int   (*Fn_EVP_DecryptInit_ex)(void*, const void*, void*, const unsigned char*, const unsigned char*);
typedef int   (*Fn_EVP_DecryptUpdate)(void*, unsigned char*, int*, const unsigned char*, int);
typedef int   (*Fn_EVP_DecryptFinal_ex)(void*, unsigned char*, int*);
typedef int   (*Fn_PKCS5_PBKDF2_HMAC)(const char*, int, const unsigned char*, int, int,
                                      const void*, int, unsigned char*);
typedef const void* (*Fn_EVP_sha512)();
typedef const void* (*Fn_EVP_sha1)();
typedef int   (*Fn_RAND_bytes)(unsigned char*, int);

//
// The elliptic-curve half, resolved separately - see VerifyEcdsaP256.
//
// EC_KEY_* is deprecated in OpenSSL 3 and still exported by it; the modern
// replacement would mean composing a key from parameters and re-encoding the
// signature as DER, for a check that is eight calls this way. If a build ever
// drops them, the symbols simply do not resolve and the certificate check says
// it cannot verify rather than saying the certificate is bad.
//
#define MY_NID_X9_62_prime256v1 415

typedef void* (*Fn_EC_KEY_new_by_curve_name)(int);
typedef void  (*Fn_EC_KEY_free)(void*);
typedef int   (*Fn_EC_KEY_set_public_key_affine_coordinates)(void*, void*, void*);
typedef void* (*Fn_BN_bin2bn)(const unsigned char*, int, void*);
typedef void  (*Fn_BN_free)(void*);
typedef void* (*Fn_ECDSA_SIG_new)();
typedef void  (*Fn_ECDSA_SIG_free)(void*);
typedef int   (*Fn_ECDSA_SIG_set0)(void*, void*, void*);
typedef int   (*Fn_ECDSA_do_verify)(const unsigned char*, int, const void*, void*);

struct SOpenSsl
{
	Fn_EVP_CIPHER_CTX_new		CtxNew = nullptr;
	Fn_EVP_CIPHER_CTX_free		CtxFree = nullptr;
	Fn_EVP_CIPHER_CTX_ctrl		CtxCtrl = nullptr;
	Fn_EVP_aes_256_gcm			Aes256Gcm = nullptr;
	Fn_EVP_EncryptInit_ex		EncInit = nullptr;
	Fn_EVP_EncryptUpdate		EncUpdate = nullptr;
	Fn_EVP_EncryptFinal_ex		EncFinal = nullptr;
	Fn_EVP_DecryptInit_ex		DecInit = nullptr;
	Fn_EVP_DecryptUpdate		DecUpdate = nullptr;
	Fn_EVP_DecryptFinal_ex		DecFinal = nullptr;
	Fn_PKCS5_PBKDF2_HMAC		Pbkdf2 = nullptr;
	Fn_EVP_sha512				Sha512 = nullptr;
	Fn_EVP_sha1					Sha1 = nullptr;
	Fn_RAND_bytes				RandBytes = nullptr;

	//
	// Optional: resolved on first use by VerifyEcdsaP256, and their absence is
	// not a reason for the rest of this to be unavailable.
	//
	bool						bEcTried = false;
	bool						bEcGood = false;
	QString						EcWhy;
	Fn_EC_KEY_new_by_curve_name	EcNewByCurve = nullptr;
	Fn_EC_KEY_free				EcFree = nullptr;
	Fn_EC_KEY_set_public_key_affine_coordinates EcSetPublic = nullptr;
	Fn_BN_bin2bn				BnBin2Bn = nullptr;
	Fn_BN_free					BnFree = nullptr;
	Fn_ECDSA_SIG_new			SigNew = nullptr;
	Fn_ECDSA_SIG_free			SigFree = nullptr;
	Fn_ECDSA_SIG_set0			SigSet0 = nullptr;
	Fn_ECDSA_do_verify			DoVerify = nullptr;

	bool	bTried = false;
	bool	bGood = false;
	QString	Why;
};

static SOpenSsl	g_Ssl;
static QMutex	g_Mutex;

//
// GCM control codes, spelled out because the header they live in is not
// included. They are ABI, not API: OpenSSL cannot renumber them without
// breaking every binary ever compiled against it.
//
const int EVP_CTRL_AEAD_SET_IVLEN = 0x9;
const int EVP_CTRL_AEAD_GET_TAG   = 0x10;
const int EVP_CTRL_AEAD_SET_TAG   = 0x11;

const int c_TagLength   = 16;
const int c_NonceLength = 12;

//
// Beside the executable first.
//
// The deployed copy is the one Qt's TLS backend already loaded and the one the
// signing step covered; whatever else is on the search path is somebody's
// unrelated OpenSSL, possibly a different major version. Naming the local one
// explicitly means this uses what was shipped rather than what was found.
//
static bool LoadLibCrypto(QLibrary& Library)
{
	const QString Dir = QCoreApplication::applicationDirPath();

	QStringList Names;
#ifdef WIN32
	Names << QDir(Dir).absoluteFilePath("libcrypto-3-x64.dll")
	      << QDir(Dir).absoluteFilePath("libcrypto-3.dll")
	      << "libcrypto-3-x64" << "libcrypto-3";
#else
	Names << QDir(Dir).absoluteFilePath("libcrypto.so.3")
	      << "libcrypto.so.3" << "libcrypto";
#endif

	foreach(const QString& Name, Names)
	{
		Library.setFileName(Name);
		if (Library.load())
			return true;
	}
	return false;
}

static bool Resolve(QLibrary& Library, const char* Name, void** ppFn, QString* pWhy)
{
	*ppFn = (void*)Library.resolve(Name);
	if (*ppFn)
		return true;
	if (pWhy)
		*pWhy = QString("libcrypto has no %1").arg(Name);
	return false;
}

//
// One published vector each for the cipher and the derivation.
//
// AES-256-GCM comes from the GCM specification's own test cases 13 and 14 - the
// empty message and the all-zero block under an all-zero key - which between
// them exercise the tag, the ciphertext and the length handling. PBKDF2 comes
// from RFC 6070, which is stated for HMAC-SHA1; the call being checked is the
// same one used with SHA-512 afterwards, and it is the *binding* that is under
// test here, not the algorithm.
//
static bool RunSelfTest(QString* pWhy)
{
	const QByteArray ZeroKey(32, 0);
	const QByteArray ZeroNonce(12, 0);

	// Case 13: empty plaintext, tag only.
	QByteArray Sealed = CCrypto::Encrypt(ZeroKey, ZeroNonce, QByteArray());
	if (Sealed.toHex() != "530f8afbc74536b9a963b4f1c4cb738b")
	{
		if (pWhy)
			*pWhy = QString("AES-256-GCM test case 13 gave %1").arg(QString::fromLatin1(Sealed.toHex()));
		return false;
	}

	// Case 14: one all-zero block.
	Sealed = CCrypto::Encrypt(ZeroKey, ZeroNonce, QByteArray(16, 0));
	if (Sealed.toHex() != "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")
	{
		if (pWhy)
			*pWhy = QString("AES-256-GCM test case 14 gave %1").arg(QString::fromLatin1(Sealed.toHex()));
		return false;
	}

	//
	// And that a changed byte is refused rather than returning rubbish, which is
	// the property the whole store rests on.
	//
	Sealed[0] = (char)(Sealed[0] ^ 1);
	bool bOk = true;
	CCrypto::Decrypt(ZeroKey, ZeroNonce, Sealed, QByteArray(), &bOk);
	if (bOk)
	{
		if (pWhy)
			*pWhy = "AES-256-GCM accepted altered ciphertext";
		return false;
	}

	// RFC 6070, first vector.
	unsigned char Out[20] = {};
	if (g_Ssl.Pbkdf2("password", 8, (const unsigned char*)"salt", 4, 1,
			g_Ssl.Sha1(), sizeof(Out), Out) != 1)
	{
		if (pWhy)
			*pWhy = "PKCS5_PBKDF2_HMAC failed";
		return false;
	}
	if (QByteArray((const char*)Out, sizeof(Out)).toHex() != "0c60c80f961f0e71f3a9b524af6012062fe037a6")
	{
		if (pWhy)
			*pWhy = "PBKDF2 does not match RFC 6070";
		return false;
	}

	return true;
}

} // namespace

bool CCrypto::IsAvailable(QString* pWhy)
{
	QMutexLocker Locker(&g_Mutex);

	if (g_Ssl.bTried)
	{
		if (pWhy)
			*pWhy = g_Ssl.Why;
		return g_Ssl.bGood;
	}
	g_Ssl.bTried = true;

	//
	// Never unloaded. The resolved pointers outlive any scope this could be
	// released in, and a QLibrary that goes out of scope while its functions are
	// still being called is a crash waiting for the first unlock.
	//
	static QLibrary Library;
	if (!LoadLibCrypto(Library))
	{
		g_Ssl.Why = "libcrypto could not be loaded";
		if (pWhy) *pWhy = g_Ssl.Why;
		return false;
	}

	struct { const char* Name; void** ppFn; } Symbols[] = {
		{ "EVP_CIPHER_CTX_new",   (void**)&g_Ssl.CtxNew },
		{ "EVP_CIPHER_CTX_free",  (void**)&g_Ssl.CtxFree },
		{ "EVP_CIPHER_CTX_ctrl",  (void**)&g_Ssl.CtxCtrl },
		{ "EVP_aes_256_gcm",      (void**)&g_Ssl.Aes256Gcm },
		{ "EVP_EncryptInit_ex",   (void**)&g_Ssl.EncInit },
		{ "EVP_EncryptUpdate",    (void**)&g_Ssl.EncUpdate },
		{ "EVP_EncryptFinal_ex",  (void**)&g_Ssl.EncFinal },
		{ "EVP_DecryptInit_ex",   (void**)&g_Ssl.DecInit },
		{ "EVP_DecryptUpdate",    (void**)&g_Ssl.DecUpdate },
		{ "EVP_DecryptFinal_ex",  (void**)&g_Ssl.DecFinal },
		{ "PKCS5_PBKDF2_HMAC",    (void**)&g_Ssl.Pbkdf2 },
		{ "EVP_sha512",           (void**)&g_Ssl.Sha512 },
		{ "EVP_sha1",             (void**)&g_Ssl.Sha1 },
		{ "RAND_bytes",           (void**)&g_Ssl.RandBytes },
	};

	for (size_t i = 0; i < sizeof(Symbols) / sizeof(Symbols[0]); i++)
	{
		if (!Resolve(Library, Symbols[i].Name, Symbols[i].ppFn, &g_Ssl.Why))
		{
			if (pWhy) *pWhy = g_Ssl.Why;
			return false;
		}
	}

	//
	// Good enough to run the tests with, which is not the same as good. The
	// flag is set before RunSelfTest because the test calls back through
	// Encrypt, and Encrypt refuses to run on a binding that has not been
	// declared usable.
	//
	g_Ssl.bGood = true;
	if (!RunSelfTest(&g_Ssl.Why))
	{
		g_Ssl.bGood = false;
		if (pWhy) *pWhy = g_Ssl.Why;
		return false;
	}

	g_Ssl.Why.clear();
	if (pWhy) pWhy->clear();
	return true;
}

QByteArray CCrypto::Random(int Length)
{
	QByteArray Out(Length, 0);

	//
	// libcrypto's generator when there is one, the operating system's when there
	// is not. Not QRandomGenerator::global(), which is seeded and reproducible
	// and has no business anywhere near a key.
	//
	if (g_Ssl.bGood && g_Ssl.RandBytes
		&& g_Ssl.RandBytes((unsigned char*)Out.data(), Length) == 1)
		return Out;

	for (int i = 0; i < Length; i++)
		Out[i] = (char)QRandomGenerator::system()->bounded(256);
	return Out;
}

QByteArray CCrypto::DeriveKey(const QByteArray& Password, const QByteArray& Salt,
                              int Iterations, int Length)
{
	if (!g_Ssl.bGood)
		return QByteArray();

	QByteArray Out(Length, 0);
	if (g_Ssl.Pbkdf2(Password.constData(), Password.size(),
			(const unsigned char*)Salt.constData(), Salt.size(), Iterations,
			g_Ssl.Sha512(), Length, (unsigned char*)Out.data()) != 1)
		return QByteArray();

	return Out;
}

QByteArray CCrypto::Encrypt(const QByteArray& Key, const QByteArray& Nonce,
                            const QByteArray& Plain, const QByteArray& Aad)
{
	if (!g_Ssl.bGood || Key.size() != 32 || Nonce.size() != c_NonceLength)
		return QByteArray();

	void* pCtx = g_Ssl.CtxNew();
	if (!pCtx)
		return QByteArray();

	QByteArray Out;
	bool bOk = g_Ssl.EncInit(pCtx, g_Ssl.Aes256Gcm(), nullptr, nullptr, nullptr) == 1
		&& g_Ssl.CtxCtrl(pCtx, EVP_CTRL_AEAD_SET_IVLEN, c_NonceLength, nullptr) == 1
		&& g_Ssl.EncInit(pCtx, nullptr, nullptr,
			(const unsigned char*)Key.constData(), (const unsigned char*)Nonce.constData()) == 1;

	int Written = 0;
	if (bOk && !Aad.isEmpty())
		bOk = g_Ssl.EncUpdate(pCtx, nullptr, &Written,
			(const unsigned char*)Aad.constData(), Aad.size()) == 1;

	if (bOk)
	{
		//
		// GCM is a stream cipher underneath, so the ciphertext is exactly as
		// long as the plaintext and there is no block padding to allow for.
		//
		Out.resize(Plain.size());
		if (!Plain.isEmpty())
			bOk = g_Ssl.EncUpdate(pCtx, (unsigned char*)Out.data(), &Written,
				(const unsigned char*)Plain.constData(), Plain.size()) == 1
				&& Written == Plain.size();
	}

	if (bOk)
	{
		unsigned char Tail[32];
		int Final = 0;
		bOk = g_Ssl.EncFinal(pCtx, Tail, &Final) == 1 && Final == 0;
	}

	if (bOk)
	{
		QByteArray Tag(c_TagLength, 0);
		bOk = g_Ssl.CtxCtrl(pCtx, EVP_CTRL_AEAD_GET_TAG, c_TagLength, Tag.data()) == 1;
		if (bOk)
			Out.append(Tag);
	}

	g_Ssl.CtxFree(pCtx);
	return bOk ? Out : QByteArray();
}

QByteArray CCrypto::Decrypt(const QByteArray& Key, const QByteArray& Nonce,
                            const QByteArray& Sealed, const QByteArray& Aad, bool* pOk)
{
	if (pOk)
		*pOk = false;

	if (!g_Ssl.bGood || Key.size() != 32 || Nonce.size() != c_NonceLength
		|| Sealed.size() < c_TagLength)
		return QByteArray();

	const QByteArray Cipher = Sealed.left(Sealed.size() - c_TagLength);
	const QByteArray Tag = Sealed.right(c_TagLength);

	void* pCtx = g_Ssl.CtxNew();
	if (!pCtx)
		return QByteArray();

	QByteArray Out(Cipher.size(), 0);
	int Written = 0;

	bool bOk = g_Ssl.DecInit(pCtx, g_Ssl.Aes256Gcm(), nullptr, nullptr, nullptr) == 1
		&& g_Ssl.CtxCtrl(pCtx, EVP_CTRL_AEAD_SET_IVLEN, c_NonceLength, nullptr) == 1
		&& g_Ssl.DecInit(pCtx, nullptr, nullptr,
			(const unsigned char*)Key.constData(), (const unsigned char*)Nonce.constData()) == 1;

	if (bOk && !Aad.isEmpty())
		bOk = g_Ssl.DecUpdate(pCtx, nullptr, &Written,
			(const unsigned char*)Aad.constData(), Aad.size()) == 1;

	if (bOk && !Cipher.isEmpty())
		bOk = g_Ssl.DecUpdate(pCtx, (unsigned char*)Out.data(), &Written,
			(const unsigned char*)Cipher.constData(), Cipher.size()) == 1;

	//
	// The tag is set before the final call, which is where it is checked. A
	// zero return there means the data or the header was altered - and the
	// plaintext produced so far must be discarded rather than returned, which
	// is the mistake this API shape exists to prevent.
	//
	if (bOk)
		bOk = g_Ssl.CtxCtrl(pCtx, EVP_CTRL_AEAD_SET_TAG, c_TagLength, (void*)Tag.constData()) == 1;

	if (bOk)
	{
		unsigned char Tail[32];
		int Final = 0;
		bOk = g_Ssl.DecFinal(pCtx, Tail, &Final) == 1;
	}

	g_Ssl.CtxFree(pCtx);

	if (!bOk)
	{
		Wipe(Out);
		return QByteArray();
	}

	if (pOk)
		*pOk = true;
	return Out;
}

void CCrypto::Wipe(QByteArray& Data)
{
	if (Data.isEmpty())
		return;

	//
	// Written through a volatile pointer so the compiler may not decide that a
	// buffer about to be freed does not need clearing - which it is entitled to
	// do, and does.
	//
	volatile char* p = Data.data();
	for (int i = 0; i < Data.size(); i++)
		p[i] = 0;
	Data.clear();
}

//
// ---- the platform’s own protection ----
//
// Windows: DPAPI, where the wrapped blob is self-contained ciphertext.
//
// Linux: the Secret Service - gnome-keyring, kwallet, whatever the desktop
// provides - reached through libsecret, loaded the same way libcrypto is above.
//
// Loading it rather than linking it is what lets this live in CoreHelpers at
// all. The first version of this file said no on Linux on the grounds that the
// Secret Service means D-Bus and D-Bus means QtDBus in a library that has
// needed only QtCore - which was a statement about where the code had been put,
// not about what the platform can do, and shipping less for that reason is
// backwards. It is also not only the GUI that wants it: TaskConsole --connect
// unlocks the same store, and a backend that lived in the viewer would leave the
// console asking for a password no script can answer.
//
// There is one real difference from DPAPI, and the interface hides it. A DPAPI
// blob *is* the secret, encrypted; a keyring entry lives in the keyring and what
// is written to our file is only the name to look it up by. Both are "an opaque
// thing that comes back as the secret", which is all the caller ever needed.
//

#ifndef WIN32

//
// libsecret’s simple password API, and the one struct it needs.
//
// The struct is hand-declared, which is the risk of loading rather than
// linking: a wrong layout here is not a compile error, it is a crash inside
// somebody else’s library. That is why PlatformSecretAvailable does a real
// round trip before it answers yes - see the note there.
//
typedef enum { SECRET_SCHEMA_ATTRIBUTE_STRING = 0 } SecretSchemaAttributeType;

struct SecretSchemaAttribute
{
	const char*					name;
	SecretSchemaAttributeType	type;
};

struct SecretSchema
{
	const char*				name;
	int						flags;
	SecretSchemaAttribute	attributes[32];

	// Private in libsecret; present so the size and layout match.
	int						reserved;
	void*					reserved1;
	void*					reserved2;
	void*					reserved3;
	void*					reserved4;
	void*					reserved5;
	void*					reserved6;
	void*					reserved7;
};

//
// SECRET_SCHEMA_DONT_MATCH_NAME is deliberately not set: the schema name is part
// of what identifies these entries, and matching on it keeps TaskExplorer’s
// items apart from everything else in the user’s keyring.
//
static const SecretSchema g_Schema = {
	"org.xanasoft.TaskExplorer.CredentialStore", 0,
	{ { "handle", SECRET_SCHEMA_ATTRIBUTE_STRING }, { NULL, SECRET_SCHEMA_ATTRIBUTE_STRING } },
	0, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

typedef int   (*Fn_secret_password_store_sync)(const SecretSchema*, const char*, const char*,
                                               const char*, void*, void**, ...);
typedef char* (*Fn_secret_password_lookup_sync)(const SecretSchema*, void*, void**, ...);
typedef int   (*Fn_secret_password_clear_sync)(const SecretSchema*, void*, void**, ...);
typedef void  (*Fn_secret_password_free)(char*);
typedef void  (*Fn_g_error_free)(void*);

struct SLibSecret
{
	Fn_secret_password_store_sync	Store = nullptr;
	Fn_secret_password_lookup_sync	Lookup = nullptr;
	Fn_secret_password_clear_sync	Clear = nullptr;
	Fn_secret_password_free			Free = nullptr;
	Fn_g_error_free					ErrorFree = nullptr;

	bool	bTried = false;
	bool	bGood = false;
};

static SLibSecret	g_Secret;
static QMutex		g_SecretMutex;

//
// Stores, reads back and removes a scratch value before claiming the keyring
// works.
//
// Three things it catches, none of which a symbol lookup would: a session with
// no Secret Service running at all (headless, or a desktop without a keyring
// daemon), a keyring that is present but locked, and - the reason it is a round
// trip rather than a version check - a struct laid out differently from the
// declaration above. Answering no costs one password per session. Answering yes
// wrongly means the store believes it can reopen itself and cannot.
//
static bool TestKeyring()
{
	void* pError = nullptr;
	const QByteArray Probe = QByteArray("probe-") + CCrypto::Random(8).toHex();

	if (!g_Secret.Store(&g_Schema, "default", "TaskExplorer self-test",
			"probe", nullptr, &pError, "handle", Probe.constData(), nullptr))
	{
		if (pError && g_Secret.ErrorFree)
			g_Secret.ErrorFree(pError);
		return false;
	}

	pError = nullptr;
	char* pBack = g_Secret.Lookup(&g_Schema, nullptr, &pError, "handle", Probe.constData(), nullptr);
	const bool bOk = pBack && strcmp(pBack, "probe") == 0;
	if (pBack)
		g_Secret.Free(pBack);
	if (pError && g_Secret.ErrorFree)
		g_Secret.ErrorFree(pError);

	pError = nullptr;
	g_Secret.Clear(&g_Schema, nullptr, &pError, "handle", Probe.constData(), nullptr);
	if (pError && g_Secret.ErrorFree)
		g_Secret.ErrorFree(pError);

	return bOk;
}

//
// Why the platform has no secret store, when it has none.
//
// "It did not work" is the same sentence for a machine with no libsecret
// installed, a headless session with no keyring daemon running, and a keyring
// that is simply locked - and those want three different things done about
// them. On a desktop the first two never happen; on a server or under WSL they
// are the normal case, and a viewer that only says "type your password again"
// leaves nowhere to go.
//
static QString g_SecretReason;

static bool LoadLibSecret()
{
	QMutexLocker Locker(&g_SecretMutex);

	if (g_Secret.bTried)
		return g_Secret.bGood;
	g_Secret.bTried = true;

	//
	// Never unloaded, for the same reason as libcrypto: the resolved pointers
	// outlive any scope this could be released in.
	//
	static QLibrary Library;
	static QLibrary Glib;

	QStringList Names;
	Names << "libsecret-1.so.0" << "libsecret-1";
	foreach(const QString& Name, Names)
	{
		Library.setFileName(Name);
		if (Library.load())
			break;
	}
	if (!Library.isLoaded())
	{
		g_SecretReason = QObject::tr("libsecret is not installed on this machine.");
		return false;
	}

	g_Secret.Store = (Fn_secret_password_store_sync)Library.resolve("secret_password_store_sync");
	g_Secret.Lookup = (Fn_secret_password_lookup_sync)Library.resolve("secret_password_lookup_sync");
	g_Secret.Clear = (Fn_secret_password_clear_sync)Library.resolve("secret_password_clear_sync");
	g_Secret.Free = (Fn_secret_password_free)Library.resolve("secret_password_free");

	//
	// g_error_free comes from glib, which libsecret has already pulled in - so
	// this only needs a handle to it, not a load of its own. Optional: without
	// it a failed call leaks a small error struct, which is not worth refusing
	// the whole feature over.
	//
	Glib.setFileName("libglib-2.0.so.0");
	if (Glib.load())
		g_Secret.ErrorFree = (Fn_g_error_free)Glib.resolve("g_error_free");

	if (!g_Secret.Store || !g_Secret.Lookup || !g_Secret.Clear || !g_Secret.Free)
	{
		g_SecretReason = QObject::tr("The libsecret on this machine is not the one this expects.");
		return false;
	}

	//
	// The probe, with a deadline.
	//
	// libsecret's synchronous calls have none of their own, and a keyring that
	// wants to prompt - a fresh login keyring with no password, a session with
	// nowhere to show a dialog - blocks in them for ever. This runs while a
	// viewer is starting up and before it has drawn anything, so "for ever"
	// means the program never appears. Measured on a WSL session with
	// gnome-keyring installed but no desktop to prompt on: it never returned.
	//
	// The thread is deliberately not joined when it times out. It is stuck
	// inside a D-Bus call in somebody else's library; there is no way to cancel
	// that, and killing it would leave that library's locks held. Letting it sit
	// costs one idle thread for the life of the process and is the only thing
	// here that cannot go wrong.
	//
	{
		//
		// A detached thread and a shared answer, not std::async: a future's
		// destructor joins, and joining a thread stuck in D-Bus only moves the
		// hang to whenever that future is destroyed. Measured - with the future
		// kept in a static, the program ran to the end of its work and then sat
		// for ever in exit. Detached, the thread is simply abandoned and the
		// process leaves without it.
		//
		// The state is a shared_ptr so it stays alive if the thread outlives
		// this scope, which is the whole case being handled.
		//
		auto pAnswer = std::make_shared<std::atomic<int> >(-1);	// -1 pending
		std::thread([pAnswer]() { pAnswer->store(TestKeyring() ? 1 : 0); }).detach();

		const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		while (pAnswer->load() < 0 && std::chrono::steady_clock::now() < Deadline)
			std::this_thread::sleep_for(std::chrono::milliseconds(50));

		const int Answer = pAnswer->load();
		if (Answer < 0)
		{
			g_Secret.bGood = false;
			g_SecretReason = QObject::tr(
				"The keyring did not answer. It is most likely waiting for a "
				"prompt that this session cannot show; saved connections still "
				"work and ask for the password each time.");
			return false;
		}
		g_Secret.bGood = (Answer == 1);
	}

	if (!g_Secret.bGood)
	{
		//
		// libsecret is here and answered; what is missing is something for it to
		// talk to. A session with no keyring daemon - a server, a container, a
		// WSL session with no desktop - is the usual case, and it is fixed by
		// running one rather than by trying again.
		//
		g_SecretReason = QObject::tr(
			"No keyring service is running, so there is nowhere to keep the key. "
			"Saved connections still work; they ask for the password each time.");
	}
	return g_Secret.bGood;
}

#endif // !WIN32

bool CCrypto::PlatformSecretAvailable()
{
#ifdef WIN32
	return true;
#else
	return LoadLibSecret();
#endif
}

QString CCrypto::PlatformSecretReason()
{
#ifdef WIN32
	//
	// DPAPI is part of the system and cannot be absent; there is nothing to
	// explain.
	//
	return QString();
#else
	PlatformSecretAvailable();	// works it out, once
	return g_SecretReason;
#endif
}

QByteArray CCrypto::PlatformWrap(const QByteArray& Secret)
{
#ifdef WIN32
	DATA_BLOB In = { (DWORD)Secret.size(), (BYTE*)Secret.constData() };
	DATA_BLOB Out = {};

	//
	// CRYPTPROTECT_UI_FORBIDDEN: this may run while no one is watching - the
	// automatic reconnection of 5.3 unlocks the store without anybody having
	// asked - and a modal system prompt from a background timer would be
	// indistinguishable from a hang.
	//
	if (!CryptProtectData(&In, L"TaskExplorer credentials", NULL, NULL, NULL,
			CRYPTPROTECT_UI_FORBIDDEN, &Out))
		return QByteArray();

	const QByteArray Wrapped((const char*)Out.pbData, (int)Out.cbData);
	LocalFree(Out.pbData);
	return Wrapped;
#else
	if (!LoadLibSecret())
		return QByteArray();

	//
	// A random name to file it under, and the secret hex-encoded because the
	// keyring stores strings and a 32-byte key is not one.
	//
	// The name is what goes in our file. It is not a secret and does not need to
	// be: whoever can read the name still has to be this user, in this session,
	// with the keyring unlocked, before it turns into anything.
	//
	const QByteArray Handle = Random(16).toHex();
	const QByteArray Hex = Secret.toHex();

	void* pError = nullptr;
	const bool bOk = g_Secret.Store(&g_Schema, "default", "TaskExplorer saved connection keys",
		Hex.constData(), nullptr, &pError, "handle", Handle.constData(), nullptr);

	if (pError && g_Secret.ErrorFree)
		g_Secret.ErrorFree(pError);

	return bOk ? Handle : QByteArray();
#endif
}

QByteArray CCrypto::PlatformUnwrap(const QByteArray& Wrapped)
{
#ifdef WIN32
	if (Wrapped.isEmpty())
		return QByteArray();

	DATA_BLOB In = { (DWORD)Wrapped.size(), (BYTE*)Wrapped.constData() };
	DATA_BLOB Out = {};

	if (!CryptUnprotectData(&In, NULL, NULL, NULL, NULL,
			CRYPTPROTECT_UI_FORBIDDEN, &Out))
		return QByteArray();

	QByteArray Secret((const char*)Out.pbData, (int)Out.cbData);
	SecureZeroMemory(Out.pbData, Out.cbData);
	LocalFree(Out.pbData);
	return Secret;
#else
	if (Wrapped.isEmpty() || !LoadLibSecret())
		return QByteArray();

	void* pError = nullptr;
	char* pHex = g_Secret.Lookup(&g_Schema, nullptr, &pError, "handle", Wrapped.constData(), nullptr);

	if (pError && g_Secret.ErrorFree)
		g_Secret.ErrorFree(pError);

	if (!pHex)
		return QByteArray();

	QByteArray Hex(pHex);
	QByteArray Secret = QByteArray::fromHex(Hex);

	//
	// Cleared here as well as freed: libsecret’s buffer is non-pageable, ours is
	// not, and the hex copy is the one that could reach a swap file.
	//
	Wipe(Hex);
	g_Secret.Free(pHex);
	return Secret;
#endif
}

void CCrypto::PlatformForget(const QByteArray& Wrapped)
{
#ifdef WIN32
	//
	// Nothing outside the file to remove.
	//
	Q_UNUSED(Wrapped);
#else
	if (Wrapped.isEmpty() || !LoadLibSecret())
		return;

	void* pError = nullptr;
	g_Secret.Clear(&g_Schema, nullptr, &pError, "handle", Wrapped.constData(), nullptr);
	if (pError && g_Secret.ErrorFree)
		g_Secret.ErrorFree(pError);
#endif
}


//
// ---- ECDSA P-256 ----
//
// The signature check behind the supporter certificate on platforms without
// BCrypt. See TaskCommon/Support.cpp for what is being checked and why.
//
// The point and the signature both arrive as raw big-endian halves, which is
// how BCrypt writes them and how the certificates carry them; nothing here
// parses DER.
//
bool CCrypto::VerifyEcdsaP256(const QByteArray& PublicKey, const QByteArray& Hash,
                              const QByteArray& Signature, QString* pWhy)
{
	auto Fail = [&](const QString& Why) -> bool {
		if (pWhy) *pWhy = Why;
		return false;
	};

	if (PublicKey.size() != 64)
		return Fail("the public key is not a P-256 point");
	if (Signature.size() != 64)
		return Fail("the signature is not a P-256 signature");
	if (Hash.isEmpty())
		return Fail("nothing to verify");

	QString Why;
	if (!CCrypto::IsAvailable(&Why))
		return Fail(Why);

	QMutexLocker Locker(&g_Mutex);

	if (!g_Ssl.bEcTried)
	{
		g_Ssl.bEcTried = true;

		//
		// The same library IsAvailable already loaded and never unloads, reached
		// again by name - QLibrary does not load it twice.
		//
		static QLibrary Library;
		if (!LoadLibCrypto(Library))
			g_Ssl.EcWhy = "libcrypto could not be loaded";
		else
		{
			struct { const char* Name; void** ppFn; } Symbols[] = {
				{ "EC_KEY_new_by_curve_name", (void**)&g_Ssl.EcNewByCurve },
				{ "EC_KEY_free",              (void**)&g_Ssl.EcFree },
				{ "EC_KEY_set_public_key_affine_coordinates", (void**)&g_Ssl.EcSetPublic },
				{ "BN_bin2bn",                (void**)&g_Ssl.BnBin2Bn },
				{ "BN_free",                  (void**)&g_Ssl.BnFree },
				{ "ECDSA_SIG_new",            (void**)&g_Ssl.SigNew },
				{ "ECDSA_SIG_free",           (void**)&g_Ssl.SigFree },
				{ "ECDSA_SIG_set0",           (void**)&g_Ssl.SigSet0 },
				{ "ECDSA_do_verify",          (void**)&g_Ssl.DoVerify },
			};

			g_Ssl.bEcGood = true;
			for (size_t i = 0; i < sizeof(Symbols) / sizeof(Symbols[0]); i++)
			{
				if (!Resolve(Library, Symbols[i].Name, Symbols[i].ppFn, &g_Ssl.EcWhy))
				{
					g_Ssl.bEcGood = false;
					break;
				}
			}
		}
	}

	if (!g_Ssl.bEcGood)
		return Fail(g_Ssl.EcWhy.isEmpty() ? QString("no elliptic curve support") : g_Ssl.EcWhy);

	bool bOk = false;

	void* pKey = g_Ssl.EcNewByCurve(MY_NID_X9_62_prime256v1);
	void* pX = g_Ssl.BnBin2Bn((const unsigned char*)PublicKey.constData(), 32, nullptr);
	void* pY = g_Ssl.BnBin2Bn((const unsigned char*)PublicKey.constData() + 32, 32, nullptr);
	void* pR = g_Ssl.BnBin2Bn((const unsigned char*)Signature.constData(), 32, nullptr);
	void* pS = g_Ssl.BnBin2Bn((const unsigned char*)Signature.constData() + 32, 32, nullptr);
	void* pSig = g_Ssl.SigNew();

	if (pKey && pX && pY && pR && pS && pSig
	 && g_Ssl.EcSetPublic(pKey, pX, pY) == 1
	 && g_Ssl.SigSet0(pSig, pR, pS) == 1)
	{
		//
		// set0 took ownership of r and s, so they must not be freed here - which
		// is why they are cleared rather than left for the cleanup below.
		//
		pR = nullptr;
		pS = nullptr;

		bOk = g_Ssl.DoVerify((const unsigned char*)Hash.constData(), Hash.size(), pSig, pKey) == 1;
		if (!bOk && pWhy)
			*pWhy = "the signature does not match";
	}
	else if (pWhy)
		*pWhy = "the key or the signature could not be read";

	if (pSig) g_Ssl.SigFree(pSig);
	if (pR)   g_Ssl.BnFree(pR);
	if (pS)   g_Ssl.BnFree(pS);
	if (pX)   g_Ssl.BnFree(pX);
	if (pY)   g_Ssl.BnFree(pY);
	if (pKey) g_Ssl.EcFree(pKey);

	return bOk;
}
