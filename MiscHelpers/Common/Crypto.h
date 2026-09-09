#pragma once
#include "../corehelpers_global.h"

#include <QByteArray>
#include <QString>

//
// The little of OpenSSL this needs, bound at run time.
//
// TaskExplorer already ships libcrypto beside its executables - Qt's TLS backend
// needs it, and the forward-secret PSK handshake of NEXT.md 5.5 rests on it
// being there. So the library is present; what is not present is a way to
// *link* it. The headers and import library exist only inside the Qt build tree
// on the machine that built Qt, and putting that path into the project files
// would leave the next person with a checkout that does not build.
//
// Hence QLibrary and a dozen resolved symbols. It costs a handful of function
// pointers and buys a build that has no new dependency at all: the same DLL
// that is already deployed, already signed by the deployment step, already
// version-matched to the Qt that ships beside it.
//
// The prototypes below are declared here rather than included, which is the
// real risk of this approach: a wrong signature compiles and then corrupts a
// stack. That is what SelfTest is for, and why IsAvailable runs it before ever
// saying yes.
//
namespace CCrypto
{
	//
	// Whether libcrypto loaded, every symbol resolved, and the known-answer
	// tests passed. Run once, cached; nothing here is usable before it.
	//
	// The tests are not ceremony. Binding an API by hand can be wrong in ways
	// that still round-trip - a mismatched tag length, a key silently truncated -
	// and a store that encrypts and decrypts its own data perfectly well while
	// being much weaker than intended would never show a symptom. Published
	// vectors are the only thing that catches that.
	//
	COREHELPERS_EXPORT bool			IsAvailable(QString* pWhy = nullptr);

	COREHELPERS_EXPORT QByteArray	Random(int Length);

	//
	// PBKDF2-HMAC-SHA512. Iterations is stored beside whatever it produced, so
	// the cost can be raised later without stranding files written today.
	//
	COREHELPERS_EXPORT QByteArray	DeriveKey(const QByteArray& Password, const QByteArray& Salt,
											  int Iterations, int Length);

	//
	// AES-256-GCM. The tag is appended to the ciphertext rather than returned
	// separately - it is not optional and nothing should be able to forget it.
	//
	// Aad is authenticated but not encrypted: the file header goes in it, so a
	// header somebody edited fails to decrypt rather than being quietly obeyed.
	//
	COREHELPERS_EXPORT QByteArray	Encrypt(const QByteArray& Key, const QByteArray& Nonce,
											const QByteArray& Plain, const QByteArray& Aad = QByteArray());

	//
	// Empty on failure, which for GCM means the data or the header was altered.
	// A caller cannot tell a wrong password from a damaged file and should not
	// try to: both mean "this did not open".
	//
	COREHELPERS_EXPORT QByteArray	Decrypt(const QByteArray& Key, const QByteArray& Nonce,
											const QByteArray& Sealed, const QByteArray& Aad = QByteArray(),
											bool* pOk = nullptr);

	//
	// Overwrites the bytes before they are freed.
	//
	// Worth almost nothing on its own - Qt has already copied this value around
	// and the operating system may have paged it out - and worth doing anyway,
	// because the copy it does clear is the long-lived one.
	//
	COREHELPERS_EXPORT void			Wipe(QByteArray& Data);

	//
	// Verifies an ECDSA P-256 signature over a SHA-256 hash.
	//
	// Here rather than beside the thing that needs it because this is where the
	// binding to libcrypto lives, and a second one somewhere else would be a
	// second set of hand-declared prototypes to get wrong.
	//
	// PublicKey is the 64 raw bytes of the point, X then Y - which is what sits
	// inside a BCrypt ECCPUBLIC blob after its header, so the same key material
	// serves both platforms. Signature is the raw 64 bytes, R then S, which is
	// also what BCrypt produces and consumes; DER is not accepted and is not
	// what the certificates carry.
	//
	// Only used where BCrypt is not: on Windows the certificate check calls the
	// platform directly, because a signature check that cannot run leaves a
	// service refusing to start, and that should not depend on a DLL beside the
	// executable being the right one.
	//
	COREHELPERS_EXPORT bool			VerifyEcdsaP256(const QByteArray& PublicKey, const QByteArray& Hash,
													const QByteArray& Signature, QString* pWhy = nullptr);

	//
	// Key material protected by the platform, so that it need not be typed.
	//
	// Windows: DPAPI, bound to the logged-on user. Nothing else on the machine
	// can unwrap it, and it does not travel - which is exactly the intent: the
	// password is what makes the file portable, and this is only a convenience
	// on one machine.
	//
	// Available() is false where there is nothing to use, and every caller has
	// to work without it - see CCredentialStore, which then asks for the
	// password every session.
	//
	COREHELPERS_EXPORT bool			PlatformSecretAvailable();
	//
	// Empty when the platform can keep a secret. Otherwise a sentence saying
	// what is missing - see the implementation for why the distinction matters.
	//
	COREHELPERS_EXPORT QString		PlatformSecretReason();

	COREHELPERS_EXPORT QByteArray	PlatformWrap(const QByteArray& Secret);
	COREHELPERS_EXPORT QByteArray	PlatformUnwrap(const QByteArray& Wrapped);

	//
	// Discards a wrapping that is no longer wanted.
	//
	// A DPAPI blob is the secret and goes when the file that holds it does, so
	// there is nothing to do; a keyring entry outlives the file and has to be
	// removed, or every time somebody turns this off and on again the keyring
	// gains another orphan nobody can account for.
	//
	COREHELPERS_EXPORT void			PlatformForget(const QByteArray& Wrapped);
}
