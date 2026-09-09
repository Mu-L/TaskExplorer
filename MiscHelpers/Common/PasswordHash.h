#pragma once
#include "../corehelpers_global.h"

#include <QByteArray>
#include <QString>

//
// Turning a password into something safe to keep on a disk.
//
// PBKDF2-HMAC-SHA512, from QtNetwork's QPasswordDigestor - which this already
// links for TLS, so it costs no new dependency. Argon2 would be the better
// choice on the merits and would cost one.
//
// ---- why not a plain hash ----
//
// A single SHA-256 of salt and password is a hash, and it is the wrong one: a
// commodity graphics card tries billions of them a second, so a stolen file of
// them is a list of passwords rather than a cracking problem. The whole reason
// the server stores a hash instead of a key is that a stolen backup should not
// be a login, and a fast hash gives that back.
//
// The iteration count is stored beside each hash rather than fixed here. What is
// slow enough today is not slow enough in five years, and a count in the file
// means it can be raised for new passwords without invalidating the old ones -
// each record says how it was made.
//
#define PWHASH_ITERATIONS_DEFAULT	600000

//
// 16 bytes of salt, which is what stops one cracking run covering every account
// at once. It is not secret and lives in the clear beside the hash.
//
#define PWHASH_SALT_BYTES			16
#define PWHASH_KEY_BYTES			32

namespace CPasswordHash
{
	//
	// A fresh salt from the operating system's generator, not the seeded one.
	//
	COREHELPERS_EXPORT QByteArray	MakeSalt();

	//
	// The stored value for a password. Deterministic given the same three
	// inputs, which is what makes verification a matter of recomputing it.
	//
	COREHELPERS_EXPORT QByteArray	Derive(const QByteArray& Password, const QByteArray& Salt,
										   int Iterations = PWHASH_ITERATIONS_DEFAULT);

	//
	// Recomputes and compares in constant time.
	//
	// Constant time because the comparison is against a value an attacker is
	// trying to produce: a memcmp that returns at the first differing byte says
	// how much of a guess was right, and that turns cracking the hash into
	// guessing it one byte at a time.
	//
	COREHELPERS_EXPORT bool			Verify(const QByteArray& Password, const QByteArray& Salt,
										   const QByteArray& Expected, int Iterations);

	//
	// Equal-length constant-time compare, exposed because the same rule applies
	// to anything else being matched against a secret.
	//
	COREHELPERS_EXPORT bool			EqualsConstantTime(const QByteArray& A, const QByteArray& B);
}
