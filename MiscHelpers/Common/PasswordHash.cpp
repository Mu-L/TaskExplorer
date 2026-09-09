#include "stdafx.h"
#include "PasswordHash.h"

#include <QRandomGenerator>
#include <QPasswordDigestor>
#include <QCryptographicHash>

QByteArray CPasswordHash::MakeSalt()
{
	//
	// QRandomGenerator::system() is the operating system's generator, not the
	// seeded one QRandomGenerator::global() gives.
	//
	QByteArray Salt(PWHASH_SALT_BYTES, 0);
	for (int i = 0; i < Salt.size(); i++)
		Salt[i] = (char)QRandomGenerator::system()->bounded(256);
	return Salt;
}

QByteArray CPasswordHash::Derive(const QByteArray& Password, const QByteArray& Salt, int Iterations)
{
	if (Salt.isEmpty() || Iterations <= 0)
		return QByteArray();

	return QPasswordDigestor::deriveKeyPbkdf2(QCryptographicHash::Sha512,
		Password, Salt, (int)Iterations, PWHASH_KEY_BYTES);
}

bool CPasswordHash::EqualsConstantTime(const QByteArray& A, const QByteArray& B)
{
	//
	// The length is compared first and in the clear, which leaks it - and does
	// not matter here: everything this compares is a fixed-size digest, so the
	// length was never a secret. What must not leak is *where* two values of the
	// same length first differ.
	//
	if (A.size() != B.size())
		return false;

	unsigned char Diff = 0;
	for (int i = 0; i < A.size(); i++)
		Diff |= (unsigned char)(A[i] ^ B[i]);
	return Diff == 0;
}

bool CPasswordHash::Verify(const QByteArray& Password, const QByteArray& Salt,
                           const QByteArray& Expected, int Iterations)
{
	if (Salt.isEmpty() || Expected.isEmpty() || Iterations <= 0)
		return false;

	return EqualsConstantTime(Derive(Password, Salt, Iterations), Expected);
}
