#pragma once
#include "../corehelpers_global.h"

#include <QByteArray>
#include <QCryptographicHash>

//
// What proves who a connection is.
//
// Two separate secrets, because they answer two separate questions.
//
// ---- why it is two and not one ----
//
// It was one: a per-identity pre-shared key, listed in the server's key file
// with the role it granted. That key was the transport key, the login, and the
// authorisation all at once, so reading one file on the server made the reader
// an administrator of it - no cracking, no guessing, just the file.
//
// Now the PSK secures the wire and does nothing else. Everyone who may reach
// this server at all shares it, and holding it is worth exactly one thing: a
// TLS session. Who you are is settled afterwards, inside that session, with a
// name and a password the server has never stored - it keeps a salt and a slow
// hash, so a stolen disk image is a cracking problem rather than a login.
//
// ---- what is still true of a stolen PSK ----
//
// Every cipher suite offered is (EC)DHE-PSK - see CIPCSocket::TlsConfiguration -
// so it is forward-secret: somebody who takes the PSK out of a backup cannot go
// back and decrypt traffic they recorded, and therefore cannot lift a password
// out of it. What they *can* do is stand between a viewer and the server and
// finish the handshake themselves, and then a password crosses to them as it is
// typed. That is a much narrower thing to have to arrange than reading a file,
// which is the point, but it is not nothing and it is why the PSK still belongs
// in a directory only administrators can read.
//
// ---- the identity ----
//
// The PSK identity travels in the clear in the ClientHello, so it must not say
// anything worth knowing - not a person, not an account, not this machine. It is
// a constant now, the same for every client, which is the least it can be: there
// is one PSK, so there is nothing for an identity to select.
//
struct SCredentials
{
	//
	// The shared transport secret, as typed. Any length - see DeriveTlsKey.
	//
	QByteArray	Psk;

	//
	// Who is logging in, once the tunnel is up. Never on the wire in the clear.
	//
	QByteArray	User;
	QByteArray	Password;

	//
	// A password may legitimately be empty on a system account somebody has set
	// up that way, so it is not part of this. A name is not optional.
	//
	bool IsValid() const { return !Psk.isEmpty() && !User.isEmpty(); }

	//
	// What every client offers as its PSK identity.
	//
	static QByteArray TlsIdentity() { return QByteArrayLiteral("taskexplorer"); }

	//
	// A secret of any length, turned into the fixed-length key TLS needs.
	//
	// Which is what lets the PSK be a passphrase somebody can type and read out
	// over a telephone rather than 64 hex characters. The hash is what enforces
	// the length, so nothing upstream has to; a one-character PSK is a bad PSK,
	// but it is bad for its entropy and not because it is the wrong size.
	//
	// Prefixed, so that this hash is only ever this hash. The same secret used
	// for something else later would derive a different value there, and neither
	// use can be replayed into the other.
	//
	static QByteArray DeriveTlsKey(const QByteArray& Psk)
	{
		if (Psk.isEmpty())
			return QByteArray();
		return QCryptographicHash::hash(QByteArrayLiteral("TaskExplorer-TLS-PSK-v1")
			+ Psk, QCryptographicHash::Sha256);
	}
};
