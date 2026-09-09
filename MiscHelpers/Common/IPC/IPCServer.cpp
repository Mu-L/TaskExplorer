#include "stdafx.h"
#include "IPCServer.h"
#include "IPCSocket.h"

#include <QLocalServer>
#include <QLocalSocket>
#include <QTcpServer>
#include <QSslSocket>
#include <QSslConfiguration>
#include <QSslCipher>
#include <QSslPreSharedKeyAuthenticator>
#include <QDateTime>
#include <QRandomGenerator>
#include <QHostAddress>

#ifndef WIN32
#include <unistd.h>
#endif


CIPCServer::CIPCServer(QObject* parent)
	: QObject(parent), m_pServer(nullptr), m_AllowedUid((quint64)-1), m_bOpenAccess(false)
{
}

CIPCServer::~CIPCServer()
{
	Close();
}

//
// The network listener.
//
// A QTcpServer subclass rather than QSslServer: the handshake has to be set up
// per socket - the PSK callback is a signal on the socket, not on the server -
// and doing it in incomingConnection is both the earliest and the clearest
// place. It also means the socket is never handed out half-negotiated: nothing
// above this sees it until it is encrypted.
//
class CTlsServer : public QTcpServer
{
public:
	CTlsServer(CIPCServer* pOwner) : QTcpServer(pOwner), m_pOwner(pOwner) {}

protected:
	void incomingConnection(qintptr Handle) override
	{
		QSslSocket* pSocket = new QSslSocket(this);
		if (!pSocket->setSocketDescriptor(Handle))
		{
			delete pSocket;
			return;
		}

		const QString Address = pSocket->peerAddress().toString();

		//
		// Refused before the handshake, not after: the point of the limit is to
		// make grinding keys expensive, and a rejected connection that still
		// costs a full key exchange has not made it expensive enough.
		//
		if (m_pOwner->IsRateLimited(Address))
		{
			pSocket->abort();
			pSocket->deleteLater();
			return;
		}

		pSocket->setSslConfiguration(CIPCSocket::TlsConfiguration());

		//
		// What the three handlers below share, and who owns it.
		//
		// They are three separate lambdas on one socket, so anything they all
		// need has to outlive each of them - and be freed exactly once, by
		// something that knows when the last of them can no longer run. That is
		// the socket’s own destruction, so this hangs off destroyed().
		//
		// bAdopted is the important half. Once the handshake completes the
		// socket belongs to a CIPCSocket, and from that moment the error
		// handler must not touch it: the peer going away is then an ordinary
		// disconnection that the owner deals with, not a failed handshake.
		//
		struct SPending
		{
			QByteArray	Identity;
			bool		bAdopted = false;
		};

		CIPCServer* pOwner = m_pOwner;
		SPending* pPending = new SPending();
		QObject::connect(pSocket, &QObject::destroyed, [pPending]() { delete pPending; });
		//
		// No identity hint is set. A server that offered one would be listing
		// its accounts to anybody who opened a socket to it.
		//
		QObject::connect(pSocket, &QSslSocket::preSharedKeyAuthenticationRequired,
			pSocket, [pOwner, pPending](QSslPreSharedKeyAuthenticator* pAuth)
			{
				pPending->Identity = pAuth->identity();

				//
				// An unknown identity is answered with a *random* key, not with
				// none.
				//
				// Answering with none is what this did first, on the reasoning that
				// a handshake with no key fails just as a handshake with the wrong
				// one does. Measured from a client, it does not: OpenSSL sends
				// "unknown psk identity" for the first and "bad record mac" for the
				// second, and the difference is readable by anybody who opens a
				// socket. That turns guessing an identity - which travels in the
				// clear, and may be a name somebody can reason about - into
				// something an attacker is told the answer to, one guess at a time,
				// before they have had to attack the key at all.
				//
				// A random key of a plausible length fails the same way a wrong one
				// does, because that is exactly what it is.
				//
				QByteArray Key = pOwner->m_Resolve ? pOwner->m_Resolve(pPending->Identity) : QByteArray();
				if (Key.isEmpty())
				{
					Key.resize(32);
					for (int i = 0; i < Key.size(); i++)
						Key[i] = (char)QRandomGenerator::system()->bounded(256);
				}
				pAuth->setPreSharedKey(Key);
			});

		QObject::connect(pSocket, &QSslSocket::encrypted, pSocket, [pOwner, pSocket, pPending]()
			{
				pPending->bAdopted = true;

				CIPCSocket* pIpc = new CIPCSocket(pSocket);

				//
				// Nobody, yet.
				//
				// This used to be the moment the caller got a name: the PSK
				// identity that completed the handshake was written straight in
				// as the account, and the server looked its rights up from it.
				// That worked because each identity had its own key, so holding
				// one meant being that one.
				//
				// It does not work now and must not look as though it does. The
				// transport secret is shared, so completing the handshake proves
				// only that the caller was allowed to open a tunnel - which is a
				// statement about the machine, not about a person. The identity
				// is a constant and says nothing at all. Who this is gets
				// settled inside the tunnel, by a login the server can refuse.
				//
				CIPCSocket::SPeer Peer;
				Peer.bNetwork = true;
				pIpc->SetPeer(Peer);

				pOwner->AdoptConnection(pIpc);
			});

		QObject::connect(pSocket, &QSslSocket::errorOccurred, pSocket,
			[pOwner, pSocket, Address, pPending](QAbstractSocket::SocketError)
			{
				//
				// Nothing to do once the connection has been handed over.
				//
				// This handler used to run regardless, and both of the things it
				// did were wrong afterwards: it freed state the encrypted
				// handler had already freed, and it called deleteLater on a
				// socket a live CIPCSocket was still reading. A viewer being
				// killed while connected therefore took the server down with it -
				// which is exactly how it was found, and it had been there since
				// the TLS listener was written.
				//
				if (pPending->bAdopted)
					return;

				pOwner->NoteHandshakeFailure(Address);
				pSocket->deleteLater();
			});

		pSocket->startServerEncryption();
	}

private:
	CIPCServer* m_pOwner;
};

//
// A sliding window rather than a counter that something has to reset. Old
// failures are dropped as they are looked at, which is the only place the list
// is walked anyway.
//
static void DropOlderThan(QList<quint64>& Times, quint64 Now, int WindowMs)
{
	while (!Times.isEmpty() && Now - Times.first() > (quint64)WindowMs)
		Times.removeFirst();
}

bool CIPCServer::IsRateLimited(const QString& Address)
{
	const quint64 Now = (quint64)QDateTime::currentMSecsSinceEpoch();

	DropOlderThan(m_AllFailures, Now, m_LimitWindowMs);
	if (m_AllFailures.count() >= m_MaxGlobal)
		return true;

	QList<quint64>& Times = m_Failures[Address];
	DropOlderThan(Times, Now, m_LimitWindowMs);
	return Times.count() >= m_MaxPerAddress;
}

void CIPCServer::NoteHandshakeFailure(const QString& Address)
{
	const quint64 Now = (quint64)QDateTime::currentMSecsSinceEpoch();
	m_AllFailures.append(Now);
	m_Failures[Address].append(Now);
}

void CIPCServer::AdoptConnection(CIPCSocket* pSocket)
{
	pSocket->setParent(this);
	m_Connections.append(pSocket);
	QObject::connect(pSocket, SIGNAL(Disconnected()), this, SLOT(OnDisconnected()));
	emit NewConnection(pSocket);
}

bool CIPCServer::ListenTcp(quint16 Port, const FResolveKey& Resolve, QString* pError,
                           const QString& Bind)
{
	if (!QSslSocket::supportsSsl())
	{
		if (pError)
			*pError = QString("this build has no TLS support");
		return false;
	}

	//
	// Nothing to authenticate with means nothing to authenticate, and a network
	// listener that let anybody in would be worse than none at all.
	//
	if (!Resolve)
	{
		if (pError)
			*pError = QString("no keys configured");
		return false;
	}

	if (CIPCSocket::TlsConfiguration().ciphers().isEmpty())
	{
		if (pError)
			*pError = QString("this TLS backend offers no forward-secret PSK cipher suite");
		return false;
	}

	QHostAddress Address = QHostAddress::Any;
	if (!Bind.isEmpty() && !Address.setAddress(Bind))
	{
		if (pError)
			*pError = QString("\"%1\" is not an address").arg(Bind);
		return false;
	}

	m_Resolve = Resolve;
	m_pTlsServer = new CTlsServer(this);
	if (!m_pTlsServer->listen(Address, Port))
	{
		if (pError)
			*pError = m_pTlsServer->errorString();
		delete m_pTlsServer;
		m_pTlsServer = nullptr;
		return false;
	}
	return true;
}

bool CIPCServer::Listen(const QString& Name, QString* pError)
{
	//
	// The local half only. The two listeners are independent - a daemon commonly
	// serves its own machine locally and the network at the same time - and
	// taking the whole thing down here would mean the order the two were started
	// in decided whether both survived.
	//
	if (m_pServer)
	{
		m_pServer->close();
		delete m_pServer;
		m_pServer = nullptr;
	}

	m_pServer = new QLocalServer(this);

	//
	// Set before listen(), because this is what the endpoint is created with -
	// applying it afterwards would leave a window in which it was open.
	//
	m_pServer->setSocketOptions(m_bOpenAccess
		? QLocalServer::WorldAccessOption
		: QLocalServer::UserAccessOption);

	//
	// Is somebody already serving this name?
	//
	// QLocalServer::listen() will not tell us: measured on both platforms, a
	// second listen() on a name a live server holds succeeds. On Linux the
	// later server silently takes every subsequent connection; on Windows the
	// pipe gains another instance and clients are split between them. Either
	// way the first server goes on believing it is serving.
	//
	// So ask directly. A short timeout: this is a local endpoint and either
	// something accepts immediately or nothing is there.
	//
	// This is a correctness check, not a security control - a squatter would
	// not probe, and there is a window between here and the bind below. What
	// keeps another user out is the endpoint's permissions; see IPCServer.h.
	//
	{
		QLocalSocket Probe;
		Probe.connectToServer(Name);
		if (Probe.waitForConnected(250))
		{
			Probe.abort();
			if (pError)
				*pError = QString("\"%1\" is already being served by another process").arg(Name);
			delete m_pServer;
			m_pServer = nullptr;
			return false;
		}
	}

	//
	// No removeServer() before binding, deliberately.
	//
	// Qt offers it for the case of a stale unix socket left by a crash, and it
	// is tempting to call it unconditionally - but it deletes whatever is
	// there, including another process's live endpoint, which is the very
	// takeover the probe above exists to avoid. A stale socket after a crash is
	// the rarer problem and the one a human can see and remove.
	//
	if (!m_pServer->listen(Name))
	{
		if (pError)
			*pError = m_pServer->errorString();
		delete m_pServer;
		m_pServer = nullptr;
		return false;
	}

	QObject::connect(m_pServer, SIGNAL(newConnection()), this, SLOT(OnNewConnection()));
	return true;
}

void CIPCServer::Close()
{
	foreach(CIPCSocket* pSocket, m_Connections)
		delete pSocket;
	m_Connections.clear();

	if (m_pServer)
	{
		m_pServer->close();
		delete m_pServer;
		m_pServer = nullptr;
	}

	if (m_pTlsServer)
	{
		m_pTlsServer->close();
		delete m_pTlsServer;
		m_pTlsServer = nullptr;
	}
}

bool CIPCServer::IsListening() const
{
	return m_pServer && m_pServer->isListening();
}

QString CIPCServer::GetName() const
{
	return m_pServer ? m_pServer->serverName() : QString();
}

void CIPCServer::OnNewConnection()
{
	while (QLocalSocket* pRaw = m_pServer->nextPendingConnection())
	{
		CIPCSocket* pSocket = new CIPCSocket(pRaw, this);
		const CIPCSocket::SPeer Peer = pSocket->GetPeer();

		//
		// An unidentifiable peer is refused, not admitted.
		//
		// It should not happen - the kernel answers for a local connection on
		// both platforms - so if it does, something is not what it appears to
		// be. Defaulting the other way would mean the one case worth being
		// suspicious of is the one that gets through.
		//
		if (!Peer.Known)
		{
			qWarning("CIPCServer: refusing a connection whose peer could not be identified");
			delete pSocket;
			continue;
		}

#ifndef WIN32
		if (m_AllowedUid != (quint64)-1 && Peer.Uid != m_AllowedUid)
		{
			qWarning("CIPCServer: refusing uid %llu, only %llu is allowed",
				(unsigned long long)Peer.Uid, (unsigned long long)m_AllowedUid);
			delete pSocket;
			continue;
		}
#endif

		QObject::connect(pSocket, SIGNAL(Disconnected()), this, SLOT(OnDisconnected()));
		m_Connections.append(pSocket);

		emit NewConnection(pSocket);
	}
}

void CIPCServer::OnDisconnected()
{
	CIPCSocket* pSocket = qobject_cast<CIPCSocket*>(sender());
	if (!pSocket)
		return;

	m_Connections.removeAll(pSocket);

	//
	// deleteLater, not delete: this runs from the socket's own signal, and the
	// socket is still on the stack above us.
	//
	pSocket->deleteLater();
}
