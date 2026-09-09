#pragma once

#include "../../corehelpers_global.h"

#include <QObject>
#include <QByteArray>
#include <QString>
#include "../Variant.h"
#include "../Credentials.h"

class QLocalSocket;
class QIODevice;
class QSslConfiguration;

//
// One connection, carrying named messages with a QVariant payload.
//
// Modelled on CIPCSocket from NeoLoader: requests, responses and events, each
// with a name and a sequence number, so a caller can match an answer to its
// question and a server can push something nobody asked for.
//
// Two deliberate differences from that one:
//
//  - **One format, not four.** The original negotiated between XML, JSON,
//    bencode and binary. This carries a length prefix and a CVariant packet,
//    always. CVariant is self-describing, is what TaskHelper already speaks, and
//    is readable without Qt - so a client in another language stays possible,
//    which a QDataStream body would have ruled out.
//
//  - **Commands are identifiers, not strings.** 'proc' is four bytes and reads
//    as "proc" in a packet dump. This class does not know what any of them
//    mean - it carries a uint32 - which is what lets it live in a library
//    beneath TaskCore. The vocabulary is in TaskExplorer/API/ApiDefs.h.
//
//  - **No crypto here at all.** The original encrypted at the message layer
//    with an ECDH exchange and a symmetric key. Locally that is unnecessary:
//    the kernel already knows who connected, and says so - see SPeer - which is
//    stronger than anything a payload could assert about itself. Remotely it is
//    the transport's job; see the note on transports below.
//
// ---- transports ----
//
// This class talks to a QLocalSocket: a named pipe on Windows, a unix domain
// socket on Linux. That is the local case and needs no encryption.
//
// The network case is a QSslSocket with TLS-PSK, and it is not implemented yet.
// When it is, the listener should be QSslServer (Qt 6.4 and later), which does
// the whole job. On a Qt older than 6.4 - which here means the 32-bit build,
// still on Qt 5.15 - QSslServer does not exist, and the network listener is to
// be compiled out rather than half-supported: there has been no 32-bit release
// since TaskHelper arrived.
//
// **Should 32-bit ever need it back, the recipe is this**, and it is all that
// QSslServer does internally:
//
//     class CSslServer : public QTcpServer
//     {
//     protected:
//         void incomingConnection(qintptr Descriptor) override
//         {
//             QSslSocket* pSocket = new QSslSocket(this);
//             if (!pSocket->setSocketDescriptor(Descriptor)) {
//                 delete pSocket;
//                 return;
//             }
//             //
//             // The PSK configuration, not a certificate. Server side answers
//             // preSharedKeyAuthenticationRequired with the secret for the
//             // identity the client offered; the handshake fails by itself if
//             // it does not match, which is the authentication.
//             //
//             pSocket->setSslConfiguration(m_Config);
//             connect(pSocket, &QSslSocket::preSharedKeyAuthenticationRequired,
//                     this, &CSslServer::OnPreSharedKey);
//             //
//             // Server, not client: this end answers a handshake rather than
//             // starting one. That single call is the whole difference.
//             //
//             pSocket->startServerEncryption();
//             addPendingConnection(pSocket);
//         }
//     };
//
// The reason to prefer PSK over a certificate is worth keeping too: PSK gives
// ECDHE for forward secrecy *and* mutual authentication in one step, where a
// self-signed certificate authenticates only the server and leaves "is this
// client allowed" to be answered separately. It also needs no key generation,
// which Qt cannot do in any case - QSslKey loads keys, it does not create them.
//
class COREHELPERS_EXPORT CIPCSocket : public QObject
{
	Q_OBJECT

public:
	//
	// Takes ownership of the device. Use Connect() for the client side.
	//
	// A QIODevice rather than a QLocalSocket, because the same framing runs over
	// a named pipe, a unix socket and a TLS connection - the only differences
	// are how it is opened, how it is closed, and whether the kernel will say
	// who is on the other end.
	//
	CIPCSocket(QIODevice* pDevice, QObject* parent = nullptr);

	//
	// What a network connection authenticates with - see Credentials.h, which
	// is where it is defined and why. The name is kept here because a hundred
	// lines say CIPCSocket::SCredentials and none of them had to change.
	//
	typedef ::SCredentials SCredentials;

	//
	// The TLS settings both ends must agree on, in one place so they cannot
	// drift apart. See the note in the implementation for what is pinned and
	// why - it is not what the plan first assumed.
	//
	static QSslConfiguration TlsConfiguration();
	virtual ~CIPCSocket();

	//
	// Opens a connection to a local server by name, synchronously. Returns NULL
	// if it could not be reached; pError, when given, says why.
	//
	//
	// A name is a local endpoint; "host:port" is a network one and needs
	// credentials. Told apart by the string itself, because a caller that had to
	// say which would eventually say the wrong one.
	//
	static CIPCSocket*	Connect(const QString& Name, int TimeoutMs = 5000, QString* pError = nullptr,
								const SCredentials& Cred = SCredentials());

	//
	// Whether an address names a network endpoint. Public because the viewer
	// asks it too - it decides whether to prompt for credentials.
	//
	static bool			IsNetworkAddress(const QString& Address, QString* pHost = nullptr, quint16* pPort = nullptr);

	//
	// Who is on the other end, according to the kernel.
	//
	// Not according to the peer: everything in a message is whatever the sender
	// chose to write, whereas this comes from the operating system and cannot
	// be forged by the process being described. It is the whole reason the
	// local transport needs no cryptography.
	//
	// Known is false when the platform could not answer - treat that as "no
	// identity", never as "trusted".
	//
	struct SPeer
	{
		bool	Known = false;
		quint64	Pid = 0;
		quint64	Uid = (quint64)-1;	// unix only; -1 where the platform has no uid

		//
		// Who, rather than which process.
		//
		// The account is what an access decision is actually about - a user can
		// have any number of processes and they all get the same answer - and it
		// is the only half of this that a pid cannot be recycled out from under.
		// A SID string on Windows; on Linux the uid above says it, and this
		// carries the same number in text so that one field means "the account"
		// on both.
		//
		QString	Account;

		//
		// Whether the caller may act as an administrator *now*.
		//
		// Two questions, not one. On Windows a member of the Administrators
		// group who has not elevated holds a token where that membership is
		// deny-only: they are an administrator in principle and not in fact, and
		// the answer to "may they" is no. Elevated says the token in hand has
		// the rights; AdminGroup says the account could get them. Anything
		// deciding what to disclose wants the first.
		//
		bool	Elevated = false;
		bool	AdminGroup = false;

		//
		// Whether the account half has been asked for yet. It cannot be had
		// when the connection is made - see ResolvePeer - so this says "already
		// tried" rather than "already known": a second attempt would fail the
		// same way and cost an impersonation each time.
		//
		bool	bResolved = false;

		//
		// Whether any of this came from the kernel rather than from a
		// handshake. True only for a local endpoint - a named pipe or a unix
		// socket - where the operating system answered for the far end.
		//
		// A network peer is nobody at all until it has logged in: completing the
		// handshake proves it holds the shared transport secret and nothing
		// more, because that secret is the same for everyone. Nothing about it
		// may be taken from a token, because there is no token. Anything
		// completing a peer later has to be able to tell the two apart.
		//
		bool	bLocal = false;

		//
		// Whether this peer arrived over the network, as opposed to a local
		// endpoint. Not the inverse of bLocal: bLocal says the kernel answered,
		// and there is a moment early in a local connection where it has not yet
		// - see ResolvePeer. This one is settled when the connection is made and
		// never changes, which is what a login gate needs.
		//
		bool	bNetwork = false;
	};
	SPeer				GetPeer() const					{ return m_Peer; }

	//
	// Fills in the half of the peer that needed a frame to have arrived. Called
	// by the read path; safe and cheap to call more than once.
	//
	void				ResolvePeer();

	//
	// For a connection the kernel cannot answer for. A network peer is whoever
	// completed the handshake, which only the code that ran it knows.
	//
	void				SetPeer(const SPeer& Peer)		{ m_Peer = Peer; }

	//
	// Bytes of the last frame received, and of every frame so far. A delta
	// protocol is worth having only if the numbers say so, and they are not
	// otherwise visible from outside.
	//
	quint64				GetLastFrameSize() const		{ return m_LastFrameSize; }
	quint64				GetTotalReceived() const		{ return m_TotalReceived; }

	bool				IsConnected() const;
	void				Disconnect();

	//
	// The sequence number identifies a conversation. A response carries the
	// number of the request it answers; a request or an event gets a fresh one.
	//
	//
	// Command is an identifier the caller chooses - a uint32, not a name. This
	// class does not interpret it; TaskCore's API_CMD_* values are what happen
	// to travel through it today.
	//
	// The payload is a CVariant and not a QVariant, so that a caller can build
	// an index keyed by uint32. Converting from QVariant would force every
	// dictionary to be a map keyed by strings, which is what the index type
	// exists to avoid - and it is also what travels, so there is one less
	// representation to keep straight.
	//
	quint64				SendRequest(quint32 Command, const CVariant& Data = CVariant());
	bool				SendResponse(quint32 Command, const CVariant& Data, quint64 Number);
	quint64				SendEvent(quint32 Command, const CVariant& Data = CVariant());

	//
	// A frame larger than this is refused and the connection dropped.
	//
	// A listener that may be privileged must not let an unauthenticated peer
	// choose how much memory it allocates: without a cap, "length = 4 GB" is a
	// one-packet denial of service. Generous enough for a full process list.
	//
	static const quint32 c_MaxFrameSize = 64 * 1024 * 1024;

	//
	// And a tighter one, for as long as the peer is still a stranger.
	//
	// The cap above is sized for a full process list, which is far more than
	// anyone needs to say hello. Until whatever protocol runs on top of this has
	// satisfied itself about who is on the other end, a listener should not let
	// an unknown peer reserve megabytes - so it can lower the limit and raise it
	// once it is happy.
	//
	// Deliberately a number and not a notion of authentication: this class
	// carries frames and knows nothing about what they mean, which is why the
	// protocol's own magic value lives inside the first message rather than
	// here. See TaskExplorer/API/ApiDefs.h.
	//
	static const quint32 c_StrangerFrameSize = 4 * 1024;

	void				SetMaxFrameSize(quint32 Size)	{ m_MaxFrameSize = Size; }
	quint32				GetMaxFrameSize() const			{ return m_MaxFrameSize; }

signals:
	void				Request(quint32 Command, const CVariant& Data, quint64 Number);
	void				Response(quint32 Command, const CVariant& Data, quint64 Number);
	void				Event(quint32 Command, const CVariant& Data, quint64 Number);
	void				Disconnected();

private slots:
	void				OnReadyRead();
	void				OnDisconnected();

protected:
	friend class CIPCServer;

	quint32				m_MaxFrameSize = c_MaxFrameSize;

	enum EMessageType
	{
		eRequest	= 1,
		eResponse	= 2,
		eEvent		= 3,
	};

	//
	// The envelope, as the four-character identifiers it is written with.
	//
	// Here rather than in a definitions header, and deliberately: this is not
	// protocol vocabulary but the shape of a message on this socket. Every
	// message has a type, a number, a command and a payload no matter what is
	// being spoken over it, so it belongs to the class and not to whoever is
	// using the class. What a command *means*, and what is in a payload, is
	// TaskCore's business - see API/ApiDefs.h.
	//
	// An index keyed by these rather than a map keyed by names: four bytes per
	// field instead of a string and its length, on every message.
	//
	enum EEnvelope
	{
		eFieldType		= 'mtyp',
		eFieldNumber	= 'mnum',
		eFieldCommand	= 'mcmd',
		eFieldData		= 'mdat',
	};

	//
	// Asks the kernel who is connected. Called by CIPCServer on accept and by
	// Connect() on the client side, so both ends know.
	//
	static bool			QueryPeer(QIODevice* pDevice, SPeer& Peer);
	static CIPCSocket*	ConnectTls(const QString& Host, quint16 Port, const SCredentials& Cred,
								   int TimeoutMs, QString* pError);

	bool				Send(quint8 Type, quint32 Command, const CVariant& Data, quint64 Number);
	void				Fail(const QString& Reason);

	QIODevice*			m_pSocket;
	QByteArray			m_ReadBuffer;
	quint64				m_Counter;
	quint64				m_LastFrameSize = 0;
	quint64				m_TotalReceived = 0;
	SPeer				m_Peer;
};
