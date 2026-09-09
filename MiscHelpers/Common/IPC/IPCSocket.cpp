#include "stdafx.h"
#include "IPCSocket.h"

#include <QLocalSocket>
#include <QSslSocket>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QSslPreSharedKeyAuthenticator>
#include <QHostAddress>

#include "../Variant.h"

#ifdef WIN32
#include <windows.h>
#include <sddl.h>		// ConvertSidToStringSidW
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

//
// The frame:
//
//     uint32   Length      of the packet that follows
//     CVariant Packet      an index of EEnvelope fields
//
// The length prefix is written by hand rather than left to the packet, because
// a reader has to know how much to wait for before it can parse anything. Four
// bytes, little-endian, which is what every machine this runs on is - and the
// static assertion in ApiDefs.h is the reminder that the rest of the format
// does not depend on that.
//
static const quint32 c_LengthSize = sizeof(quint32);


CIPCSocket::CIPCSocket(QIODevice* pDevice, QObject* parent)
	: QObject(parent), m_pSocket(pDevice), m_Counter(0)
{
	m_pSocket->setParent(this);

	QObject::connect(m_pSocket, SIGNAL(readyRead()), this, SLOT(OnReadyRead()));

	//
	// The two socket families spell the same event differently and share no base
	// that declares it, so the connection is made against whichever this is.
	// QIODevice has no "disconnected".
	//
	if (QLocalSocket* pLocal = qobject_cast<QLocalSocket*>(m_pSocket))
		QObject::connect(pLocal, SIGNAL(disconnected()), this, SLOT(OnDisconnected()));
	else if (QAbstractSocket* pNet = qobject_cast<QAbstractSocket*>(m_pSocket))
		QObject::connect(pNet, SIGNAL(disconnected()), this, SLOT(OnDisconnected()));

	QueryPeer(m_pSocket, m_Peer);
}

//
// The half of the peer that could not be had at connection time.
//
// Called once, after the first frame has been read. Cheap to call again - it
// returns at once when the account is already known, or when there is nothing
// to ask because this is a network connection whose identity comes from the
// handshake instead.
//
void CIPCSocket::ResolvePeer()
{
	if (m_Peer.bResolved || !m_Peer.Account.isEmpty())
		return;
	m_Peer.bResolved = true;

	SPeer Fresh;
	if (QueryPeer(m_pSocket, Fresh) && !Fresh.Account.isEmpty())
	{
		m_Peer.Account = Fresh.Account;
		m_Peer.Elevated = Fresh.Elevated;
		m_Peer.AdminGroup = Fresh.AdminGroup;
	}
}

//
// What both ends must agree on, and why it is not what the plan first assumed.
//
// The plan said "pin to ECDHE-PSK". Measured against this build that would have
// been a mistake: of the five ECDHE-PSK suites OpenSSL 3.4 offers, four are CBC
// and date from TLS 1.0, and they are worse than the DHE-PSK GCM suites they
// would have been preferred over. What actually matters is two properties -
//
//   - an ephemeral key exchange, so that a captured session cannot be opened
//     later by somebody who eventually learns the key; and
//   - authentication by the key itself rather than by a certificate, which is
//     the whole point of PSK. The RSA-PSK suites need one.
//
// - and an AEAD cipher on top of them. Four suites survive that, listed here in
// the order they should be preferred. ECDHE-PSK-CHACHA20-POLY1305 is the only
// one that is both ECDHE and AEAD, and it is what two of these actually settle
// on.
//
// TLS 1.2, and that is a requirement rather than a preference. Qt PSK signals
// are the TLS 1.2 external-PSK mechanism; 1.3 reuses the session-resumption
// path and Qt does not wire an external key into it, so a handshake allowed to
// reach 1.3 with only PSK suites configured fails with "no suitable signature
// algorithm". Measured, not guessed.
//
QSslConfiguration CIPCSocket::TlsConfiguration()
{
	QSslConfiguration Cfg = QSslConfiguration::defaultConfiguration();

	//
	// There are no certificates here, so there is nothing to verify and nothing
	// to warn about. What authenticates both ends is the key: a server without
	// it cannot finish the handshake, and neither can a client.
	//
	Cfg.setPeerVerifyMode(QSslSocket::VerifyNone);
	Cfg.setProtocol(QSsl::TlsV1_2);

	static const char* Order[] = {
		"ECDHE-PSK-CHACHA20-POLY1305",
		"DHE-PSK-AES256-GCM-SHA384",
		"DHE-PSK-CHACHA20-POLY1305",
		"DHE-PSK-AES128-GCM-SHA256",
	};

	const QList<QSslCipher> Supported = QSslConfiguration::supportedCiphers();
	QList<QSslCipher> Picked;
	for (size_t i = 0; i < sizeof(Order) / sizeof(Order[0]); i++)
	{
		foreach(const QSslCipher& C, Supported)
		{
			if (C.name() == QLatin1String(Order[i]))
				{ Picked.append(C); break; }
		}
	}
	Cfg.setCiphers(Picked);
	return Cfg;
}

//
// "host:port", as opposed to a pipe or socket name.
//
// The port is what tells them apart: a local endpoint name may contain anything
// else, and requiring a scheme would mean every address written so far had to
// grow one.
//
bool CIPCSocket::IsNetworkAddress(const QString& Address, QString* pHost, quint16* pPort)
{
	//
	// "[v6]:port" first, because an IPv6 literal is full of colons and there is
	// no way to find the port in one without the brackets.
	//
	// The scope id an announcement arrives with - fe80::1%12 - is part of the
	// address and is kept; without it a link-local address is not routable back,
	// and discovery on a machine with more than one interface produces almost
	// nothing else. The brackets themselves are removed, because they are
	// notation rather than address and Qt will not resolve a name containing
	// them.
	//
	if (Address.startsWith(QLatin1Char('[')))
	{
		const int Close = Address.indexOf(QLatin1Char(']'));
		if (Close < 2 || Close + 2 >= Address.length() || Address[Close + 1] != QLatin1Char(':'))
			return false;

		bool bOk = false;
		const ushort Port = Address.mid(Close + 2).toUShort(&bOk);
		if (!bOk || Port == 0)
			return false;

		if (pHost)
			*pHost = Address.mid(1, Close - 1);
		if (pPort)
			*pPort = Port;
		return true;
	}

	//
	// Otherwise exactly one colon, and nothing that looks like an address in
	// front of it.
	//
	// It used to take the *last* colon and treat everything before it as a host,
	// which reads as tolerant and is a guess: "fe80::1" then parses as the host
	// "fe80:" on port 1, and a bare IPv6 address becomes a connection attempt to
	// something that does not exist. Refusing what is ambiguous costs nothing -
	// a v6 address has to be bracketed to have a port at all.
	//
	const int Colon = Address.indexOf(QLatin1Char(':'));
	if (Colon <= 0 || Address.indexOf(QLatin1Char(':'), Colon + 1) != -1)
		return false;

	bool bOk = false;
	const ushort Port = Address.mid(Colon + 1).toUShort(&bOk);
	if (!bOk || Port == 0)
		return false;

	if (pHost)
		*pHost = Address.left(Colon);
	if (pPort)
		*pPort = Port;
	return true;
}


CIPCSocket::~CIPCSocket()
{
}

CIPCSocket* CIPCSocket::Connect(const QString& Name, int TimeoutMs, QString* pError,
                                const SCredentials& Cred)
{
	QString Host;
	quint16 Port = 0;
	if (IsNetworkAddress(Name, &Host, &Port))
		return ConnectTls(Host, Port, Cred, TimeoutMs, pError);

	QLocalSocket* pSocket = new QLocalSocket();
	pSocket->connectToServer(Name);
	if (!pSocket->waitForConnected(TimeoutMs))
	{
		//
		// What was being attempted, then the library's words for why it did not
		// work. On its own the second is a sentence about a socket - "Invalid
		// name", "Connection refused" - which says nothing about the daemon
		// somebody was trying to reach or the name they reached it by.
		//
		if (pError)
			*pError = QObject::tr("No daemon answered as \"%1\" on this machine. (%2)")
				.arg(Name).arg(pSocket->errorString());
		delete pSocket;
		return nullptr;
	}

	return new CIPCSocket(pSocket);
}

CIPCSocket* CIPCSocket::ConnectTls(const QString& Host, quint16 Port,
                                   const SCredentials& Cred, int TimeoutMs, QString* pError)
{
	if (Cred.Psk.isEmpty())
	{
		if (pError)
			*pError = QObject::tr("No transport key for this machine.");
		return nullptr;
	}

	if (!QSslSocket::supportsSsl())
	{
		if (pError)
			*pError = QObject::tr("This build has no TLS support.");
		return nullptr;
	}

	QSslSocket* pSocket = new QSslSocket();
	pSocket->setSslConfiguration(TlsConfiguration());

	//
	// The key goes in when the library asks for it and only then; it is never
	// held anywhere this class could be asked for it.
	//
	// Any identity hint the server offers is ignored, and no server here sends
	// one: a hint enumerates the account list to whoever connects. Nor is one
	// needed - the identity is a constant, because there is a single shared
	// transport secret and nothing for an identity to select.
	//
	// Hashed to length here rather than being required to arrive at it, so that
	// the secret can be a passphrase somebody types. See SCredentials.
	//
	const QByteArray Identity = SCredentials::TlsIdentity();
	const QByteArray Key = SCredentials::DeriveTlsKey(Cred.Psk);
	QObject::connect(pSocket, &QSslSocket::preSharedKeyAuthenticationRequired,
		[Identity, Key](QSslPreSharedKeyAuthenticator* pAuth)
		{
			pAuth->setIdentity(Identity);
			pAuth->setPreSharedKey(Key);
		});

	//
	// Whether the machine was reached at all, which is the only distinction
	// worth drawing here and cannot be drawn afterwards: by the time the wait
	// returns, a socket that connected and was then dropped is in the same
	// state as one that never connected.
	//
	bool bReached = false;
	QObject::connect(pSocket, &QAbstractSocket::connected, [&bReached]() { bReached = true; });

	pSocket->connectToHostEncrypted(Host, Port);
	if (!pSocket->waitForEncrypted(TimeoutMs))
	{
		//
		// A wrong key looks exactly like any other handshake failure from here,
		// and that is correct: a server that distinguished "no such identity"
		// from "wrong key" would answer a question nobody should be able to ask.
		//
		// Which is why the reading is chosen by whether the machine answered at
		// all rather than by which error came back. The two cases really do
		// arrive differently - a wrong key for a known identity fails the
		// handshake outright with "bad record mac", while an identity the server
		// has never heard of gets no key to fail with and the connection simply
		// ends, reported as "Unknown error". Reading the error code would have
		// worded the first and given up on the second, and the second is the
		// more likely mistake.
		//
		// The library's own words are kept after it: by far the likeliest cause
		// is a mistyped key, and neither of those strings says that to anyone
		// who has not spent time inside a TLS library - but one of them is the
		// only thing that would help if the cause were something else entirely.
		//
		if (pError)
		{
			if (bReached)
				*pError = QObject::tr("The machine did not accept this identity and key. (%1)")
					.arg(pSocket->errorString());
			//
			// Nothing was set on the socket, so the wait simply ran out. That is a
			// different failure from being refused and needs saying differently:
			// a refusal means something answered, a timeout means nothing did.
			//
			// It is also where the reading of "unknown error" came from - Qt's
			// string for a socket that has no error because none was reported,
			// which is exactly the case when a firewall discards the packets
			// instead of refusing them. Passing that through told the reader
			// nothing at all about a situation with an ordinary explanation.
			//
			else if (pSocket->error() == QAbstractSocket::UnknownSocketError
				 || pSocket->error() == QAbstractSocket::SocketTimeoutError)
				*pError = QObject::tr("%1:%2 did not answer within %3 seconds. Either nothing is listening on that port, or a firewall is discarding the connection rather than refusing it.")
					.arg(Host).arg(Port).arg((TimeoutMs + 999) / 1000);
			//
			// And where the socket does have something to say, it is said about
			// the address that was tried rather than on its own.
			//
			else
				*pError = QObject::tr("Could not reach %1:%2: %3")
					.arg(Host).arg(Port).arg(pSocket->errorString());
		}
		delete pSocket;
		return nullptr;
	}

	CIPCSocket* pIpc = new CIPCSocket(pSocket);

	//
	// There is no kernel to ask across a network, so what this peer *is* comes
	// from the key it just proved it had. The client fills in its own side for
	// symmetry; only the server side of this matters.
	//
	SPeer Peer;
	Peer.Known = true;
	Peer.Account = QString::fromUtf8(Identity);
	pIpc->SetPeer(Peer);
	return pIpc;
}

bool CIPCSocket::IsConnected() const
{
	if (QLocalSocket* pLocal = qobject_cast<QLocalSocket*>(m_pSocket))
		return pLocal->state() == QLocalSocket::ConnectedState;
	if (QAbstractSocket* pNet = qobject_cast<QAbstractSocket*>(m_pSocket))
		return pNet->state() == QAbstractSocket::ConnectedState;
	return false;
}

void CIPCSocket::Disconnect()
{
	if (QLocalSocket* pLocal = qobject_cast<QLocalSocket*>(m_pSocket))
		pLocal->disconnectFromServer();
	else if (QAbstractSocket* pNet = qobject_cast<QAbstractSocket*>(m_pSocket))
		pNet->disconnectFromHost();
}

//
// Who is on the other end, asked of the kernel rather than of the peer.
//
bool CIPCSocket::QueryPeer(QIODevice* pDevice, SPeer& Peer)
{
	Peer = SPeer();

	//
	// Only a local endpoint has a kernel to ask. Across a network there is no
	// operating-system identity to be had - see NEXT.md 5.5 - and what a network
	// peer is comes from the key it completed the handshake with, which the
	// server fills in through SetPeer.
	//
	QLocalSocket* pSocket = qobject_cast<QLocalSocket*>(pDevice);
	if (!pSocket)
		return false;

#ifdef WIN32
	//
	// A QLocalSocket is a named pipe here, and its descriptor is the pipe
	// handle. GetNamedPipeClientProcessId answers for the far end when we are
	// the server; when we are the client it fails, which is correct - a client
	// has no business being told about the server this way, and it should be
	// checking the pipe's own permissions instead.
	//
	// There is no uid: identity on Windows is a SID, which goes in Account.
	//
	const HANDLE hPipe = (HANDLE)pSocket->socketDescriptor();
	if (hPipe == INVALID_HANDLE_VALUE || hPipe == NULL)
		return false;

	ULONG ProcessId = 0;
	if (!GetNamedPipeClientProcessId(hPipe, &ProcessId))
		return false;

	Peer.Pid = ProcessId;
	Peer.Known = true;
	Peer.bLocal = true;

	//
	// The account, from the client's own token.
	//
	// Deliberately *not* from the pid above. Between reading a pid and opening
	// that process the client can exit and the number be handed to something
	// else, and the something else would then be the one authorised. Nothing
	// here is asked of the peer either: impersonating the pipe client hands us
	// the token the kernel associated with the connection when it was made.
	//
	// Identification level is enough - the token is only read, never acted
	// through - and it is what a client gets by default, so this does not need
	// the client's cooperation.
	//
	// Impersonation is per thread, so the revert happens before anything else
	// can run on this one. A failure to revert would leave this thread wearing
	// somebody else's identity, which is why it is not conditional on success.
	//
	//
	// This is why the account is resolved late and not in the constructor.
	//
	// ImpersonateNamedPipeClient needs the server to have *read* from the pipe
	// first; before the client has written anything it fails with
	// ERROR_CANNOT_IMPERSONATE. GetNamedPipeClientProcessId above has no such
	// rule, which is exactly what made this hard to see: the peer came back with
	// a pid and an empty account, every caller was judged neither administrator
	// nor owner of anything, and every per-process request answered empty. It
	// failed closed, which is the safe direction and the wrong answer.
	//
	// See ResolvePeer: the pid is taken when the connection is made and this
	// half is retried once a frame has arrived.
	//
	if (!ImpersonateNamedPipeClient(hPipe))
		return true;	// pid known, account not; the caller decides what that means

	HANDLE hToken = NULL;
	const BOOL bOpened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken);
	RevertToSelf();

	if (!bOpened)
		return true;

	//
	// The SID as text, which is what an access rule compares and what a log
	// line can show. It is the same spelling CProcessInfo::GetUserKey uses, so
	// the two can be compared directly.
	//
	DWORD Size = 0;
	GetTokenInformation(hToken, TokenUser, NULL, 0, &Size);
	if (Size > 0)
	{
		QByteArray Buffer(Size, 0);
		if (GetTokenInformation(hToken, TokenUser, Buffer.data(), Size, &Size))
		{
			LPWSTR SidText = NULL;
			if (ConvertSidToStringSidW(((PTOKEN_USER)Buffer.data())->User.Sid, &SidText))
			{
				Peer.Account = QString::fromWCharArray(SidText);
				LocalFree(SidText);
			}
		}
	}

	TOKEN_ELEVATION Elevation = { 0 };
	DWORD Returned = 0;
	if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &Returned))
		Peer.Elevated = Elevation.TokenIsElevated != 0;

	//
	// Membership of the local Administrators group, asked of this token rather
	// than of the account. On a split token the group is deny-only and the
	// answer is false, which is the truthful answer to "is this caller an
	// administrator" - see the note in SPeer.
	//
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdminsSid = NULL;
	if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminsSid))
	{
		BOOL bMember = FALSE;
		if (CheckTokenMembership(hToken, AdminsSid, &bMember))
			Peer.AdminGroup = bMember != FALSE;
		FreeSid(AdminsSid);
	}

	CloseHandle(hToken);
	return true;
#else
	//
	// SO_PEERCRED is filled in by the kernel at connect time from the peer's
	// credentials as they were then. It cannot be set, spoofed or changed by
	// the process it describes, which is what makes it worth trusting.
	//
	const int Fd = (int)pSocket->socketDescriptor();
	if (Fd < 0)
		return false;

	struct ucred Cred;
	socklen_t Len = sizeof(Cred);
	if (getsockopt(Fd, SOL_SOCKET, SO_PEERCRED, &Cred, &Len) != 0)
		return false;

	Peer.Pid = (quint64)Cred.pid;
	Peer.Uid = (quint64)Cred.uid;

	//
	// The same field means the same thing on both platforms: the account, as
	// text. A uid is what CProcessInfo::GetUserKey answers with here, so the
	// two compare directly.
	//
	Peer.bLocal = true;
	Peer.Account = QString::number(Cred.uid);

	//
	// root is the whole of it on Linux: there is no second, unelevated form of
	// it the way a Windows split token has, so both answers are the same one.
	// Capabilities are finer and are not asked about here - a caller that has
	// CAP_SYS_PTRACE without being root is a case this does not yet distinguish.
	//
	Peer.Elevated = (Cred.uid == 0);
	Peer.AdminGroup = Peer.Elevated;

	Peer.Known = true;
	return true;
#endif
}

quint64 CIPCSocket::SendRequest(quint32 Command, const CVariant& Data)
{
	const quint64 Number = ++m_Counter;
	if (!Send(eRequest, Command, Data, Number))
		return 0;
	return Number;
}

bool CIPCSocket::SendResponse(quint32 Command, const CVariant& Data, quint64 Number)
{
	return Send(eResponse, Command, Data, Number);
}

quint64 CIPCSocket::SendEvent(quint32 Command, const CVariant& Data)
{
	const quint64 Number = ++m_Counter;
	if (!Send(eEvent, Command, Data, Number))
		return 0;
	return Number;
}

bool CIPCSocket::Send(quint8 Type, quint32 Command, const CVariant& Data, quint64 Number)
{
	if (!IsConnected())
		return false;

	//
	// BeginIMap, not BeginMap: an index keyed by uint32 rather than a
	// dictionary keyed by name. Four bytes per field instead of a string and
	// its length, on every message.
	//
	CVariant Message;
	Message.BeginIMap();
	Message.Write(eFieldType, Type);
	Message.Write(eFieldNumber, Number);
	Message.Write(eFieldCommand, Command);
	if (Data.IsValid())
		Message.WriteVariant(eFieldData, Data);
	Message.Finish();

	CBuffer Packet;
	Message.ToPacket(&Packet);

	if ((quint32)Packet.GetSize() > m_MaxFrameSize)
		return false;	// our own doing, not the peer's - refuse rather than send something unreadable

	const quint32 Length = (quint32)Packet.GetSize();

	QByteArray Frame;
	Frame.append((const char*)&Length, c_LengthSize);
	Frame.append((const char*)Packet.GetBuffer(), (int)Packet.GetSize());

	return m_pSocket->write(Frame) == Frame.size();
}

void CIPCSocket::OnReadyRead()
{
	m_ReadBuffer.append(m_pSocket->readAll());

	//
	// Now that something has arrived, the rest of the peer can be asked for -
	// on Windows the account could not be had before this point. Once per
	// connection; see ResolvePeer.
	//
	ResolvePeer();

	for (;;)
	{
		if ((quint32)m_ReadBuffer.size() < c_LengthSize)
			break;	// not even a length yet

		quint32 Length = 0;
		memcpy(&Length, m_ReadBuffer.constData(), c_LengthSize);

		//
		// The peer chooses this number, so it is checked before it is used for
		// anything. Without the cap a single frame header could ask this
		// process - which may be running as a service - to wait for and buffer
		// an arbitrary amount.
		//
		if (Length > m_MaxFrameSize)
		{
			Fail(QString("frame of %1 bytes exceeds the limit").arg(Length));
			return;
		}

		if ((quint32)m_ReadBuffer.size() < c_LengthSize + Length)
			break;	// the body has not all arrived

		quint8 Type = 0;
		quint64 Number = 0;
		quint32 Command = 0;
		CVariant Data;

		try
		{
			//
			// FromPacket raises rather than returning a code when the bytes do
			// not parse, and these bytes came from outside this process, so the
			// catch is not decoration.
			//
			CBuffer Packet((void*)(m_ReadBuffer.constData() + c_LengthSize), Length, true);

			CVariant Message;
			Message.FromPacket(&Packet);

			Type = Message.Find(eFieldType).To<quint8>();
			Number = Message.Find(eFieldNumber).To<quint64>();
			Command = Message.Find(eFieldCommand).To<quint32>();

			//
			// The payload is copied out, not referenced.
			//
			// CVariant::Find hands back a *derived* variant - one whose payload
			// points into its parent's bytes - and the parent here is a local
			// that dies when this function returns. A handler that keeps what it
			// was given, which is the obvious thing to do with an answer, would
			// be reading freed memory by the time it looked.
			//
			// A round trip through the packet format is the deep copy: there is
			// no other way to ask a CVariant to own its bytes. It costs a
			// serialise and a parse of the payload per message, which is worth
			// paying for an API that cannot be misused this way.
			//
			// The payload itself is not decoded - this class does not know what
			// any command means - so whatever built it on the far side is what
			// the handler reads.
			//
			CVariant Payload = Message.Find(eFieldData);
			if (Payload.IsValid())
			{
				CBuffer Copy;
				Payload.ToPacket(&Copy);
				Copy.SetPosition(0);
				Data.FromPacket(&Copy);
			}
		}
		catch (...)
		{
			//
			// The framing is out of step at this point and nothing further on
			// this connection can be trusted, so it goes rather than being
			// resynchronised.
			//
			Fail("malformed message");
			return;
		}

		m_LastFrameSize = c_LengthSize + Length;
		m_TotalReceived += m_LastFrameSize;

		m_ReadBuffer.remove(0, c_LengthSize + Length);

		switch (Type)
		{
		case eRequest:	emit Request(Command, Data, Number); break;
		case eResponse:	emit Response(Command, Data, Number); break;
		case eEvent:	emit Event(Command, Data, Number); break;
		default:
			Fail(QString("unknown message type %1").arg(Type));
			return;
		}
	}
}

void CIPCSocket::Fail(const QString& Reason)
{
	qWarning("CIPCSocket: dropping connection: %s", qPrintable(Reason));
	m_ReadBuffer.clear();
	if (m_pSocket)
		//
		// Hard close: the framing is out of step and nothing further on this
		// connection can be trusted, so it is dropped rather than shut down
		// politely.
		//
		if (QLocalSocket* pLocal = qobject_cast<QLocalSocket*>(m_pSocket))
			pLocal->abort();
		else if (QAbstractSocket* pNet = qobject_cast<QAbstractSocket*>(m_pSocket))
			pNet->abort();
	emit Disconnected();
}

void CIPCSocket::OnDisconnected()
{
	emit Disconnected();
}
