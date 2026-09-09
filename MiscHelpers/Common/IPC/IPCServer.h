#pragma once
#include <functional>

#include "../../corehelpers_global.h"

#include <QObject>
#include <QList>
#include <QString>

class QLocalServer;
class CIPCSocket;

//
// Accepts local connections: a named pipe on Windows, a unix socket on Linux.
//
// The security of this is not in the messages, it is in two things that happen
// before any message is read:
//
//  1. **Who may open the endpoint at all.** QLocalServer::UserAccessOption
//     builds a Windows security descriptor granting only the account that
//     created the pipe, and chmods the unix socket to 0600. That is the control
//     that matters, and it is applied by default here rather than left to a
//     caller to remember.
//
//  2. **Who actually did.** Every accepted connection carries the peer's
//     process id, and on unix its uid, taken from the kernel - see
//     CIPCSocket::SPeer. SetAllowedUid() turns that into a rule.
//
// Nothing here trusts anything a client says about itself, because at this
// point a client has not said anything yet.
//
// ---- what the name check is and is not ----
//
// Listen() probes for an existing server before binding, and refuses if one
// answers. That catches an accidental second instance and makes a conflict
// visible; it is **not** a defence against a deliberate squatter, who would
// simply not probe. There is also a window between the probe and the bind.
//
// What actually keeps another *user* out is the endpoint's own permissions: the
// unix socket is 0600 in a sticky /tmp, where only its owner may unlink it, and
// the Windows pipe carries a descriptor naming only the creating account. A
// process of the *same* user can still take a name on either platform - Windows
// has FILE_FLAG_FIRST_PIPE_INSTANCE for exactly this and QLocalServer does not
// expose it - and that is precisely the case the privileged-server note below
// is about. Same-user is inside the local trust boundary as long as the server
// is not more privileged than its clients.
//
// ---- a case this does not yet handle ----
//
// A server running as SYSTEM or root, serving an ordinary user's viewer, cannot
// use UserAccessOption: it would grant only SYSTEM and the user could not
// connect. That deployment needs an explicit descriptor naming the intended
// user, and it is the deployment TaskServer will eventually want. Deliberately
// not guessed at here - it is a decision about who may command a privileged
// process, and it should be made once, visibly, rather than implied by a
// default. SetOpenAccess() exists so that case is written down when it arrives
// rather than being reached by quietly widening this one.
//
class COREHELPERS_EXPORT CIPCServer : public QObject
{
	Q_OBJECT

public:
	CIPCServer(QObject* parent = nullptr);
	virtual ~CIPCServer();

	//
	// Starts listening.
	//
	// Refuses if something is already serving this name - which QLocalServer
	// itself will not do. That was measured rather than assumed: with a live
	// server holding a name, a second listen() succeeds on both platforms. On
	// Linux the later server then receives every connection and the first sees
	// nothing; on Windows the pipe merely gains another instance and a client
	// takes whichever is free.
	//
	bool				Listen(const QString& Name, QString* pError = nullptr);
	void				Close();
	bool				IsListening() const;
	QString				GetName() const;

	//
	// Refuse any peer whose uid is not this one. Has no effect on Windows,
	// where identity is a SID and the endpoint's own permissions carry the
	// weight; call it anyway, so the rule is stated in one place for both.
	//
	// (quint64)-1, the default, means no uid rule.
	//
	void				SetAllowedUid(quint64 Uid)		{ m_AllowedUid = Uid; }

	//
	// Drops the "only this account" restriction on the endpoint itself. Only
	// for the privileged-server case described above, and it must be paired
	// with something else that decides who may connect - on its own it means
	// anyone on the machine can.
	//
	void				SetOpenAccess(bool bOpen)		{ m_bOpenAccess = bOpen; }

	//
	// Also listen for network connections, with TLS-PSK and no certificates.
	//
	// A separate call rather than another address form of Listen, because the
	// two are not alternatives: a daemon commonly serves its own machine over
	// the local endpoint *and* the network at the same time, and only the
	// network one needs keys.
	//
	// Resolve is asked for the key belonging to an identity the client offered.
	// Returning an empty QByteArray fails the handshake, which is the only
	// answer a client ever gets - there is deliberately no way to tell "no such
	// identity" from "wrong key" from the outside.
	//
	// It is called on the socket thread during the handshake, so it must not
	// block; a lookup in a map read at start-up is what it is for.
	//
	typedef std::function<QByteArray(const QByteArray& Identity)> FResolveKey;

	//
	// Bind names which of the machine’s addresses to accept on; empty means all
	// of them. A machine with one interface facing something it does not trust
	// wants the other thing, and saying so here is one place rather than a
	// firewall rule on every such machine.
	//
	// An address the machine does not have is refused rather than quietly
	// widened to all - the two differ by exactly the thing the caller was
	// asking for.
	//
	bool				ListenTcp(quint16 Port, const FResolveKey& Resolve, QString* pError = nullptr,
								  const QString& Bind = QString());

	//
	// How many handshakes may fail before an address, or everybody, is made to
	// wait.
	//
	// Per address stops one host grinding keys; the global one stops a spread
	// of them doing it between them. Neither touches the residual risk that was
	// accepted: an active attacker who lures a client and grinds the resulting
	// transcript offline is not making handshakes here at all - which is what
	// the forward-secret cipher pinning is for.
	//
	void				SetHandshakeLimits(int PerAddress, int Global, int WindowMs)
							{ m_MaxPerAddress = PerAddress; m_MaxGlobal = Global; m_LimitWindowMs = WindowMs; }


	//
	// Whether the network listener is actually up. Asked by anything that would
	// otherwise advertise a port nobody is serving.
	//
	bool				IsListeningTcp() const			{ return m_pTlsServer != nullptr; }

	QList<CIPCSocket*>	GetConnections() const			{ return m_Connections; }

signals:
	void				NewConnection(CIPCSocket* pSocket);

private slots:
	void				OnNewConnection();
	void				OnDisconnected();

protected:
	QLocalServer*		m_pServer;
	class CTlsServer*	m_pTlsServer = nullptr;
	QList<CIPCSocket*>	m_Connections;
	quint64				m_AllowedUid;
	bool				m_bOpenAccess;

	//
	// Failed handshakes, by address and in total, with the time of each. Kept as
	// times rather than a count so that the window slides instead of needing to
	// be reset by something.
	//
	int					m_MaxPerAddress = 10;
	int					m_MaxGlobal = 60;
	int					m_LimitWindowMs = 60 * 1000;
	QMap<QString, QList<quint64> > m_Failures;
	QList<quint64>		m_AllFailures;

public:
	//
	// Called by the TLS listener. Public because the helper that runs the
	// handshake is a separate class; not part of the interface anybody else
	// should use.
	//
	bool				IsRateLimited(const QString& Address);
	void				NoteHandshakeFailure(const QString& Address);
	void				AdoptConnection(CIPCSocket* pSocket);
	FResolveKey			m_Resolve;
};
