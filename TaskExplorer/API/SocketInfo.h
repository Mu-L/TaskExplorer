#pragma once
#include <qobject.h>
#include "../../MiscHelpers/Common/Common.h"
#include "../../MiscHelpers/Common/Status.h"
#include "AbstractInfo.h"
#include "MiscStats.h"

#define NET_TYPE_NETWORK_IPV4		0x1
#define NET_TYPE_NETWORK_IPV6		0x2
//
// A socket in the machine's own namespace rather than on a network - a unix
// domain socket on Linux. It carries a path instead of an address and a port,
// and most of a Linux process's sockets are of this kind: the connection to
// wineserver, the X display, the journal, the D-Bus bus.
//
// Off by default in the views. The Sockets tab is a network view, as it is on
// Windows, and a machine has hundreds of these; a person who wants them says
// so - see Options/ShowUnixSockets.
//
#define NET_TYPE_NETWORK_UNIX		0x4
#define NET_TYPE_NETWORK_MASK		0x7

//
// TCP connection states, by the MIB numbering. Declared here rather than in the
// .cpp because the reading of them now happens in the viewer.
//
enum ETcpState
{
	eTcpClosed		=  1,
	eTcpListen		=  2,
	eTcpSynSent		=  3,
	eTcpSynRcvd		=  4,
	eTcpEstablished	=  5,
	eTcpFinWait1	=  6,
	eTcpFinWait2	=  7,
	eTcpCloseWait	=  8,
	eTcpClosing		=  9,
	eTcpLastAck		= 10,
	eTcpTimeWait	= 11,
	eTcpDeleteTcb	= 12,
	eTcpBlocked		= -1,		// this application's own marker, not a MIB state
};

#define NET_TYPE_PROTOCOL_TCP		0x10
#define NET_TYPE_PROTOCOL_UDP		0x20
#define NET_TYPE_PROTOCOL_MASK		0x30
#define NET_TYPE_PROTOCOL_TCP_SRV	0x40
#define NET_TYPE_PROTOCOL_OTHER		0x80

#define NET_TYPE_NONE 0x0
#define NET_TYPE_IPV4_TCP (NET_TYPE_NETWORK_IPV4 | NET_TYPE_PROTOCOL_TCP)
#define NET_TYPE_IPV6_TCP (NET_TYPE_NETWORK_IPV6 | NET_TYPE_PROTOCOL_TCP)
#define NET_TYPE_IPV4_UDP (NET_TYPE_NETWORK_IPV4 | NET_TYPE_PROTOCOL_UDP)
#define NET_TYPE_IPV6_UDP (NET_TYPE_NETWORK_IPV6 | NET_TYPE_PROTOCOL_UDP)

//
// The three kinds of unix socket, spelled with the protocol bits they behave
// like: a stream socket is connection oriented as TCP is, a datagram socket is
// not as UDP is not. Their states are their own - see EUnixSocketState.
//
#define NET_TYPE_UNIX_STREAM	(NET_TYPE_NETWORK_UNIX | NET_TYPE_PROTOCOL_TCP)
#define NET_TYPE_UNIX_DGRAM		(NET_TYPE_NETWORK_UNIX | NET_TYPE_PROTOCOL_UDP)
#define NET_TYPE_UNIX_SEQPACKET	(NET_TYPE_NETWORK_UNIX | NET_TYPE_PROTOCOL_OTHER)

//
// What a unix socket's state field holds. The first four are the kernel's own
// numbering; the last is this application's, because the kernel reports
// listening as a flag beside the state rather than as one of its values.
//
enum EUnixSocketState
{
	eUnixUnconnected	= 1,
	eUnixConnecting		= 2,
	eUnixConnected		= 3,
	eUnixDisconnecting	= 4,
	eUnixListen			= 5,
};

class TASKCORE_EXPORT CSocketInfo: public CAbstractInfoEx
{
	Q_OBJECT

	TRACK_OBJECT(CSocketInfo)
public:
	CSocketInfo(QObject *parent = nullptr);
	virtual ~CSocketInfo();

	virtual quint64				GetHashID() const			{ QReadLocker Locker(&m_Mutex); return m_HashID; }

	virtual quint32				GetProtocolType() const		{ QReadLocker Locker(&m_Mutex); return m_ProtocolType; }

	//
	// What the two ends are called, where they are named by something other
	// than an address and a port.
	//
	// A unix socket is bound to a filesystem path, or to an abstract name, or
	// to nothing at all - an anonymous pair is the ordinary case for a client,
	// and there the peer's name is the only thing worth reading. Empty on a
	// protocol with no such notion, which is what the address columns fall back
	// on.
	//
	virtual QString				GetLocalName() const		{ QReadLocker Locker(&m_Mutex); return m_LocalName; }
	virtual QString				GetRemoteName() const		{ QReadLocker Locker(&m_Mutex); return m_RemoteName; }

	//
	// And who is at the other end, where the socket has no name to give.
	//
	// Both ends of a connected unix pair are usually anonymous - only the
	// listening socket carries the path - so the one thing worth knowing about
	// such a socket is which program it is talking to. Zero when the peer is not
	// held by anything this machine can see. The name is looked up from the pid
	// where it is shown; what travels is the number.
	//
	virtual quint64				GetRemoteProcessId() const	{ QReadLocker Locker(&m_Mutex); return m_RemoteProcessId; }
	virtual QHostAddress		GetLocalAddress() const		{ QReadLocker Locker(&m_Mutex); return m_LocalAddress; }
	virtual quint16				GetLocalPort() const		{ QReadLocker Locker(&m_Mutex); return m_LocalPort; }
	virtual QHostAddress		GetRemoteAddress() const	{ QReadLocker Locker(&m_Mutex); return m_RemoteAddress; }
	virtual quint16				GetRemotePort() const		{ QReadLocker Locker(&m_Mutex); return m_RemotePort; }
	virtual quint32				GetState() const			{ QReadLocker Locker(&m_Mutex); return m_State; }
	virtual void				SetClosed();
	virtual void				SetBlocked()				{ QWriteLocker Locker(&m_Mutex); m_State = -1; }
	virtual bool				WasBlocked() const			{ QReadLocker Locker(&m_Mutex); return m_State == -1; }
	virtual quint64				GetProcessId() const		{ QReadLocker Locker(&m_Mutex); return m_ProcessId; }

	virtual QString				GetRemoteHostName() const	{ QReadLocker Locker(&m_Mutex); return m_RemoteHostName; }

	virtual QString				GetProcessName() const		{ QReadLocker Locker(&m_Mutex); return m_ProcessName; }
	virtual QWeakPointer<QObject> GetProcess() const		{ QReadLocker Locker(&m_Mutex); return m_pProcess; }
	
	virtual SSockStats			GetStats() const			{ QReadLocker Locker(&m_StatsMutex); return m_Stats; }

	enum EMatchMode
	{
		eFuzzy = 0,
		eStrict,
	};

	virtual bool				Match(quint64 ProcessId, quint32 ProtocolType, const QHostAddress& LocalAddress, quint16 LocalPort, const QHostAddress& RemoteAddress, quint16 RemotePort, EMatchMode Mode);

	static quint64				MkHash(quint64 ProcessId, quint32 ProtocolType, const QHostAddress& LocalAddress, quint16 LocalPort, const QHostAddress& RemoteAddress, quint16 RemotePort);

	virtual STATUS				Close() = 0;

	virtual void				UpdateStats();

	//
	// ---- platform surface ----
	//
	// Everything either platform can report, so the models never need to know
	// which one answered. An implementation without the notion does not
	// override; the default below is the honest answer, and whether a column
	// built on it is worth showing is decided by GetOsType()/HasCapability().
	//
	// Whether the firewall is letting this endpoint through, where one reports.
	//
	// What the platform firewall decided about a connection. "Restricted" means
	// it was let through under a narrower rule than the program asked for.
	//
	enum EFirewallStatus
	{
		eFirewallUnknown				= 0,
		eFirewallAllowedNotRestricted	= 1,
		eFirewallAllowedRestricted		= 2,
		eFirewallNotAllowedNotRestricted= 3,
		eFirewallNotAllowedRestricted	= 4,
	};
	virtual int     GetFirewallStatus()				{ return eFirewallUnknown; }

	virtual QString GetOwnerServiceName()			{ return QString(); }

protected:
	quint64						m_HashID;

	quint32						m_ProtocolType;
	QString						m_LocalName;
	QString						m_RemoteName;
	quint64						m_RemoteProcessId = 0;
	QHostAddress				m_LocalAddress;
	quint16						m_LocalPort;
	QHostAddress				m_RemoteAddress;
	quint16						m_RemotePort;
	quint32						m_State;
	quint64						m_ProcessId;

	QString						m_ProcessName;
	QWeakPointer<QObject>		m_pProcess;

	QString						m_RemoteHostName;

	// I/O stats
	mutable QReadWriteLock		m_StatsMutex;
	SSockStats					m_Stats;
};

typedef QSharedPointer<CSocketInfo> CSocketPtr;
typedef QWeakPointer<CSocketInfo> CSocketRef;