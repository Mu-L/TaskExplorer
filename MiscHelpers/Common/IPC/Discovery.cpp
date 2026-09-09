#include "stdafx.h"
#include "Discovery.h"

#include <QUdpSocket>
#include <QNetworkInterface>
#include <QNetworkDatagram>
#include <QTimer>

//
// The wire, such as it is.
//
//   "TEDS" | version | type | payload
//
// Four bytes of magic and a version before anything else, because this listens
// on a multicast group that anything may send to. Without them every stray
// datagram on the port would be handed up as a machine.
//
#define DISCO_MAGIC		"TEDS"
#define DISCO_VERSION	1

#define DISCO_QUERY		1
#define DISCO_ANNOUNCE	2

//
// Small on purpose. An announcement carries a name, an id and a port; anything
// that does not fit in this does not belong in a packet shouted at a network
// segment.
//
#define DISCO_MAX		2048

static QByteArray MakeDatagram(quint8 Type, const QByteArray& Payload)
{
	QByteArray Datagram(DISCO_MAGIC, 4);
	Datagram.append((char)DISCO_VERSION);
	Datagram.append((char)Type);
	Datagram.append(Payload);
	return Datagram;
}

static bool ParseDatagram(const QByteArray& Datagram, quint8* pType, QByteArray* pPayload)
{
	if (Datagram.size() < 6 || Datagram.size() > DISCO_MAX)
		return false;
	if (memcmp(Datagram.constData(), DISCO_MAGIC, 4) != 0)
		return false;
	if ((quint8)Datagram[4] != DISCO_VERSION)
		return false;

	*pType = (quint8)Datagram[5];
	*pPayload = Datagram.mid(6);
	return true;
}

CDiscovery::CDiscovery(QObject* parent)
	: QObject(parent)
{
	m_GroupV4 = DefaultGroupV4();
	m_GroupV6 = DefaultGroupV6();
}

CDiscovery::~CDiscovery()
{
	StopAnnouncing();
	StopLookup();
}

void CDiscovery::SetGroups(const QString& V4, const QString& V6)
{
	if (!V4.isEmpty())
		m_GroupV4 = V4;
	if (!V6.isEmpty())
		m_GroupV6 = V6;
}

void CDiscovery::SetPayload(const QByteArray& Payload)
{
	m_Payload = Payload;
}

bool CDiscovery::IsAnnouncing() const	{ return m_Announce.IsOpen(); }
bool CDiscovery::IsLookingUp() const	{ return m_Lookup.IsOpen(); }

//
// A socket bound to one family's Any, joined to that family's group on every
// interface that will have it.
//
// Per interface, explicitly, rather than letting the stack pick one: the default
// is whichever interface the routing table prefers, which on a machine with a
// VPN or a hypervisor bridge is regularly not the one the other machines are on.
//
// ShareAddress is not optional - a viewer and a server on the same machine both
// want this port, and on a developer's machine that is the normal case.
//
static QUdpSocket* OpenOne(QObject* pParent, const QHostAddress& Any, const QHostAddress& Group,
                           quint16 Port, QString* pError)
{
	if (Group.isNull())
		return nullptr;

	QUdpSocket* pSocket = new QUdpSocket(pParent);
	if (!pSocket->bind(Any, Port, QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint))
	{
		if (pError)
			*pError = pSocket->errorString();
		delete pSocket;
		return nullptr;
	}

	int Joined = 0;
	foreach(const QNetworkInterface& Interface, QNetworkInterface::allInterfaces())
	{
		if (!(Interface.flags() & QNetworkInterface::IsUp)
			|| !(Interface.flags() & QNetworkInterface::CanMulticast))
			continue;

		if (pSocket->joinMulticastGroup(Group, Interface))
			Joined++;
	}

	if (Joined == 0)
	{
		//
		// Bound but deaf. Nothing would ever arrive, and keeping it would make
		// IsOpen() say yes to something that cannot work.
		//
		if (pError)
			*pError = QString("no interface would join %1").arg(Group.toString());
		delete pSocket;
		return nullptr;
	}

	//
	// Loopback on, deliberately: a viewer and a server on one machine is how
	// this gets tested, and how a single-machine user gets a filled-in list.
	//
	pSocket->setSocketOption(QAbstractSocket::MulticastLoopbackOption, 1);

	//
	// One hop. These groups are link-local by design and the TTL is the second
	// lock on that - a misconfigured router cannot carry the packet further than
	// the segment it was meant for.
	//
	pSocket->setSocketOption(QAbstractSocket::MulticastTtlOption, 1);

	return pSocket;
}

bool CDiscovery::OpenEndpoint(SEndpoint* pEndpoint, quint16 Port, const char* pSlot, QString* pError)
{
	QString ErrorV4, ErrorV6;

	pEndpoint->pV4 = OpenOne(this, QHostAddress::AnyIPv4, QHostAddress(m_GroupV4), Port, &ErrorV4);
	pEndpoint->pV6 = OpenOne(this, QHostAddress::AnyIPv6, QHostAddress(m_GroupV6), Port, &ErrorV6);
	pEndpoint->Port = Port;

	//
	// One family is enough. A v6-only network has no v4 group to join and a
	// machine with IPv6 switched off cannot bind AnyIPv6 at all; neither is worth
	// refusing to run over.
	//
	if (!pEndpoint->IsOpen())
	{
		if (pError)
			*pError = QString("IPv4: %1; IPv6: %2").arg(ErrorV4).arg(ErrorV6);
		return false;
	}

	if (pEndpoint->pV4)
		connect(pEndpoint->pV4, SIGNAL(readyRead()), this, pSlot);
	if (pEndpoint->pV6)
		connect(pEndpoint->pV6, SIGNAL(readyRead()), this, pSlot);

	return true;
}

void CDiscovery::CloseEndpoint(SEndpoint* pEndpoint)
{
	delete pEndpoint->pV4;
	delete pEndpoint->pV6;
	pEndpoint->pV4 = nullptr;
	pEndpoint->pV6 = nullptr;
	pEndpoint->Port = 0;
}

void CDiscovery::SendTo(const SEndpoint& Endpoint, const QByteArray& Datagram)
{
	if (Endpoint.pV4)
		Endpoint.pV4->writeDatagram(Datagram, QHostAddress(m_GroupV4), Endpoint.Port);

	//
	// Once per interface for v6, which has no default route for multicast the way
	// v4 does - a datagram with no interface named goes nowhere useful.
	//
	if (Endpoint.pV6)
	{
		foreach(const QNetworkInterface& Interface, QNetworkInterface::allInterfaces())
		{
			if (!(Interface.flags() & QNetworkInterface::IsUp)
				|| !(Interface.flags() & QNetworkInterface::CanMulticast))
				continue;

			Endpoint.pV6->setMulticastInterface(Interface);
			Endpoint.pV6->writeDatagram(Datagram, QHostAddress(m_GroupV6), Endpoint.Port);
		}
		Endpoint.pV6->setMulticastInterface(QNetworkInterface());
	}
}

bool CDiscovery::StartAnnouncing(quint16 Port, int IntervalMs, QString* pError)
{
	StopAnnouncing();

	if (!OpenEndpoint(&m_Announce, Port, SLOT(OnAnnounceDatagram()), pError))
		return false;

	if (IntervalMs > 0)
	{
		m_pBeaconTimer = new QTimer(this);
		connect(m_pBeaconTimer, SIGNAL(timeout()), this, SLOT(OnBeacon()));
		m_pBeaconTimer->start(IntervalMs);

		//
		// One straight away, so a server that has just started is visible to a
		// viewer already listening rather than after a full interval.
		//
		OnBeacon();
	}

	return true;
}

void CDiscovery::StopAnnouncing()
{
	delete m_pBeaconTimer;
	m_pBeaconTimer = nullptr;
	CloseEndpoint(&m_Announce);
}

bool CDiscovery::StartLookup(quint16 Port, int IntervalMs, QString* pError)
{
	StopLookup();

	//
	// The looking side joins the groups too, because announcements are sent to
	// them - a socket that only ever sent would never hear a beacon, only the
	// unicast answers to its own questions.
	//
	if (!OpenEndpoint(&m_Lookup, Port, SLOT(OnLookupDatagram()), pError))
		return false;

	if (IntervalMs > 0)
	{
		m_pQueryTimer = new QTimer(this);
		connect(m_pQueryTimer, SIGNAL(timeout()), this, SLOT(Query()));
		m_pQueryTimer->start(IntervalMs);
	}

	Query();
	return true;
}

void CDiscovery::StopLookup()
{
	delete m_pQueryTimer;
	m_pQueryTimer = nullptr;
	CloseEndpoint(&m_Lookup);
}

void CDiscovery::Query()
{
	SendTo(m_Lookup, MakeDatagram(DISCO_QUERY, QByteArray()));
}

void CDiscovery::OnBeacon()
{
	SendTo(m_Announce, MakeDatagram(DISCO_ANNOUNCE, m_Payload));
}

void CDiscovery::ReadFrom(QUdpSocket* pSocket, bool bAnswerQueries)
{
	while (pSocket && pSocket->hasPendingDatagrams())
	{
		const QNetworkDatagram Datagram = pSocket->receiveDatagram(DISCO_MAX);

		quint8 Type = 0;
		QByteArray Payload;
		if (!ParseDatagram(Datagram.data(), &Type, &Payload))
			continue;

		if (Type == DISCO_QUERY && bAnswerQueries)
		{
			//
			// Answered straight back to whoever asked, not to the group.
			//
			// One reply to one question, rather than a burst at everybody on the
			// segment every time any viewer opens a dialog. It also reaches a
			// viewer whose own multicast reception is not working, which happens
			// more often than it should.
			//
			pSocket->writeDatagram(MakeDatagram(DISCO_ANNOUNCE, m_Payload),
				Datagram.senderAddress(), Datagram.senderPort());
			continue;
		}

		if (Type == DISCO_ANNOUNCE && !bAnswerQueries)
			emit Found(Datagram.senderAddress(), Payload);
	}
}

void CDiscovery::OnAnnounceDatagram()
{
	ReadFrom(qobject_cast<QUdpSocket*>(sender()), true);
}

void CDiscovery::OnLookupDatagram()
{
	ReadFrom(qobject_cast<QUdpSocket*>(sender()), false);
}
