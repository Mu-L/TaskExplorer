#pragma once
#include "../../corehelpers_global.h"

#include <QObject>
#include <QHostAddress>
#include <QByteArray>

class QUdpSocket;
class QTimer;

//
// Finding machines on the local network, and being found.
//
// ---- two halves, separately switched ----
//
// Announcing and looking are independent, and neither implies the other. A
// build box should be findable without watching for anything itself; a viewer
// should be able to look without telling the network it exists. Anything that
// tied them together would force one of those to be wrong.
//
// ---- why multicast rather than broadcast ----
//
// Broadcast is IPv4-only, and IPv6 has no such thing at all - a design that
// started with broadcast would have to be replaced rather than extended the
// first time somebody ran this on a v6-only network. Multicast is the mechanism
// both families share.
//
// ---- and why two sockets rather than one ----
//
// A dual-stack socket bound to AnyIPv6 receives both families and looks like the
// tidy answer. It is not: Qt refuses outright to join an IPv4 multicast group on
// a socket bound to AnyIPv6 or Any -
//
//     cannot bind to QHostAddress::Any (or an IPv6 address) and join an
//     IPv4 multicast group; bind to QHostAddress::AnyIPv4 instead
//
// - so the tidy version silently worked over IPv6 only, which is exactly the
// half nobody would have noticed missing. One socket per family, each bound to
// its own Any, each joining its own group.
//
// Either may fail to open and that is not an error: a v6-only network has no v4
// group to join and a v4-only machine cannot bind AnyIPv6. Only both failing is
// a failure.
//
// Default scope is link-local on both - 239.255 is IPv4's administratively
// scoped block and routers do not forward it by default; ff02:: is IPv6's
// link-local scope and routers must not forward it at all. "The machines on my
// network segment" is the question being asked, and a discovery packet loose on
// somebody's WAN is not an improvement.
//
// ---- what an announcement may say ----
//
// This class carries an opaque payload and has no opinion about it, which is
// what keeps it in CoreHelpers with no dependency on the protocol. The caller
// decides - and the rule it has to keep is that an announcement is shouted at
// everything on the segment, so it may carry only what is needed to *find* a
// machine. Everything else stays behind the handshake, where there is a key.
//
class COREHELPERS_EXPORT CDiscovery : public QObject
{
	Q_OBJECT

public:
	CDiscovery(QObject* parent = nullptr);
	virtual ~CDiscovery();

	static QString		DefaultGroupV4()			{ return "239.255.42.99"; }
	static QString		DefaultGroupV6()			{ return "ff02::4299"; }
	static quint16		DefaultPort()				{ return 28334; }

	//
	// The groups, if the defaults do not suit. Must be set before either half is
	// started; changing them afterwards does nothing until it is stopped and
	// started again.
	//
	void				SetGroups(const QString& V4, const QString& V6);

	//
	// ---- being found ----
	//
	// Answers queries, and beacons every IntervalMs if that is not zero.
	//
	// Answering is the part that matters and is always on while this is running;
	// the beacon is for viewers that were not listening when they asked, and for
	// keeping a list fresh without re-asking. Zero means answer only, which is
	// the quieter default.
	//
	bool				StartAnnouncing(quint16 Port, int IntervalMs, QString* pError = nullptr);
	void				StopAnnouncing();
	bool				IsAnnouncing() const;

	//
	// What to say when asked. May be changed at any time - a server whose port
	// changed should not have to stop announcing to say so.
	//
	void				SetPayload(const QByteArray& Payload);

	//
	// ---- looking ----
	//
	bool				StartLookup(quint16 Port, int IntervalMs, QString* pError = nullptr);
	void				StopLookup();
	bool				IsLookingUp() const;

public slots:
	//
	// Asks now, without waiting for the interval. What the connect dialog calls
	// when it opens - somebody who has just gone looking should not wait out a
	// timer to see anything.
	//
	void				Query();

signals:
	//
	// Something answered. The address is where it answered *from*, which is not
	// necessarily anything the payload says: a machine cannot always know which
	// of its own addresses is the one a given viewer can reach, and the source
	// address is the one that demonstrably works.
	//
	void				Found(const QHostAddress& From, const QByteArray& Payload);

private slots:
	void				OnAnnounceDatagram();
	void				OnLookupDatagram();
	void				OnBeacon();

private:
	//
	// One socket per family, opened and closed together.
	//
	struct SEndpoint
	{
		QUdpSocket*	pV4 = nullptr;
		QUdpSocket*	pV6 = nullptr;
		quint16		Port = 0;

		bool IsOpen() const { return pV4 || pV6; }
	};

	bool				OpenEndpoint(SEndpoint* pEndpoint, quint16 Port, const char* pSlot, QString* pError);
	void				CloseEndpoint(SEndpoint* pEndpoint);
	void				SendTo(const SEndpoint& Endpoint, const QByteArray& Datagram);
	void				ReadFrom(QUdpSocket* pSocket, bool bAnswerQueries);

	SEndpoint			m_Announce;
	SEndpoint			m_Lookup;

	QTimer*				m_pBeaconTimer = nullptr;
	QTimer*				m_pQueryTimer = nullptr;

	QString				m_GroupV4;
	QString				m_GroupV6;
	QByteArray			m_Payload;
};
