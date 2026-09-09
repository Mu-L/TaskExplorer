#include "stdafx.h"
#include "SocketInfo.h"

CSocketInfo::CSocketInfo(QObject *parent) : CAbstractInfoEx(parent)
{
	m_HashID = -1;

	m_ProtocolType = 0;;
	m_LocalPort = 0;
	m_RemotePort = 0;
	m_State = 0;
	m_ProcessId = -1;
}

CSocketInfo::~CSocketInfo()
{
}

bool CSocketInfo::Match(quint64 ProcessId, quint32 ProtocolType, const QHostAddress& LocalAddress, quint16 LocalPort, const QHostAddress& RemoteAddress, quint16 RemotePort, EMatchMode Mode)
{
	QReadLocker Locker(&m_Mutex); 

#ifdef _DEBUG
	QString m_LocalAddressStr = m_LocalAddress.toString();
	QString m_RemoteAddressStr = m_RemoteAddress.toString();
	QString LocalAddressStr = LocalAddress.toString();
	QString RemoteAddressStr = RemoteAddress.toString();
#endif

	if (m_ProcessId != ProcessId)
		return false;

	if (m_ProtocolType != ProtocolType)
		return false;

	if ((m_ProtocolType & (NET_TYPE_PROTOCOL_TCP | NET_TYPE_PROTOCOL_UDP)) != 0)
	{
		if (m_LocalPort != LocalPort)
			return false;
	}

	// a socket may be bount to all adapters than it has a local null address
	if (Mode == eStrict || m_LocalAddress != QHostAddress::AnyIPv4)
	{
		if(m_LocalAddress != LocalAddress)
			return false;
	}

	// don't test the remote endpoint if this is a udp socket
	if (Mode == eStrict || (m_ProtocolType & NET_TYPE_PROTOCOL_TCP) != 0)
	{
		if ((m_ProtocolType & (NET_TYPE_PROTOCOL_TCP | NET_TYPE_PROTOCOL_UDP)) != 0)
		{
			if (m_RemotePort != RemotePort)
				return false;
		}

		if (m_RemoteAddress != RemoteAddress)
			return false;
	}

	return true;
}

quint64 CSocketInfo::MkHash(quint64 ProcessId, quint32 ProtocolType, const QHostAddress& LocalAddress, quint16 LocalPort, const QHostAddress& RemoteAddress, quint16 RemotePort)
{
	if ((ProtocolType & NET_TYPE_PROTOCOL_UDP) != 0)
		RemotePort = 0;

	quint64 HashID = ((quint64)LocalPort << 0) | ((quint64)RemotePort << 16) | (quint64)(((quint32*)&ProcessId)[0] ^ ((quint32*)&ProcessId)[1]) << 32;

	return HashID;
}

void CSocketInfo::UpdateStats()
{
	QWriteLocker Locker(&m_StatsMutex);
	m_Stats.UpdateStats();
}

#ifndef MIB_TCP_STATE
typedef enum {
    MIB_TCP_STATE_CLOSED     =  1,
    MIB_TCP_STATE_LISTEN     =  2,
    MIB_TCP_STATE_SYN_SENT   =  3,
    MIB_TCP_STATE_SYN_RCVD   =  4,
    MIB_TCP_STATE_ESTAB      =  5,
    MIB_TCP_STATE_FIN_WAIT1  =  6,
    MIB_TCP_STATE_FIN_WAIT2  =  7,
    MIB_TCP_STATE_CLOSE_WAIT =  8,
    MIB_TCP_STATE_CLOSING    =  9,
    MIB_TCP_STATE_LAST_ACK   = 10,
    MIB_TCP_STATE_TIME_WAIT  = 11,
    MIB_TCP_STATE_DELETE_TCB = 12,
    //
    // Extra TCP states not defined in the MIB
    //
    MIB_TCP_STATE_RESERVED      = 100
} MIB_TCP_STATE;
#endif

static_assert(eTcpClosed      == MIB_TCP_STATE_CLOSED,      "tcp state drifted");
static_assert(eTcpListen      == MIB_TCP_STATE_LISTEN,      "tcp state drifted");
static_assert(eTcpEstablished == MIB_TCP_STATE_ESTAB,       "tcp state drifted");
static_assert(eTcpTimeWait    == MIB_TCP_STATE_TIME_WAIT,   "tcp state drifted");
static_assert(eTcpDeleteTcb   == MIB_TCP_STATE_DELETE_TCB,  "tcp state drifted");

void CSocketInfo::SetClosed()
{ 
	QWriteLocker Locker(&m_Mutex); 
	if(m_State != -1)
		m_State = MIB_TCP_STATE_CLOSED; 
	Locker.unlock();

	QWriteLocker StatsLocker(&m_StatsMutex);
	m_Stats.Net.ReceiveDelta.Delta = 0;
	m_Stats.Net.SendDelta.Delta = 0;
	m_Stats.Net.ReceiveRawDelta.Delta = 0;
	m_Stats.Net.SendRawDelta.Delta = 0;
	m_Stats.Net.ReceiveRate.Clear();
	m_Stats.Net.SendRate.Clear();
}

