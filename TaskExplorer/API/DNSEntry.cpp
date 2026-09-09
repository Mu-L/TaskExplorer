#include "stdafx.h"
#include "DNSEntry.h"


CDnsLogEntry::CDnsLogEntry(const QString& HostName, const QList<QHostAddress>& Addresses)
{
	m_HostName = HostName;
	m_Addresses = Addresses;
}

QList<QHostAddress> CDnsLogEntry::UpdateAddresses(const QList<QHostAddress>& Addresses)
{
	QWriteLocker Locker(&m_Mutex);

	QList<QHostAddress> NewAddresses;
	if (m_Addresses == Addresses)
		return NewAddresses;

	foreach(const QHostAddress& Address, Addresses)
	{
		if (m_Addresses.contains(Address))
			continue;
		m_Addresses.append(Address);
		NewAddresses.append(Address);
	}

	return NewAddresses;
}

/////////////////////////////////
//

CDnsCacheEntry::CDnsCacheEntry(const QString& HostName, quint16 Type, const QHostAddress& Address, const QString& ResolvedString, QObject *parent) : CAbstractInfoEx(parent)
{
	m_CreateTimeStamp = GetTime() * 1000;

	m_HostName = HostName;
	m_Type = Type;
	m_Address = Address;
	m_ResolvedString = ResolvedString;
	m_TTL = 0;

	m_QueryCounter = 0;
}

void CDnsCacheEntry::SetTTL(quint64 TTL)
{
	QWriteLocker Locker(&m_Mutex); 

	if (m_TTL <= 0) {
		//m_CreateTimeStamp = GetTime() * 1000;
		m_RemoveTimeStamp = 0;
		m_QueryCounter++;
	}

	m_TTL = TTL; 
}

void CDnsCacheEntry::SubtractTTL(quint64 Delta)
{ 
	QWriteLocker Locker(&m_Mutex); 

	if (m_TTL > 0) // in case we flushed the cache and the entries were gone before the TTL expired
		m_TTL = 0;

	m_TTL -= Delta;	
}

/*
void CDnsCacheEntry::RecordProcess(const QString& ProcessName, quint64 ProcessId, const QWeakPointer<QObject>& pProcess, bool bUpdate)
{
	QWriteLocker Locker(&m_Mutex); 

	CDnsProcRecordPtr &pRecord = m_ProcessRecords[qMakePair(ProcessName, ProcessId)];
	if (!pRecord)
		pRecord = CDnsProcRecordPtr(new CDnsProcRecord(ProcessName, ProcessId));

	pRecord->Update(pProcess, bUpdate);
}
*/
