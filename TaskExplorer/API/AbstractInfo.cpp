#include "stdafx.h"
#include "AbstractInfo.h"
#include "../../MiscHelpers/Common/Settings.h"
#include "SystemAPI.h"

//
// A strong reference for as long as the caller holds it, or null when the
// machine this object came from has gone. See the note in the header.
//
CSystemPtr CAbstractInfo::GetSystem() const
{
	return m_pSystem.toStrongRef();
}

//
// The weak half of the pair; see the header for why it is weak and why what
// comes back out is not.
//
void CAbstractInfo::SetSystem(const CSystemPtr& pSystem)
{
	m_pSystem = pSystem;
}



//
// Starts at one, so that a zero uid is always a bug and never an object.
//
QAtomicInteger<quint64> CAbstractInfo::m_NextObjectUid(1);

CAbstractInfo::CAbstractInfo(QObject *parent)
	: QObject(parent), m_pSystem(nullptr), m_ObjectUid(m_NextObjectUid.fetchAndAddOrdered(1))
{
}

volatile quint64 CAbstractInfoEx::m_PersistenceTime = 5000;
volatile quint64 CAbstractInfoEx::m_HighlightTime = 2500;

CAbstractInfoEx::CAbstractInfoEx(QObject *parent)
	: CAbstractInfo(parent)
{
	m_NewlyCreated = true;
	m_CreateTimeStamp = 0;
	m_RemoveTimeStamp = 0;
}

CAbstractInfoEx::~CAbstractInfoEx()
{
}

bool CAbstractInfoEx::CanBeRemoved() const
{ 
	QReadLocker Locker(&m_Mutex); 
	if (m_RemoveTimeStamp == 0)
		return false;
	return GetCurTick() - m_RemoveTimeStamp > m_PersistenceTime;
}

void CAbstractInfoEx::ClearPersistence()
{
	QReadLocker Locker(&m_Mutex); 
	if (m_RemoveTimeStamp != 0)
		m_RemoveTimeStamp = GetCurTick() - m_PersistenceTime;
}

bool CAbstractInfoEx::IsNewlyCreated() const
{
	QReadLocker Locker(&m_Mutex);
	if (m_NewlyCreated)
	{
		// Note: GetTime() is very slow, and there is no point to check it over and over agian once we know that this object is old
		quint64 curTime = (qint64)GetTime() * 1000ULL;
		if (!(curTime - m_CreateTimeStamp < m_HighlightTime))
			m_NewlyCreated = false;
	}
	return m_NewlyCreated;
}
