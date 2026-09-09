#pragma once
#include "../TokenInfo.h"

class CVariant;

//
// The token of a process running under Wine.
//
// Filled from the helper inside the prefix, because none of this exists on the
// Linux side of a Wine process: a token is a wineserver object and /proc has no
// notion of one. See NEXT.md 5.16.
//
// What it reports is Wine's answer, not a real Windows security context - there
// is no domain behind it, no LSA, and the integrity level is a number Wine keeps
// rather than a policy it enforces. That is still the right thing to show,
// because it is exactly what the program running there sees and acts on. It is
// only a reason not to present it as something it is not.
//
// Derives from CTokenInfo rather than being a structure of its own so that the
// daemon's existing serialisation carries it unchanged - MakeTokenBlock and the
// group and privilege lists all read these virtuals - and a viewer receives it
// as the CRemoteToken it already knows how to draw.
//
class CWineToken : public CTokenInfo
{
	Q_OBJECT
public:
	CWineToken(QObject* parent = NULL);

	//
	// Fill from one "Token" reply. Returns false for a reply that carried
	// nothing, which is not the same as a token with nothing in it.
	//
	bool					Apply(const CVariant& Token);

	virtual QString			GetUserName() const					{ QReadLocker Locker(&m_Mutex); return m_UserName; }
	virtual QString			GetSidString() const				{ QReadLocker Locker(&m_Mutex); return m_UserSid; }
	virtual quint32			GetSessionId() const				{ QReadLocker Locker(&m_Mutex); return m_SessionId; }
	virtual QString			GetOwnerName() const				{ QReadLocker Locker(&m_Mutex); return m_OwnerName; }
	virtual QString			GetGroupName() const				{ QReadLocker Locker(&m_Mutex); return m_GroupName; }

	virtual bool			IsElevated() const					{ QReadLocker Locker(&m_Mutex); return m_bElevated; }
	virtual int				GetElevationType() const			{ QReadLocker Locker(&m_Mutex); return m_ElevationType; }
	virtual quint32			GetIntegrityLevel() const			{ QReadLocker Locker(&m_Mutex); return m_Integrity; }

	virtual QMap<QByteArray, SGroup>	GetGroups() const		{ QReadLocker Locker(&m_Mutex); return m_Groups; }
	virtual QMap<QString, SPrivilege>	GetPrivileges() const	{ QReadLocker Locker(&m_Mutex); return m_Privileges; }

protected:
	QString					m_UserName;
	QString					m_UserSid;
	QString					m_OwnerName;
	QString					m_GroupName;
	quint32					m_SessionId = 0;
	bool					m_bElevated = false;
	int						m_ElevationType = 0;
	quint32					m_Integrity = 0;

	QMap<QByteArray, SGroup>	m_Groups;
	QMap<QString, SPrivilege>	m_Privileges;
};

typedef QSharedPointer<CWineToken> CWineTokenPtr;
