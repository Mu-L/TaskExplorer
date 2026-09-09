#include "stdafx.h"
#include "LinuxWineToken.h"
#include "../../../MiscHelpers/Common/Variant.h"
#include "../../../MiscHelpers/Common/XVariant.h"

CWineToken::CWineToken(QObject* parent)
	: CTokenInfo(parent)
{
}

bool CWineToken::Apply(const CVariant& Token)
{
	CVariant Value;
	if (!Token.Find("Ok", Value) || !Value.To<bool>())
		return false;	// the helper could not open the process, or its token

	QWriteLocker Locker(&m_Mutex);

	if (Token.Find("User", Value))			m_UserName = XVariant(Value).AsQStr();
	if (Token.Find("UserSid", Value))		m_UserSid = XVariant(Value).AsQStr();
	if (Token.Find("Owner", Value))			m_OwnerName = XVariant(Value).AsQStr();
	if (Token.Find("Group", Value))			m_GroupName = XVariant(Value).AsQStr();
	if (Token.Find("Session", Value))		m_SessionId = Value.To<quint32>();
	if (Token.Find("Elevated", Value))		m_bElevated = Value.To<bool>();
	if (Token.Find("ElevationType", Value))	m_ElevationType = (int)Value.To<qint32>();
	if (Token.Find("Integrity", Value))		m_Integrity = Value.To<quint32>();

	//
	// Keyed by the SID's text, not by its bytes.
	//
	// The map wants a QByteArray key and the collectors on both platforms use
	// the raw SID for it, which is what makes two groups with the same name
	// distinguishable. The helper sends the text form - it is what everything
	// downstream displays and compares - so that is what is used here, as bytes.
	// Unique for the same reason the raw form is.
	//
	m_Groups.clear();
	CVariant Groups;
	if (Token.Find("Groups", Groups))
	{
		Groups.ReadRawList([&](const CVariant& Entry) {
			CVariant Field;
			SGroup Group;
			if (Entry.Find("Sid", Field))			Group.SidString = XVariant(Field).AsQStr();
			if (Entry.Find("Name", Field))			Group.Name = XVariant(Field).AsQStr();
			if (Entry.Find("Attributes", Field))	Group.Attributes = Field.To<quint32>();

			if (Group.SidString.isEmpty())
				return;

			Group.Sid = Group.SidString.toUtf8();
			m_Groups.insert(Group.Sid, Group);
		});
	}

	m_Privileges.clear();
	CVariant Privileges;
	if (Token.Find("Privileges", Privileges))
	{
		Privileges.ReadRawList([&](const CVariant& Entry) {
			CVariant Field;
			SPrivilege Privilege;
			if (Entry.Find("Name", Field))			Privilege.Name = XVariant(Field).AsQStr();
			if (Entry.Find("Attributes", Field))	Privilege.Attributes = Field.To<quint32>();

			if (!Privilege.Name.isEmpty())
				m_Privileges.insert(Privilege.Name, Privilege);
		});
	}

	return true;
}
