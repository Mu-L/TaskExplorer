#pragma once
#include "../SecurityInfo.h"

//
// The Windows side of CSecurityEditable.
//
// Every securable thing in this application already had the same shape: a
// callback that opens the object for a given access mask, plus a context. That
// is what PhEditSecurity wanted, and it is all this needs too - so a process, a
// service and an LSA account are the same class here, differing only in which
// opener they carry and which type string names their access rights.
//
// The context is held as a byte array rather than a bare pointer. The old code
// had to park contexts in static buffers because the native dialog outlived the
// call that opened it; owning a copy removes that hazard.
//
class TASKCORE_EXPORT CWinSecurityObject : public CSecurityEditable
{
public:
	typedef long (__stdcall *POpenObject)(void** Handle, unsigned long DesiredAccess, void* Context);

	// for openers whose context is a value squeezed into the pointer (a pid, a handle)
	CWinSecurityObject(const QString& Name, const QString& Type, POpenObject Opener, quint64 Context, quint64 ObjectId = 0);

	// for openers that dereference the context
	CWinSecurityObject(const QString& Name, const QString& Type, POpenObject Opener, const QByteArray& Context);

	virtual QString	GetName() const						{ return m_Name; }
	virtual QString	GetTypeName() const					{ return m_Type; }
	virtual quint64	GetObjectId() const					{ return m_ObjectId; }

	virtual QList<SAccessRight> GetAccessRights() const;

	virtual STATUS	GetSecurity(SSecurityInfo& Info, bool bWithAudit = false) const;
	virtual STATUS	SetSecurity(const SSecurityInfo& Info, bool bWithAudit = false);

protected:
	void*			Context() const;

	QString			m_Name;
	QString			m_Type;
	POpenObject		m_Opener;
	QByteArray		m_Context;
	quint64			m_Value;
	quint64			m_ObjectId;
	bool			m_bByValue;
};

//
// Name <-> SID, which only the machine holding the accounts can do. Exposed
// because the dialog needs it when a principal is added by name.
//
TASKCORE_EXPORT QString LookupSidByName(const QString& Name);
TASKCORE_EXPORT QString LookupNameBySid(const QString& Sid);
