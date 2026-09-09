#pragma once
#include "../taskcore_global.h"
#include <qobject.h>
#include "AbstractInfo.h"

//
// One registered RPC endpoint.
//
// This was CRpcEndpoint, and the RPC view reached it by casting the system to
// CWindowsAPI - a cast that cannot succeed once the system is a remote one,
// whatever platform the viewer is running on. The same move GetGdiList got, for
// the same reason; see CGdiInfo.
//
// Everything here is a value the collector has already worked out. Nothing in
// the three fields is Windows-shaped: an interface id, a human description and
// a binding string. A Linux backend reporting the endpoints of a D-Bus or
// systemd activation socket would fill in the same three.
//
class TASKCORE_EXPORT CRpcEndpointInfo : public CAbstractInfoEx
{
	Q_OBJECT

	TRACK_OBJECT(CRpcEndpointInfo)
public:
	CRpcEndpointInfo(QObject *parent = nullptr);
	virtual ~CRpcEndpointInfo();

	virtual QString GetIfId() const				{ QReadLocker Locker(&m_Mutex); return m_IfId; }
	virtual QString GetDescription() const		{ QReadLocker Locker(&m_Mutex); return m_Description; }
	virtual QString GetBinding() const			{ QReadLocker Locker(&m_Mutex); return m_Binding; }

protected:
	//
	// The collector fills these in directly rather than through setters, which
	// is what it did when the class was its own; the friendship moves with the
	// members.
	//
	friend class CWindowsAPI;

	QString							m_IfId;
	QString							m_Description;
	QString							m_Binding;
};

typedef QSharedPointer<CRpcEndpointInfo> CRpcEndpointPtr;
typedef QWeakPointer<CRpcEndpointInfo> CRpcEndpointRef;
