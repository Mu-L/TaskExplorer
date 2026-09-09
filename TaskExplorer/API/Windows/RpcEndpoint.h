#pragma once
#include <qobject.h>
#include "..\RpcInfo.h"

//
// The Windows half of an RPC endpoint: what only the RPC runtime can answer.
// Everything a viewer reads is on CRpcEndpointInfo, so a remote system can
// answer it too - see the note there.
//
class CRpcEndpoint: public CRpcEndpointInfo
{
	Q_OBJECT

	TRACK_OBJECT(CRpcEndpoint)
public:
	CRpcEndpoint(QObject *parent = nullptr);
	virtual ~CRpcEndpoint();

protected:
	friend class CWindowsAPI;

	bool							UpdateDynamicData(void* hEnumBind);
};