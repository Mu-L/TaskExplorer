#pragma once
#include <qobject.h>
#include "../HeapInfo.h"

class CWinHeap: public CHeapInfo
{
	Q_OBJECT

	TRACK_OBJECT(CWinHeap)
public:
	CWinHeap(QObject *parent = nullptr);
	virtual ~CWinHeap();

	virtual quint32 GetFlags() const;
	virtual quint32 GetClass() const;
	virtual int GetHeapKind() const;
	virtual int GetFrontEndType() const;
	virtual quint32 GetType() const;
	
protected:
	friend class CWinProcess;

	quint32 m_Signature;
	quint8 m_HeapFrontEndType;
};

typedef QSharedPointer<CWinHeap> CWinHeapPtr;
typedef QWeakPointer<CWinHeap> CWinHeapRef;