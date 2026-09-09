#pragma once
#include "../../../taskcore_global.h"
#include "../../AssemblyList.h"

class TASKCORE_EXPORT CAssemblyEnum : public CAssemblyEnumerator
{
	Q_OBJECT

	TRACK_OBJECT(CAssemblyEnum)
public:
	CAssemblyEnum(quint64 ProcessId, QObject *parent = nullptr);
	virtual ~CAssemblyEnum();

protected:
	void				run();

	//bool				m_bCancel;
	quint64				m_ProcessId;

private:
	static void			AddNodes(CAssemblyListPtr& List, struct _PH_LIST* NodeList, quint64 ParentId = 0);
};