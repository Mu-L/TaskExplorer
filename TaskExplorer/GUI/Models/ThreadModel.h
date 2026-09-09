#pragma once
#include <qwidget.h>
#include "../MiscHelpers/Common/ListItemModel.h"
#include "../../API/ThreadInfo.h"

class CThreadModel : public CListItemModel
{
    Q_OBJECT

public:
    CThreadModel(QObject *parent = 0);
	~CThreadModel();

	void			Sync(QMap<quint64, CThreadPtr> ThreadList);

	void			SetExtThreadId(bool bSet) { m_bExtThreadId = bSet; }

	CThreadPtr		GetThread(const QModelIndex &index) const;

    int				columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant		headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;

	enum EColumns
	{
		eThread = 0,
		eCPU,
		eCPU_History,
		eStartAddress,
		eService,
		eName,
		eType,
		eCreated,
		eStartModule,
		eContextSwitches,
		eContextSwitchesDelta,
		ePriority,
		eBasePriority,
		eBasePriorityActual,
		ePagePriority,
		eIOPriority,
		eCycles,
		eCyclesDelta,
		eState,
		eKernelTime,
		eUserTime,
		eIdealProcessor,
		eImpersonation,
		eCritical,
		eAppDomain,

		ePendingIRP,
		eLastSystemCall,
		eLastStatusCode,
		eCOM_Apartment,
		eCOM_Flags,
		eFiber,
		ePriorityBoost,
		eStackUsage,
		eWaitTime,
		eIO_Reads,
		eIO_Writes,
		eIO_Other,
		eIO_ReadBytes,
		eIO_WriteBytes,
		eIO_OtherBytes,
		//eIO_TotalBytes,
		eIO_ReadsDelta,
		eIO_WritesDelta,
		eIO_OtherDelta,
		//eIO_TotalDelta,
		eIO_ReadBytesDelta,
		eIO_WriteBytesDelta,
		eIO_OtherBytesDelta,
		//eIO_TotalBytesDelta,
		eIO_ReadRate,
		eIO_WriteRate,
		eIO_OtherRate,
		//eIO_TotalRate,
		eTID_LXSS,
		ePowerThrottling,
		//eContainerID,
		eRPC_Usage,
		eCount
	};

protected:
	struct SThreadNode: SListNode
	{
		SThreadNode(const QVariant& Id) : SListNode(Id), iColor(0) {}

		CThreadPtr			pThread;

		int					iColor;
	};

	bool m_bExtThreadId;

	virtual SListNode* MkNode(const QVariant& Id) { return new SThreadNode(Id); }

	virtual QVariant GetDefaultIcon() const;
};