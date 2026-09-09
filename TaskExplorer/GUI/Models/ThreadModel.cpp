#include "stdafx.h"
#include "../TaskStrings.h"
#include "../TaskExplorer.h"
#include "ThreadModel.h"
#include "../../../MiscHelpers/Common/Common.h"
CThreadModel::CThreadModel(QObject *parent)
:CListItemModel(parent)
{
	m_bExtThreadId = false;
}

CThreadModel::~CThreadModel()
{
}

void CThreadModel::Sync(QMap<quint64, CThreadPtr> ThreadList)
{
	QList<SListNode*> New;
	QHash<QVariant, SListNode*> Old = m_Map;

	bool bClearZeros = theConf->GetBool("Options/ClearZeros", true);

	foreach (const CThreadPtr& pThread, ThreadList)
	{
		QVariant ID = pThread->GetThreadId();

		int Row = -1;
		QHash<QVariant, SListNode*>::iterator I = Old.find(ID);
		SThreadNode* pNode = I != Old.end() ? static_cast<SThreadNode*>(I.value()) : NULL;
		if(!pNode)
		{
			pNode = static_cast<SThreadNode*>(MkNode(ID));
			pNode->Values.resize(columnCount());
			pNode->pThread = pThread;
			pNode->IsBold = pThread->IsMainThread();
			New.append(pNode);
		}
		else
		{
			I.value() = NULL;
			Row = GetRow(pNode);
		}
		int Col = 0;
		bool State = false;
		int Changed = 0;

		// Note: icons are loaded asynchroniusly
		if (m_bUseIcons && !pNode->Icon.isValid() && !m_ColumnsOff.contains(eThread))
		{
			CProcessPtr pProcess = pNode->pThread->GetProcess().staticCast<CProcessInfo>();
			CModulePtr pModule = pProcess ? pProcess->GetModuleInfo() : CModulePtr();
			if (pModule)
			{
				QPixmap Icon = ::MakeIcon(pModule->GetFileIcon());
				if (!Icon.isNull()) {
					Changed = 1; // set change for first column
					pNode->Icon = Icon;
				}
			}
		}

		int RowColor = CTaskExplorer::eNone;
		if (pThread->IsMarkedForRemoval() && CTaskExplorer::UseListColor(CTaskExplorer::eToBeRemoved))			RowColor = CTaskExplorer::eToBeRemoved;
		else if (pThread->IsNewlyCreated() && CTaskExplorer::UseListColor(CTaskExplorer::eAdded))				RowColor = CTaskExplorer::eAdded;
		else if (pThread->IsCriticalThread() && CTaskExplorer::UseListColor(CTaskExplorer::eIsProtected))	RowColor = CTaskExplorer::eIsProtected;
		else if (pThread->IsGuiThread() && CTaskExplorer::UseListColor(CTaskExplorer::eGuiThread))			RowColor = CTaskExplorer::eGuiThread;
		if (pNode->iColor != RowColor) {
			pNode->iColor = RowColor;
			pNode->Color = CTaskExplorer::GetListColor(RowColor);
			Changed = 2;
		}

		if (pNode->IsGray != pThread->IsSuspended())
		{
			pNode->IsGray = pThread->IsSuspended();
			Changed = 2;
		}

		STaskStats CpuStats = pThread->GetCpuStats();
		SIOStatsEx IoStats = pThread->GetIoStats();

		for(int section = 0; section < columnCount(); section++)
		{
			if (m_ColumnsOff.contains(section))
				continue; // ignore columns which are hidden

			QVariant Value;
			switch(section)
			{
				case eThread:				Value = pThread->GetThreadId(); break;
				case eTID_LXSS:				Value = pThread->GetLXSSThreadId(); break;
				case eCPU_History:
				case eCPU:					Value = CpuStats.CpuUsage; break;
				case eStartAddress:			Value = pThread->GetStartAddressString(); break;
				case eService:				Value = pThread->GetServiceName(); break;
				case eName:					Value = pThread->GetThreadName(); break;
				case eType:					Value = pThread->IsMainThread() ? 2 : pThread->IsGuiThread() ? 1 : 0; break;
				case eCreated:				Value = pThread->GetCreateTimeStamp(); break;
				case eStartModule:			Value = pThread->GetStartAddressFileName(); break;
				case eContextSwitches:		Value = CpuStats.ContextSwitchesDelta.Value; break;
				case eContextSwitchesDelta:	Value = CpuStats.ContextSwitchesDelta.Delta; break;
                case ePriority:				Value = (quint32)pThread->GetPriority(); break;
				case eBasePriority:			Value = (quint32)pThread->GetBasePriorityIncrement(); break;
				case eBasePriorityActual:	Value = (quint32)pThread->GetBasePriority(); break;
                case ePagePriority:			Value = (quint32)pThread->GetPagePriority(); break;
                case eIOPriority:			Value = (quint32)pThread->GetIOPriority(); break;
				case eCycles:				Value = CpuStats.CycleDelta.Value; break;
				case eCyclesDelta:			Value = CpuStats.CycleDelta.Delta; break;
				case eState:				Value = pThread->GetWaitState(); break;
				case eKernelTime:			Value = CpuStats.CpuKernelDelta.Value;
				case eUserTime:				Value = CpuStats.CpuUserDelta.Value;
				case eIdealProcessor:		Value = ::GetIdealProcessorString(pThread); break;
				case eImpersonation:		Value = pThread->IsSandboxed() ? (pThread->HasToken2() ? 1 : 0) : (int)pThread->GetTokenState(); break;
				case eCritical:				Value = pThread->IsCriticalThread() ? tr("Critical") : ""; break;
				case eAppDomain:			Value = pThread->GetAppDomain(); break;

				case ePendingIRP:			Value = pThread->HasPendingIrp(); break;
				case eLastSystemCall:		Value = ::GetLastSysCallInfoString(pThread); break;
				case eLastStatusCode:		Value = ::GetLastSysCallStatusString(pThread); break;
				case eCOM_Apartment:		Value = pThread->GetApartmentType(); break;
				case eCOM_Flags: 			Value = pThread->GetApartmentFlags(); break;
				case eFiber:				Value = pThread->IsFiber(); break;
				case ePriorityBoost:		Value = pThread->HasPriorityBoost(); break;
				case eStackUsage:			Value = pThread->GetStackUsagePercent(); break;
				//case eWaitTime:				
				case eIO_Reads:				Value = IoStats.ReadCount; break;
				case eIO_Writes:			Value = IoStats.WriteCount; break;
				case eIO_Other:				Value = IoStats.OtherCount; break;
				case eIO_ReadBytes:			Value = IoStats.ReadRaw; break;
				case eIO_WriteBytes:		Value = IoStats.WriteRaw; break;
				case eIO_OtherBytes:		Value = IoStats.OtherRaw; break;		
				//case eIO_TotalBytes:		Value = ; break;
				case eIO_ReadsDelta:		Value = IoStats.ReadDelta.Delta; break;
				case eIO_WritesDelta:		Value = IoStats.WriteDelta.Delta; break;
				case eIO_OtherDelta:		Value = IoStats.OtherDelta.Delta; break;
					//case eIO_TotalDelta:		Value = ; break;
				case eIO_ReadBytesDelta:	Value = IoStats.ReadRawDelta.Delta; break;
				case eIO_WriteBytesDelta:	Value = IoStats.WriteRawDelta.Delta; break;
				case eIO_OtherBytesDelta:	Value = IoStats.OtherRawDelta.Delta; break;
					//case eIO_TotalBytesDelta:	Value = ; break;
				case eIO_ReadRate:			Value = IoStats.ReadRate.Get(); break;
				case eIO_WriteRate:			Value = IoStats.WriteRate.Get(); break;
				case eIO_OtherRate:			Value = IoStats.OtherRate.Get(); break;
					//case eIO_TotalRate:		Value = ; break;
				case ePowerThrottling:		Value = pThread->IsPowerThrottled(); break;
				//case eContainerID:			
				case eRPC_Usage:			Value = pThread->HasRpcState(); break;
			}

			SThreadNode::SValue& ColValue = pNode->Values[section];

			if (ColValue.Raw != Value)
			{
				if(Changed == 0)
					Changed = 1;
				ColValue.Raw = Value;

				switch (section)
				{
					case eThread:				if (m_bExtThreadId)
													ColValue.Formatted = tr("%1 (%2): %3").arg(::LocalizeName(pThread->GetName())).arg(theGUI->FormatID(pThread->GetProcessId())).arg(theGUI->FormatID(pThread->GetThreadId()));
												else
													ColValue.Formatted = theGUI->FormatID(pThread->GetThreadId());
												break;
					//case eThread:				ColValue.Formatted = "0x" + QString::number(pThread->GetThreadId()); break;
					case eCPU:					ColValue.Formatted = (!bClearZeros || CpuStats.CpuUsage > 0.00004) ? QString::number(CpuStats.CpuUsage*100, 10, 2) + "%" : ""; break;

					case ePriority:				ColValue.Formatted = ::GetPriorityString(pThread); break;
					case eBasePriority:			ColValue.Formatted = ::GetBasePriorityIncrementString(pThread); break;
					case eBasePriorityActual:	ColValue.Formatted = ::GetBasePriorityString(pThread); break;
					case ePagePriority:			ColValue.Formatted = ::GetPagePriorityString(pThread); break;
					case eIOPriority:			ColValue.Formatted = ::GetIOPriorityString(pThread); break;

					case eCreated:				ColValue.Formatted = QDateTime::fromSecsSinceEpoch(Value.toULongLong()/1000).toString("dd.MM.yyyy hh:mm:ss"); break;
					case eType:					ColValue.Formatted = ::GetThreadTypeString(pThread); break;
					case eState:				ColValue.Formatted = ::GetThreadStateString(pThread); break;
					case eCycles:
					case eContextSwitches:
												ColValue.Formatted = FormatNumber(Value.toULongLong()); break;
					case eCyclesDelta:
					case eContextSwitchesDelta:
												ColValue.Formatted = FormatNumberEx(Value.toULongLong(), bClearZeros); break;
					case eImpersonation:		ColValue.Formatted = ::GetTokenStateString(pThread); break;

					case ePendingIRP:			ColValue.Formatted = pThread->HasPendingIrp() ? tr("Yes") : ""; break;
					case eFiber:				ColValue.Formatted = pThread->IsFiber() ? tr("Yes") : ""; break;
					case ePriorityBoost:		ColValue.Formatted = pThread->HasPriorityBoost() ? tr("Yes") : ""; break;
					case eStackUsage:			ColValue.Formatted = ::GetStackUsageString(pThread); break;
					case ePowerThrottling:		ColValue.Formatted = pThread->IsPowerThrottled() ? tr("Yes") : ""; break;
					case eRPC_Usage:			ColValue.Formatted = pThread->HasRpcState() ? tr("Yes") : ""; break;

					case eCOM_Apartment:		ColValue.Formatted = ::GetApartmentTypeString(pThread); break;
					case eCOM_Flags:			ColValue.Formatted = ::GetApartmentFlagsString(pThread); break;

					case eIO_Reads:
					case eIO_Writes:
					case eIO_Other:
												ColValue.Formatted = FormatNumber(Value.toULongLong()); break;

					case eIO_ReadsDelta:
					case eIO_WritesDelta:
					case eIO_OtherDelta:
												ColValue.Formatted = FormatNumberEx(Value.toULongLong(), bClearZeros); break;

					case eIO_ReadBytes:
					case eIO_WriteBytes:
					case eIO_OtherBytes:
												if(Value.type() != QVariant::String) ColValue.Formatted = FormatSize(Value.toULongLong()); break; 

					case eIO_ReadBytesDelta:
					case eIO_WriteBytesDelta:
					case eIO_OtherBytesDelta:
												if(Value.type() != QVariant::String) ColValue.Formatted = FormatSizeEx(Value.toULongLong(), bClearZeros); break; 

					//case eIO_TotalRate:
					case eIO_ReadRate:
					case eIO_WriteRate:
					case eIO_OtherRate:
												if(Value.type() != QVariant::String) ColValue.Formatted = FormatRateEx(Value.toULongLong(), bClearZeros); break; 
				}
			}

			if(State != (Changed != 0))
			{
				if(State && Row != -1)
					emit dataChanged(createIndex(Row, Col), createIndex(Row, section-1));
				State = (Changed != 0);
				Col = section;
			}
			if (Changed == 1)
				Changed = 0;
		}
		if(State && Row != -1)
			emit dataChanged(createIndex(Row, Col, pNode), createIndex(Row, columnCount()-1, pNode));

	}

	CListItemModel::Sync(New, Old);
}

CThreadPtr CThreadModel::GetThread(const QModelIndex &index) const
{
	if (!index.isValid())
        return CThreadPtr();

	SThreadNode* pNode = static_cast<SThreadNode*>(index.internalPointer());
	return pNode->pThread;
}

int CThreadModel::columnCount(const QModelIndex &parent) const
{
	return eCount;
}

QVariant CThreadModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
	{
		switch(section)
		{
			case eThread:				return tr("Thread");
			case eTID_LXSS:				return tr("LXSS TID");
			case eCPU_History:			return tr("CPU graph");
			case eCPU:					return tr("CPU");
			case eCyclesDelta:			return tr("Cycles delta");
			case eStartAddress:			return tr("Start address");
			case eService:				return tr("Service");
			case eName:					return tr("Name");
			case eType:					return tr("Type");
			case eCreated:				return tr("Created");
			case eStartModule:			return tr("Start module");
			case eContextSwitches:		return tr("Context switches");
			case eContextSwitchesDelta:	return tr("Context switches delta");
			case ePriority:				return tr("Priority");
			case eBasePriority:			return tr("Base priority");
			case eBasePriorityActual: 	return tr("Base priority (actual)");
			case ePagePriority:			return tr("Page priority");
			case eIOPriority:			return tr("I/O priority");
			case eCycles:				return tr("Cycles");
			case eState:				return tr("State");
			case eKernelTime:			return tr("Kernel time");
			case eUserTime:				return tr("User time");
			case eIdealProcessor:		return tr("Ideal processor");
			case eCritical:				return tr("Critical");
			case eImpersonation:		return tr("Impersonation Token");
			case eAppDomain:			return tr("App Domain");

			case ePendingIRP:			return tr("Pending IRP");	
			case eLastSystemCall:		return tr("Last system call");
			case eLastStatusCode:		return tr("Last status code");
			case eCOM_Apartment:		return tr("COM apartment");
			case eCOM_Flags:			return tr("COM flags");
			case eFiber:				return tr("Fiber");	
			case ePriorityBoost:		return tr("Priority boost");
			case eStackUsage:			return tr("Stack usage");
			case eWaitTime:				return tr("Wait time");
			case eIO_Reads:				return tr("I/O reads");
			case eIO_Writes:			return tr("I/O writes");
			case eIO_Other:				return tr("I/O other");
			case eIO_ReadBytes:			return tr("I/O read bytes");
			case eIO_WriteBytes:		return tr("I/O write bytes");
			case eIO_OtherBytes:		return tr("I/O other bytes");
			//case eIO_TotalBytes:		return tr("I/O total bytes");
			case eIO_ReadsDelta:		return tr("I/O reads delta");
			case eIO_WritesDelta:		return tr("I/O writes delta");
			case eIO_OtherDelta:		return tr("I/O other delta");
			//case eIO_TotalDelta:		return tr("I/O total delta");
			case eIO_ReadBytesDelta:	return tr("I/O read bytes delta");
			case eIO_WriteBytesDelta:	return tr("I/O write bytes delta");
			case eIO_OtherBytesDelta:	return tr("I/O other bytes delta");
			//case eIO_TotalBytesDelta:	return tr("I/O total bytes delta");
			case eIO_ReadRate:			return tr("I/O read rate");
			case eIO_WriteRate:			return tr("I/O write rate");
			case eIO_OtherRate:			return tr("I/O other rate");
			//case eIO_TotalRate:		return tr("I/O total rate");
			case ePowerThrottling:		return tr("Power throttling");
			//case eContainerID:			return tr("Container ID");
			case eRPC_Usage:				return tr("RPC usage");
		}
	}
    return QVariant();
}

QVariant CThreadModel::GetDefaultIcon() const 
{ 
	return g_ExeIcon;
}
