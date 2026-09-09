#include "stdafx.h"
#include "../TaskStrings.h"
#include "../TaskExplorer.h"
#include "ServiceModel.h"
#include "../../../MiscHelpers/Common/Common.h"
#include "../../API/SystemAPI.h"

CServiceModel::CServiceModel(QObject *parent)
:CListItemModel(parent)
{
	m_ShowDriver = true;
	m_bUseIcons = true;
}

CServiceModel::~CServiceModel()
{
}

void CServiceModel::Sync(QMap<QString, CServicePtr> ServiceList)
{
	QList<SListNode*> New;
	QHash<QVariant, SListNode*> Old = m_Map;

	foreach (const CServicePtr& pService, ServiceList)
	{
		if (!m_ShowDriver && pService->IsDriver())
			continue;

		QVariant ID = pService->GetName();

		int Row = -1;
		QHash<QVariant, SListNode*>::iterator I = Old.find(ID);
		SServiceNode* pNode = I != Old.end() ? static_cast<SServiceNode*>(I.value()) : NULL;
		if(!pNode)
		{
			pNode = static_cast<SServiceNode*>(MkNode(ID));
			pNode->Values.resize(columnCount());
			pNode->pService = pService;
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

		CModulePtr pModule = pService->GetModuleInfo();
		// Note: icons are loaded asynchroniusly
		if (m_bUseIcons && !pNode->Icon.isValid() && !m_ColumnsOff.contains(eService))
		{
			QPixmap Icon;
			if (pService->IsDriver())
				Icon = g_DllIcon.pixmap(16, 16);
			else if (pModule)
				Icon = ::MakeIcon(pModule->GetFileIcon()); 

			if (!Icon.isNull()) {
				Changed = 1; // set change for first column
				pNode->Icon = Icon;
			}
		}
		int RowColor = CTaskExplorer::eNone;
		if (pService->IsMarkedForRemoval() && CTaskExplorer::UseListColor(CTaskExplorer::eToBeRemoved))		RowColor = CTaskExplorer::eToBeRemoved;
		else if (pService->IsNewlyCreated() && CTaskExplorer::UseListColor(CTaskExplorer::eAdded))			RowColor = CTaskExplorer::eAdded;
		else if (pService->IsDriver() && CTaskExplorer::UseListColor(CTaskExplorer::eDriver))			RowColor = CTaskExplorer::eDriver;
		if (pNode->iColor != RowColor) {
			pNode->iColor = RowColor;
			pNode->Color = CTaskExplorer::GetListColor(RowColor);
			Changed = 2;
		}

		if (pNode->IsGray != pService->IsStopped())
		{
			pNode->IsGray = pService->IsStopped();
			Changed = 2;
		}


		for(int section = 0; section < columnCount(); section++)
		{
			if (m_ColumnsOff.contains(section))
				continue; // ignore columns which are hidden

			QVariant Value;
			switch(section)
			{
				case eService:				Value = pService->GetName().toLower(); break;
				case eDisplayName:			Value = pService->GetDisplayName(); break;
				case eType:					Value = ::GetServiceTypeString(pService); break;
				case eStatus:				Value = ::GetServiceStateString(pService); break;
				case eStartType:			Value = ::GetServiceStartTypeString(pService); break;
				case ePID:					Value = (int)pService->GetPID(); break;
				case eFileName:				Value = pService->GetFileName(); break;
				case eDescription:			Value = pModule ? pModule->GetFileInfo("Description") : ""; break;
				case eCompanyName:			Value = pModule ? pModule->GetFileInfo("CompanyName") : ""; break;
				case eVersion:				Value = pModule ? pModule->GetFileInfo("FileVersion") : ""; break;
				case eErrorControl:			Value = ::GetServiceErrorControlString(pService); break;
				case eGroupe:				Value = pService->GetGroupeName(); break;
				case eBinaryPath:			Value = pService->GetBinaryPath(); break;

				//case eKeyModificationTime:	
				case eVerificationStatus:	Value = ::GetVerifyResultString(pModule); break;
				case eVerifiedSigner:		Value = pModule ? pModule->GetVerifySignerName() : ""; break;

				//
				// A service that failed with its own error code reports the
				// generic "service specific error" in the Win32 field and the
				// real one alongside; show whichever is meaningful.
				//
				case eExitCode:				Value = pService->GetServiceSpecificExitCode() != 0 ? pService->GetServiceSpecificExitCode() : pService->GetWin32ExitCode(); break;
			}

			SServiceNode::SValue& ColValue = pNode->Values[section];

			if (ColValue.Raw != Value)
			{
				if(Changed == 0)
					Changed = 1;
				ColValue.Raw = Value;

				switch (section)
				{
					case ePID:				if (Value.toLongLong() < 0) ColValue.Formatted = ""; 
											else ColValue.Formatted = theGUI->FormatID(Value.toLongLong()); 
											break;

					case eService:			ColValue.Formatted = pService->GetName(); break;
				}
			}

			if(State != (Changed != 0))
			{
				if(State && Row != -1)
					emit dataChanged(createIndex(Row, Col), createIndex(Row, section-1));
				State = (Changed != 0);
				Col = section;
			}
			if(Changed == 1)
				Changed = 0;
		}
		if(State && Row != -1)
			emit dataChanged(createIndex(Row, Col, pNode), createIndex(Row, columnCount()-1, pNode));

	}

	CListItemModel::Sync(New, Old);
}

CServicePtr CServiceModel::GetService(const QModelIndex &index) const
{
	if (!index.isValid())
        return CServicePtr();

	SServiceNode* pNode = static_cast<SServiceNode*>(index.internalPointer());
	return pNode->pService;
}

int CServiceModel::columnCount(const QModelIndex &parent) const
{
	return eCount;
}

QVariant CServiceModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
	{
		switch(section)
		{
			case eService:				return tr("Service");
			case eDisplayName:			return tr("Display Name");
			case eType:					return tr("Type");
			case eStatus:				return tr("Status");
			case eStartType:			return tr("Start type");
			case ePID:					return tr("PID");
			case eFileName:				return tr("File name");
			case eErrorControl:			return tr("Error control");
			case eGroupe:				return tr("Groupe");
			case eDescription:			return tr("Description");
			case eCompanyName:			return tr("Company name");
			case eVersion:				return tr("Version");
			case eBinaryPath:			return tr("Binary path");

			//case eKeyModificationTime:	return tr("Modification time");

			case eVerificationStatus:	return tr("Verification status");
			case eVerifiedSigner:		return tr("Verified signer");

			case eExitCode:				return tr("Exit code");
		}
	}
    return QVariant();
}

QVariant CServiceModel::GetDefaultIcon() const 
{ 
	return g_ExeIcon;
}