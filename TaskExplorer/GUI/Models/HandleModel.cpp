#include "stdafx.h"
#include "../TaskExplorer.h"
#include "../TaskStrings.h"
#include "HandleModel.h"
#include "../../../MiscHelpers/Common/Common.h"
CHandleModel::CHandleModel(QObject *parent)
:CListItemModel(parent)
{
	m_SizePosNA = false;
}

CHandleModel::~CHandleModel()
{
}

void CHandleModel::Sync(QMap<quint64, CHandlePtr> HandleList)
{
	QList<SListNode*> New;
	QHash<QVariant, SListNode*> Old = m_Map;
	
	bool bClearZeros = theConf->GetBool("Options/ClearZeros", true);

	foreach (const CHandlePtr& pHandle, HandleList)
	{
		QVariant ID = (quint64)pHandle.data();

		int Row = -1;
		QHash<QVariant, SListNode*>::iterator I = Old.find(ID);
		SHandleNode* pNode = I != Old.end() ? static_cast<SHandleNode*>(I.value()) : NULL;
		if(!pNode)
		{
			pNode = static_cast<SHandleNode*>(MkNode(ID));
			pNode->Values.resize(columnCount());
			pNode->pHandle = pHandle;
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

		CProcessPtr pProcess = pNode->pHandle->GetProcess().staticCast<CProcessInfo>();

		// Note: icons are loaded asynchroniusly
		if (m_bUseIcons && !pNode->Icon.isValid() && !m_ColumnsOff.contains(eProcess))
		{
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
		if (pHandle->IsMarkedForRemoval() && CTaskExplorer::UseListColor(CTaskExplorer::eToBeRemoved))		RowColor = CTaskExplorer::eToBeRemoved;
		else if (pHandle->IsNewlyCreated() && CTaskExplorer::UseListColor(CTaskExplorer::eAdded))			RowColor = CTaskExplorer::eAdded;
		else if (pHandle->IsInherited() && CTaskExplorer::UseListColor(CTaskExplorer::eIsInherited))		RowColor = CTaskExplorer::eIsInherited;
		else if (pHandle->IsProtected() && CTaskExplorer::UseListColor(CTaskExplorer::eIsProtected))		RowColor = CTaskExplorer::eIsProtected;
		if (pNode->iColor != RowColor) {
			pNode->iColor = RowColor;
			pNode->Color = CTaskExplorer::GetListColor(RowColor);
			Changed = 2;
		}

		for(int section = 0; section < columnCount(); section++)
		{
			if (m_ColumnsOff.contains(section))
				continue; // ignore columns which are hidden

			QVariant Value;
			switch(section)
			{
				case eProcess:			Value = pHandle->GetProcessId(); break;	
				case eHandle:			Value = pHandle->GetHandleId(); break;
				case eType:				Value = pHandle->GetTypeName(); break;
				case eName:				Value = pHandle->GetFileName(); break;
				case ePosition:			Value = pHandle->GetPosition(); break;	
				case eSize:				Value = pHandle->GetSize(); break;	
				case eGrantedAccess:	Value = (quint32)pHandle->GetGrantedAccess(); break;
				case eFileShareAccess:	Value = (quint32)pHandle->GetFileFlags(); break;	
				case eAttributes:		Value = (quint32)pHandle->GetAttributes(); break;	
				case eObjectAddress:	Value = pHandle->GetObjectAddress(); break;	
				case eOriginalName:		Value = pHandle->GetOriginalName(); break;	
				//case eHandleCount:		Value = pHandle->GetHandleCount(); break; // PhGetHandleInformation
				//case eRefCount:			Value = pHandle->GetRefCount(); break; // PhGetHandleInformation
				//case ePagedSize:		Value = pHandle->GetPagedSize(); break; // PhGetHandleInformation
				//case eNonPagedSize:		Value = pHandle->GetNonpagedSize(); break; // PhGetHandleInformation
			}

			SHandleNode::SValue& ColValue = pNode->Values[section];

			if (m_SizePosNA && (section == ePosition || section == eSize))
				Value = tr("N/A");

			if (ColValue.Raw != Value)
			{
				if(Changed == 0)
					Changed = 1;
				ColValue.Raw = Value;

				switch (section)
				{
					case eProcess:			ColValue.Formatted = tr("%1 (%2)").arg(::LocalizeName(pProcess.isNull() ? QString() : pProcess->GetName())).arg(theGUI->FormatID(pHandle->GetProcessId())); break;	
					case eHandle:			ColValue.Formatted = "0x" + QString::number(pHandle->GetHandleId(), 16); break;
					case eType:				ColValue.Formatted = ::GetHandleTypeString(pHandle); break;
					case eGrantedAccess:	ColValue.Formatted = ::GetGrantedAccessString(pHandle); break;
					case eAttributes:		ColValue.Formatted = ::GetHandleAttributesString(pHandle); break;	
					case eFileShareAccess:	ColValue.Formatted = ::GetFileShareAccessString(pHandle); break;	
					case eObjectAddress:	ColValue.Formatted = FormatAddress(pHandle->GetObjectAddress()); break;	
					case eSize:
					case ePosition:			if(Value.type() != QVariant::String) ColValue.Formatted = FormatNumberEx(Value.toULongLong(), bClearZeros);
				}
			}

			if(State != (Changed != 0))
			{
				if(State && Row != -1)
					emit dataChanged(createIndex(Row, Col), createIndex(Row, section-1));
				State = Changed;
				Col = (Changed != 0);
			}
			if(Changed == 1)
				Changed = 0;
		}
		if(State && Row != -1)
			emit dataChanged(createIndex(Row, Col, pNode), createIndex(Row, columnCount()-1, pNode));

	}

	CListItemModel::Sync(New, Old);
}

CHandlePtr CHandleModel::GetHandle(const QModelIndex &index) const
{
	if (!index.isValid())
        return CHandlePtr();

	SHandleNode* pNode = static_cast<SHandleNode*>(index.internalPointer());
	return pNode->pHandle;
}

int CHandleModel::columnCount(const QModelIndex &parent) const
{
	return eCount;
}

QVariant CHandleModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
	{
		switch(section)
		{
			case eProcess:				return tr("Process");
			case eHandle:				return tr("Handle");
			case eType:					return tr("Type");
			case eName:					return tr("File Name");
			case ePosition:				return tr("Position");
			case eSize:					return tr("Size");
			case eGrantedAccess:		return tr("Granted access");
			case eFileShareAccess:		return tr("File share access");
			case eAttributes:			return tr("Attributes");
			case eObjectAddress:		return tr("Object address");
			case eOriginalName:			return tr("Original name");
			//case eHandleCount:			return tr("Handle count");
			//case eRefCount:				return tr("Reference count");
			//case ePagedSize:			return tr("Paged size");
			//case eNonPagedSize:			return tr("Non-paged size");
		}
	}
    return QVariant();
}

QVariant CHandleModel::GetDefaultIcon() const 
{ 
	return g_ExeIcon;
}