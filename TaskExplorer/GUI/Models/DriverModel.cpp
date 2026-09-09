#include "stdafx.h"
#include "../TaskExplorer.h"
#include "DriverModel.h"
#include "../../../MiscHelpers/Common/Common.h"
CDriverModel::CDriverModel(QObject *parent)
:CListItemModel(parent)
{
}

CDriverModel::~CDriverModel()
{
}

void CDriverModel::Sync(QMap<QString, CDriverPtr> DriverList)
{
	QList<SListNode*> New;
	QHash<QVariant, SListNode*> Old = m_Map;

	foreach (const CDriverPtr& pDriver, DriverList)
	{
		QVariant ID = pDriver->GetBinaryPath();

		int Row = -1;
		QHash<QVariant, SListNode*>::iterator I = Old.find(ID);
		SDriverNode* pNode = I != Old.end() ? static_cast<SDriverNode*>(I.value()) : NULL;
		if(!pNode)
		{
			pNode = static_cast<SDriverNode*>(MkNode(ID));
			pNode->Values.resize(columnCount());
			pNode->pDriver = pDriver;
			New.append(pNode);
		}
		else
		{
			I.value() = NULL;
			Row = GetRow(pNode);
		}

		int Col = 0;
		bool State = false;
		bool Changed = false;

		CModulePtr pModule = pDriver->GetModuleInfo();
		for(int section = 0; section < columnCount(); section++)
		{
			if (m_ColumnsOff.contains(section))
				continue; // ignore columns which are hidden

			QVariant Value;
			switch(section)
			{
				case eDriver:				Value = pDriver->GetFileName(); break;
				case eImageBase:			Value = pDriver->GetImageBase(); break;
				case eImageSize:			Value = pDriver->GetImageSize(); break;
				case eDescription:			Value = pModule ? pModule->GetFileInfo("Description") : ""; break;
				case eCompanyName:			Value = pModule ? pModule->GetFileInfo("CompanyName") : ""; break;
				case eVersion:				Value = pModule ? pModule->GetFileInfo("FileVersion") : ""; break;
				case eBinaryPath:			Value = pDriver->GetBinaryPath(); break;
				case eRefCount:				Value = pDriver->GetRefCount(); break;
				case eUsedBy:				Value = pDriver->GetUsedBy(); break;
				case eState:				Value = pDriver->GetState(); break;
			}

			SDriverNode::SValue& ColValue = pNode->Values[section];

			if (ColValue.Raw != Value)
			{
				Changed = true;
				ColValue.Raw = Value;

				switch (section)
				{
                    case eDriver: break;
					case eImageBase:	ColValue.Formatted = FormatAddress(Value.toULongLong()); break;
					case eImageSize:	ColValue.Formatted = FormatSize(Value.toULongLong()); break;			
				}
			}

			if(State != Changed)
			{
				if(State && Row != -1)
					emit dataChanged(createIndex(Row, Col), createIndex(Row, section-1));
				State = Changed;
				Col = section;
			}
			Changed = false;
		}
		if(State && Row != -1)
			emit dataChanged(createIndex(Row, Col, pNode), createIndex(Row, columnCount()-1, pNode));

	}

	CListItemModel::Sync(New, Old);
}

CDriverPtr CDriverModel::GetDriver(const QModelIndex &index) const
{
	if (!index.isValid())
        return CDriverPtr();

	SDriverNode* pNode = static_cast<SDriverNode*>(index.internalPointer());
	return pNode->pDriver;
}

int CDriverModel::columnCount(const QModelIndex &parent) const
{
	return eCount;
}

QVariant CDriverModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
	{
		switch(section)
		{
			//
			// "Name", not "Driver": one tab serves both kinds of machine now,
			// and what it lists is a driver on Windows and a kernel module on
			// Linux. The neutral word is true of both.
			//
			case eDriver:				return tr("Name");
			case eImageBase:			return tr("Image base");
			case eImageSize:			return tr("Image size");
			case eDescription:			return tr("Description");
			case eCompanyName:			return tr("Company name");
			case eVersion:				return tr("Version");
			case eBinaryPath:			return tr("Binary path");
			case eRefCount:				return tr("Ref count");
			case eUsedBy:				return tr("Used by");
			case eState:				return tr("State");
		}
	}
    return QVariant();
}
