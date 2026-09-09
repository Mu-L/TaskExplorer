#pragma once
#include <qwidget.h>
#include "../MiscHelpers/Common/ListItemModel.h"
#include "../../API/GdiInfo.h"

class CGDIModel : public CListItemModel
{
    Q_OBJECT

public:
    CGDIModel(QObject *parent = 0);
	~CGDIModel();

	void			Sync(QMap<quint64, CGdiPtr> List);
	
	CGdiPtr		GetGDI(const QModelIndex &index) const;

    int				columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant		headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;

	enum EColumns
	{
		eHandle = 0,
		eType,
		eObject,
		eProcess,
		eInformation,
		eCount
	};

protected:
	struct SGDINode: SListNode
	{
		SGDINode(const QVariant& Id) : SListNode(Id), iColor(0) {}

		CGdiPtr			pGDI;

		int					iColor;
	};

	virtual SListNode* MkNode(const QVariant& Id) { return new SGDINode(Id); }
};