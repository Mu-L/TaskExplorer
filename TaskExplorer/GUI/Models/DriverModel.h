#pragma once
#include <qwidget.h>
#include "../MiscHelpers/Common/ListItemModel.h"
#include "../../API/DriverInfo.h"

class CDriverModel : public CListItemModel
{
    Q_OBJECT

public:
    CDriverModel(QObject *parent = 0);
	~CDriverModel();

	void			Sync(QMap<QString, CDriverPtr> DriverList);
	
	CDriverPtr		GetDriver(const QModelIndex &index) const;

    int				columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant		headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;

	enum EColumns
	{
		eDriver = 0,
		eImageBase,
		eImageSize,
		eDescription,
		eCompanyName,
		eVersion,
		eBinaryPath,

		// Filled by a Linux collector only; see CDriverInfo's platform surface.
		eRefCount,
		eUsedBy,
		eState,

		eCount
	};

protected:
	struct SDriverNode: SListNode
	{
		SDriverNode(const QVariant& Id) : SListNode(Id) {}

		CDriverPtr			pDriver;
	};

	virtual SListNode* MkNode(const QVariant& Id) { return new SDriverNode(Id); }
};