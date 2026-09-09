#pragma once
#include <qwidget.h>
#include "../MiscHelpers/Common/ListItemModel.h"
#include "../../API/ServiceInfo.h"

class CServiceModel : public CListItemModel
{
    Q_OBJECT

public:
    CServiceModel(QObject *parent = 0);
	~CServiceModel();

	void			Sync(QMap<QString, CServicePtr> ServiceList);
	
	CServicePtr		GetService(const QModelIndex &index) const;

    int				columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant		headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;
	void			SetShowKernelServices(bool bShow) { m_ShowDriver = bShow; }
	enum EColumns
	{
		eService = 0,
		eStatus,
		ePID,
		//
		// Both are meaningful on either platform: the display name is systemd's
		// unit Description, and the type is the unit suffix - which matters now
		// that the list holds timers, sockets and mounts as well as services.
		//
		eDisplayName,
		eType,
		eStartType,
		eFileName,
		eErrorControl,
		eGroupe,
		eDescription,
		eCompanyName,
		eVersion,
		eBinaryPath,

		//eKeyModificationTime,

		eVerificationStatus,
		eVerifiedSigner,

		eExitCode,

		eCount
	};

protected:
	struct SServiceNode: SListNode
	{
		SServiceNode(const QVariant& Id) : SListNode(Id) {}

		int					iColor;
		CServicePtr			pService;
	};

	virtual SListNode* MkNode(const QVariant& Id) { return new SServiceNode(Id); }

	virtual QVariant GetDefaultIcon() const;
	bool				m_ShowDriver;
};