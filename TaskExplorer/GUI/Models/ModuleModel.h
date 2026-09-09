#pragma once
#include <qwidget.h>
#include "../../API/ModuleInfo.h"
#include "../../../MiscHelpers/Common/TreeItemModel.h"
class CModuleModel : public CTreeItemModel
{
    Q_OBJECT

public:
    CModuleModel(QObject *parent = 0);
	~CModuleModel();

	QSet<quint64>	Sync(const QMap<quint64, CModulePtr>& ModuleList);

	CModulePtr		GetModule(const QModelIndex &index) const;

	int				columnCount(const QModelIndex &parent = QModelIndex()) const;
	QVariant		headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;

	enum EColumns
	{
		eModule = 0,
		eModuleFile,
		eBaseAddress,
		eSize,
		eDescription,
		eCompanyName,
		eVersion,
		eFileName,
		eType,
		eLoadCount,
		eVerificationStatus,
		eVerifiedSigner,
		eMitigations,
		eImageCoherency,
		eTimeStamp,
		eLoadTime,
		eLoadReason,
		eFileModifiedTime,
		eFileSize,
		eEntryPoint,
		eService,
		eParentBaseAddress,
		eOriginalName,
		eArchitecture,
		eEnclaveType,
		eEnclaveBaseAddress,
		eEnclaveSize,
		eCount
	};

protected:
	struct SModuleNode: STreeNode
	{
		SModuleNode(const QVariant& Id) : STreeNode(Id) {}

		CModulePtr			pModule;
	};

	virtual STreeNode*		MkNode(const QVariant& Id) { return new SModuleNode(Id); }


	QList<QVariant>			MakeModPath(const CModulePtr& pModule, const QMap<quint64, CModulePtr>& ModuleList);
	bool					TestModPath(const QList<QVariant>& Path, const CModulePtr& pModule, const QMap<quint64, CModulePtr>& ModuleList, int Index = 0);
	void					Sync(const CModuleInfo* pModule, QList<QVariant> Path, QSet<quint64> &Added, QMap<QList<QVariant>, QList<STreeNode*> > &New, QHash<QVariant, STreeNode*> &Old);
	virtual QVariant		GetDefaultIcon() const;
};