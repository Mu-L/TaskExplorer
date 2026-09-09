#pragma once
#include <qwidget.h>
#include "../../API/ProcessInfo.h"
#include "../../../MiscHelpers/Common/PanelView.h"
#include "../../../MiscHelpers/Common/TreeWidgetEx.h"
#include "../StatsView.h"

class CProcessModel;
class QSortFilterProxyModel;
class CServicesView;
class CEnvironmentView;

class CProcessView : public QWidget //CPanelView
{
	Q_OBJECT
public:
	CProcessView(QWidget *parent = 0);
	virtual ~CProcessView();

public slots:
	void					ShowProcesses(const QList<CProcessPtr>& Processes);
	void					ShowProcess(const CProcessPtr& pProcess);

	//
	// What the panel says when there is nothing selected.
	//
	// ShowProcess cannot answer it - it reads the process on its first line and
	// there is none - and leaving the last one on screen is worse than blank: a
	// page of numbers about a machine nobody is connected to reads exactly like a
	// page of numbers about one that is.
	//
	void					ClearProcess();
	void					Refresh();

private slots:
	void					OnResetColumns();
	void					OnColumnsChanged();


	//void					OnClicked(const QModelIndex& Index);
	void					OnCurrentChanged(const QModelIndex &current, const QModelIndex &previous);

	void					OnCertificate(const QString& Link);
	void					OnPolicy();
	void					OnPermissions();

protected:
	//virtual void				OnMenu(const QPoint& Point);
	//virtual QTreeView*			GetView()	{ return m_pStatsList; }
	//virtual QAbstractItemModel* GetModel()	{ return m_pStatsList->model(); }

	void					SyncModel();

	CProcessPtr				GetCurrentProcess();

	QList<CProcessPtr>		m_Processes;

private:
	QVBoxLayout*			m_pMainLayout;

	/*QScrollArea*			m_pScrollArea;

	QWidget*				m_pInfoWidget;
	QVBoxLayout*			m_pInfoLayout;*/

	QWidget*				m_pStackedWidget;
	QStackedLayout*			m_pStackedLayout;

	QWidget*				m_pOneProcWidget;
	QVBoxLayout*			m_pOneProcLayout;

	QGroupBox*				m_pFileBox;
	QGridLayout*			m_pFileLayout;
	QLabel*					m_pIcon;
	QLabel*					m_pProcessName;
	QLabel*					m_pCompanyName;
	QLabel*					m_pProcessVersion;
	QLabel*					m_pSubSystem;
	//
	// Says why this panel is empty when the target withheld the process. See
	// API_PROC_REDACTED.
	//
	QLabel*					m_pRedacted;

	QLineEdit*				m_pFilePath;
	// Shown only for a process running under Wine; see ShowProcess.
	QLabel*					m_pWineImageLabel = nullptr;
	QLineEdit*				m_pWineImage = nullptr;

	QLabel*					m_pFilePathNtLabel;
	QLineEdit*				m_pFilePathNt;

	// The Windows-only sub-tabs; -1 when the tab was never added. See ShowProcess.
	int						m_SecurityTab = -1;
	int						m_AppTab = -1;
	QTabWidget*				m_pTabWidget;

	QScrollArea*			m_pProcessArea;
	//QGroupBox*				m_pProcessBox;
	QWidget*				m_pProcessBox;
	QGridLayout*			m_pProcessLayout;
	QLineEdit*				m_pCmdLine;
	QLineEdit*				m_pCurDir;
	//
	// Both sets are built and share one grid row; ShowProcess shows whichever
	// belongs to the machine the selected process is on. They used to be built
	// one or the other from theSystem, which is *this* machine - so a Windows
	// viewer watching a Linux box got the desktop row it can never fill and no
	// user name row at all.
	//
	QLabel*					m_pDesktopLabel = nullptr;
	QLineEdit*				m_pDesktop = nullptr;
	QLabel*					m_pDPIAware = nullptr;
	QLabel*					m_pUserNameLabel = nullptr;
	QLineEdit*				m_pUserName = nullptr;
	QLineEdit*				m_pProcessId;
	QLineEdit*				m_pStartedBy;

	QWidget*				m_pMultiProcWidget;
	QVBoxLayout*			m_pMultiProcLayout;

	CProcessModel*			m_pProcessModel;
	QSortFilterProxyModel*	m_pSortProxy;

	QTreeViewEx*			m_pProcessList;
	QLabel*					m_pPEBAddressLabel = nullptr;
	QLineEdit*				m_pPEBAddress;
	QLabel*					m_ImageType;

	//QGroupBox*				m_pSecurityBox;
	QWidget*				m_pSecurityBox;
	QGridLayout*			m_pSecurityLayout;

	QLabel*					m_pVerification;
	QLabel*					m_pSigner;

	CPanelWidgetEx*			m_pMitigation;
	QLabel*					m_Protecetion;
	QCheckBox*				m_pNoWriteUp;
	QCheckBox*				m_pNoReadUp;
	QCheckBox*				m_pNoExecuteUp;
	QPushButton*			m_pPermissions;

	//QGroupBox*				m_pAppBox;
	QWidget*				m_pAppBox;
	QGridLayout*			m_pAppLayout;

	QLineEdit*				m_pAppID;
	QLineEdit*				m_pPackageName;
	//QLineEdit*				m_pPackageDataDir;

	CServicesView*			m_pServiceView;
	CEnvironmentView*		m_pEnvironmentView;


	CStatsView*				m_pStatsView;
};

