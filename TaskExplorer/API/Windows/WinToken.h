#pragma once
#include <qobject.h>
#include "../../../MiscHelpers/Common/Status.h"
#include "../ProcessInfo.h"
#include "../AbstractInfo.h"
#include "../TokenInfo.h"

#undef GetUserName

class CWinToken : public CTokenInfo
{
	Q_OBJECT

	TRACK_OBJECT(CWinToken)
public:
	CWinToken(QObject *parent = nullptr);
	virtual ~CWinToken();

	static CWinToken* NewSystemToken(const CSystemPtr& pSystem);
	static CWinToken* TokenFromProcess(const CSystemPtr& pSystem, void* QueryHandle);
	static CWinToken* TokenFromHandle(const CSystemPtr& pSystem, quint64 ProcessId, quint64 HandleId);
	static CWinToken* TokenFromThread(const CSystemPtr& pSystem, quint64 ThreadId);
	static CWinToken* OriginalToken(const CSystemPtr& pSystem, quint64 ProcessId);
	static CWinToken* OriginalToken(const CSystemPtr& pSystem, quint64 ProcessId, quint64 ThreadId);

	virtual QString			GetUserName() const { QReadLocker Locker(&m_Mutex); return m_UserName; }
	virtual QString			GetContainerName() const { QReadLocker Locker(&m_Mutex); return m_ContainerName; }
	virtual QByteArray		GetUserSid(bool bReal = false) const { QReadLocker Locker(&m_Mutex); if(bReal && m_IsAppContainer == 2) return m_OwnerSid; return m_UserSid; }
	virtual QString			GetSidString() const { QReadLocker Locker(&m_Mutex); return m_SidString; }
	virtual bool			IsAppContainer() const { QReadLocker Locker(&m_Mutex); return m_IsAppContainer != 0; }
	virtual quint32			GetSessionId() const { QReadLocker Locker(&m_Mutex); return m_SessionId; }
	virtual QString			GetOwnerName() const { QReadLocker Locker(&m_Mutex); return m_OwnerName; }
	virtual QByteArray		GetOwnerSid() const { QReadLocker Locker(&m_Mutex); return m_OwnerSid; }
	virtual QString			GetGroupName() const { QReadLocker Locker(&m_Mutex); return m_GroupName; }
	virtual QByteArray		GetGroupSid() const { QReadLocker Locker(&m_Mutex); return m_GroupSid; }

	virtual bool			IsElevated() const { QReadLocker Locker(&m_Mutex); return m_Elevated; }
	virtual int				GetElevationType() const { QReadLocker Locker(&m_Mutex); return m_ElevationType; }
	virtual quint32			GetIntegrityLevel() const { QReadLocker Locker(&m_Mutex); return m_IntegrityLevel; }
	virtual STATUS			SetIntegrityLevel(quint32 IntegrityLevel) const;
	virtual int				GetVirtualization() const { QReadLocker Locker(&m_Mutex); return m_Virtualization; }




	virtual QMap<QByteArray, SGroup> GetGroups() const { QReadLocker Locker(&m_Mutex); return m_Groups; }
	virtual QMap<QString, SPrivilege> GetPrivileges() const { QReadLocker Locker(&m_Mutex); return m_Privileges; }


	virtual bool			IsVirtualizationAllowed() const { QReadLocker Locker(&m_Mutex); return (m_Virtualization & VIRTUALIZATION_ALLOWED) != 0; }
	virtual bool			IsVirtualizationEnabled() const { QReadLocker Locker(&m_Mutex); return (m_Virtualization & VIRTUALIZATION_ENABLED) != 0; }
	virtual STATUS			SetVirtualizationEnabled(bool bSet);

	virtual STATUS			PrivilegeAction(const SPrivilege& Privilege, EAction Action, bool bForce = false);
	virtual STATUS			GroupAction(const SGroup& Group, EAction Action);

	virtual CSecurityEditablePtr GetSecurityObject(bool bDefaultToken = false) const;

	virtual QSharedPointer<CTokenInfo> GetLinkedToken();

	virtual SAdvancedInfo GetAdvancedInfo();

	virtual SContainerInfo GetContainerInfo();


	virtual QMap<QByteArray, SCapability> GetCapabilities();

	virtual QMap<QString, SAttribute> GetClaims(bool DeviceClaims);

	virtual QMap<QString, SAttribute> GetAttributes();

	virtual QSet<EDangerousFlags> GetDangerousFlags() const { QReadLocker Locker(&m_Mutex); return m_DangerousFlags; }
	enum EQueryType
	{
		eProcess = 0,
		eLinked,
		eOriginalPrimary,
		eOriginalThread,
		eHandle,
		eThread
	};

public slots:
	virtual void OnSidResolved(const QByteArray& SID, const QString& Name);

protected:
	friend class CWinProcess;
	friend class CTokenView;

	bool InitStaticData();
	bool UpdateDynamicData(bool MonitorChange = true, bool IsOrWasRunning = false);
	bool UpdateExtendedData();

	QString		m_UserName;
	QString		m_ContainerName;
	QByteArray	m_UserSid;
	QString		m_SidString;
	int			m_IsAppContainer;
	QString		m_OwnerName;
	QByteArray	m_OwnerSid;
	QString		m_GroupName;
	QByteArray	m_GroupSid;
	quint32		m_SessionId;

	bool		m_Elevated;
	int			m_ElevationType;
	quint32		m_IntegrityLevel;
	int			m_Virtualization;

	enum ETokenState
	{
		eNotInitialized = 0,
		eNotYetLocked,
		eInitialized,
		eHasChanged
	}			m_TokenState;

	QMap<QByteArray, SGroup> m_Groups;
	QMap<QString, SPrivilege> m_Privileges;
	QSet<EDangerousFlags> m_DangerousFlags;
	
private:
	void SetDangerousFlag(EDangerousFlags Flag, bool Set);

	struct SWinToken*		m;
};


typedef QSharedPointer<CWinToken> CWinTokenPtr;
