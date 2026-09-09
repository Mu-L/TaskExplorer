#pragma once
#include <qobject.h>
#include "AbstractInfo.h"

#include "ModuleInfo.h"

class TASKCORE_EXPORT CDriverInfo: public CAbstractInfoEx
{
	Q_OBJECT

	TRACK_OBJECT(CDriverInfo)
public:
	CDriverInfo(QObject *parent = nullptr);
	virtual ~CDriverInfo();

	virtual QString GetFileName() const				{ QReadLocker Locker(&m_Mutex); return m_FileName; }
	virtual QString GetBinaryPath() const			{ QReadLocker Locker(&m_Mutex); return m_BinaryPath; }

	virtual CModulePtr GetModuleInfo()				{ QReadLocker Locker(&m_Mutex); return m_pModuleInfo; }

	//
	// ---- platform surface ----
	//
	// Everything either platform can report, so the models never need to know
	// which one answered. An implementation without the notion does not
	// override; the default below is the honest answer, and whether a column
	// built on it is worth showing is decided by GetOsType()/HasCapability().
	//
	virtual quint64 GetImageBase() const			{ return 0; }
	virtual quint64 GetImageSize() const			{ return 0; }

	//
	// What Linux reports about a loaded module and Windows has no equivalent
	// for: how many things hold it, which modules those are, and whether it is
	// settled or still coming or going.
	//
	// A Windows driver simply does not override these, and the columns built on
	// them stay empty - which is the same arrangement as the two above, and why
	// one view can serve both. See CDriversView::OnResetColumns for which of
	// them are worth showing on which machine.
	//
	virtual quint32 GetRefCount() const				{ return 0; }
	virtual QString GetUsedBy() const				{ return QString(); }
	virtual QString GetState() const				{ return QString(); }

protected:

	QString							m_FileName;
	QString							m_BinaryPath;

	CModulePtr						m_pModuleInfo;
};

typedef QSharedPointer<CDriverInfo> CDriverPtr;
typedef QWeakPointer<CDriverInfo> CDriverRef;