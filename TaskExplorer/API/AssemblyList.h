#pragma once
#include "../taskcore_global.h"
#include <qobject.h>
#include <QThread>

class TASKCORE_EXPORT CAssemblyList : public QSharedData
{
public:
	CAssemblyList();

	void Clear()							{ m_Assemblies.clear(); }

	void AddAssembly(quint64 ID, quint64 ParentID, QString Structure, QString FileName, QString Flags, QString NativePath);

	int	GetCount() const					{ return m_Assemblies.count(); }

	struct SAssembly
	{
		quint64 ID;
		quint64 ParentID;

		QString Structure;
		QString FileName;
		QString Flags;
		QString NativePath;
	};

	const SAssembly& GetAssembly(int index) const;

protected:

	quint64 m_ProcessId;
	quint64 m_ThreadId;

	QList<SAssembly>	m_Assemblies;
};

typedef QSharedDataPointer<CAssemblyList> CAssemblyListPtr;

//
// Collecting the list, which only the machine running the process can do.
//
// Walking a CLR's loaded assemblies means reading that process's memory, so it
// happens on a worker and reports back - the same shape a remote collector will
// have, where the wait is a round trip rather than a memory read. The view only
// ever sees this interface, so it does not know which it is talking to.
//
class TASKCORE_EXPORT CAssemblyEnumerator : public QThread
{
	Q_OBJECT
public:
	CAssemblyEnumerator(QObject* parent = nullptr) : QThread(parent) {}

signals:
	void				Assemblies(const CAssemblyListPtr& List);
	void				Finished();
};
