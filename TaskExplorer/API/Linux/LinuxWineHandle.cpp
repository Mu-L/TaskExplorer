#include "stdafx.h"
#include "LinuxWineHandle.h"
#include "LinuxHandle.h"
#include "../../../MiscHelpers/Common/Variant.h"
#include "../../../MiscHelpers/Common/XVariant.h"

//
// The names wineserver gives its object kinds.
//
// Taken from the object types it compiles in rather than from anything read at
// run time - see the header for why that is sound. The order fixes the indexes,
// so entries are appended and never inserted: an index that changes meaning
// between two builds would leave a viewer filtering on the wrong kind without
// anything looking wrong.
//
// eOther is last and is where an unrecognised name lands. Such a handle still
// reports its real name in the type column - only the filter groups it.
//
static const char* const c_WineTypes[] =
{
	"Other",
	"Process",
	"Thread",
	"File",
	"Directory",
	"SymbolicLink",
	"Key",
	"Event",
	"Mutant",
	"Semaphore",
	"Timer",
	"Section",
	"Token",
	"Job",
	"Desktop",
	"WindowStation",
	"Device",
	"Driver",
	"IoCompletion",
	"DebugObject",
	"Type",
	//
	// Appended, not inserted: the ones above were written from wineserver's
	// compiled-in types and this one from what a prefix actually reported -
	// measured, thirteen kinds in use across ten processes and this the only one
	// the list did not already have.
	//
	"KeyedEvent",
};

int CWineHandle::TypeIndex(const QString& Name)
{
	for (int i = 1; i < (int)(sizeof(c_WineTypes) / sizeof(c_WineTypes[0])); i++)
	{
		if (Name.compare(QLatin1String(c_WineTypes[i]), Qt::CaseInsensitive) == 0)
			return c_TypeBase + i;
	}
	return c_TypeBase;	// eOther
}

QList<CSystemAPI::SHandleType> CWineHandle::GetTypes()
{
	QList<CSystemAPI::SHandleType> Types;

	for (int i = 0; i < (int)(sizeof(c_WineTypes) / sizeof(c_WineTypes[0])); i++)
	{
		CSystemAPI::SHandleType Type;
		Type.Index = c_TypeBase + i;
		Type.Name = QLatin1String(c_WineTypes[i]);
		//
		// The second group: offered only while a Wine process is selected,
		// because on any other process here not one of these can occur.
		//
		Type.Group = 1;
		Types.append(Type);
	}

	return Types;
}

CWineHandle::CWineHandle(QObject* parent)
	: CHandleInfo(parent)
{
}

bool CWineHandle::Apply(quint64 Pid, const CVariant& Entry)
{
	CVariant Value;
	if (!Entry.Find("Handle", Value))
		return false;

	QWriteLocker Locker(&m_Mutex);

	m_ProcessId = Pid;
	m_HandleId = Value.To<quint64>();

	if (Entry.Find("Access", Value))		m_Access = Value.To<quint32>();
	if (Entry.Find("Attributes", Value))	m_Attributes = Value.To<quint32>();
	if (Entry.Find("Object", Value))		m_Object = Value.To<quint64>();

	//
	// An object with no name is the normal case, not a failure: an event created
	// without one is unnamed for its whole life. Empty is the honest answer and
	// the Hide Unnamed filter is what it is for.
	//
	m_FileName = Entry.Find("Name", Value) ? XVariant(Value).AsQStr() : QString();

	m_TypeName = Entry.Find("Type", Value) ? XVariant(Value).AsQStr() : QString();
	m_TypeIndex = (quint32)TypeIndex(m_TypeName);

	//
	// A type the helper could not read at all - a handle it duplicated but could
	// not query. Named rather than left blank, so the column does not look like
	// a bug in the reader.
	//
	if (m_TypeName.isEmpty())
		m_TypeName = "Other";

	return true;
}

STATUS CWineHandle::Close(bool bForce)
{
	Q_UNUSED(bForce);
	return ERR(TE_NotSupported);
}
