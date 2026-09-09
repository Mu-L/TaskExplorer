#pragma once
#include "../taskcore_global.h"
#include <qobject.h>
#include "AbstractInfo.h"

//
// A graphics object owned by a process.
//
// This was CWinGDI, and the GDI view reached it by casting a process to
// CWinProcess - which is a cast that cannot succeed once the process is a
// remote one, whatever platform the viewer is running on.
//
// Everything here is a value the collector has already worked out. The type in
// particular: on Windows it is encoded in the handle's own bits, and decoding
// it needs the object manager's macros, so it is decoded once where those
// macros exist and only the answer is stored.
//
// The notion is not Windows-only even though the name is. X11 and Wayland
// clients own drawables, pixmaps, regions and fonts in a compositor; a Linux
// backend that wanted to report them would fill in the same fields.
//
class TASKCORE_EXPORT CGdiInfo : public CAbstractInfoEx
{
	Q_OBJECT

	TRACK_OBJECT(CGdiInfo)
public:
	CGdiInfo(QObject *parent = nullptr);
	virtual ~CGdiInfo();

	virtual QString GetProcessName() const			{ QReadLocker Locker(&m_Mutex); return m_ProcessName; }
	virtual quint64 GetProcessId() const			{ QReadLocker Locker(&m_Mutex); return m_ProcessId; }
	virtual quint32 GetHandleId() const				{ QReadLocker Locker(&m_Mutex); return m_HandleId; }

	//
	// What the handle refers to. Named rather than numbered so a viewer can say
	// "Brush" without knowing the platform's encoding; GUI/TaskStrings.cpp
	// turns it into a word.
	//
	enum EGdiType
	{
		eGdiUnknown		= 0,
		eGdiAltDc,
		eGdiBitmap,
		eGdiBrush,
		eGdiClientObj,
		eGdiDibSection,
		eGdiDc,
		eGdiExtPen,
		eGdiFont,
		eGdiMetaDc16,
		eGdiMetafile,
		eGdiMetafile16,
		eGdiPalette,
		eGdiPen,
		eGdiRegion,
	};
	virtual quint32 GetGdiType() const				{ QReadLocker Locker(&m_Mutex); return m_GdiType; }

	virtual quint64 GetObject() const				{ QReadLocker Locker(&m_Mutex); return m_Object; }
	virtual QString GetInformations() const			{ QReadLocker Locker(&m_Mutex); return m_Informations; }

protected:
	QString			m_ProcessName;
	quint64			m_ProcessId = 0;
	quint32			m_HandleId = 0;
	quint32			m_GdiType = eGdiUnknown;
	quint64			m_Object = 0;
	QString			m_Informations;
};

typedef QSharedPointer<CGdiInfo> CGdiPtr;
typedef QWeakPointer<CGdiInfo> CGdiRef;
