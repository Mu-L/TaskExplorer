#pragma once

#include "../corehelpers_global.h"

// The vswprintf_l shim lives in a Qt-free header so that STL-only code (and
// TaskHelper) can use it too.
#include "Compat.h"

COREHELPERS_EXPORT time_t GetTime();
// Was __time64_t, which is an MSVC extension. QDateTime::toMSecsSinceEpoch()
// returns qint64 and __time64_t is a 64-bit signed integer, so this is the same
// type on Windows and portable everywhere else.
COREHELPERS_EXPORT qint64 GetTimeMs();
COREHELPERS_EXPORT quint64 GetCurTick();


COREHELPERS_EXPORT quint64 GetRand64();
COREHELPERS_EXPORT QString GetRand64Str(bool forUrl = true);

COREHELPERS_EXPORT int	GetRandomInt(int iMin, int iMax);

COREHELPERS_EXPORT typedef QPair<QString,QString> StrPair;
COREHELPERS_EXPORT StrPair Split2(const QString& String, QString Separator = "=", bool Back = false);
COREHELPERS_EXPORT QStringList SplitStr(const QString& String, QString Separator);

COREHELPERS_EXPORT bool PathStartsWith(const QString& Path, const QString& Start);

typedef COREHELPERS_EXPORT QMultiMap<QString,QString> TArguments;
// The separators were spelled L';' / L'=' - wchar_t, which QChar no longer
// converts from implicitly (and which is 32-bit on Linux). u'' gives char16_t,
// the type QChar actually holds.
TArguments COREHELPERS_EXPORT GetArguments(const QString& Arguments, QChar Separator = u';', QChar Assigner = u'=', QString* First = NULL, bool bLowerKeys = false, bool bReadEsc = false);

COREHELPERS_EXPORT QString UnEscape(QString Text);

COREHELPERS_EXPORT QString FormatSize(quint64 Size, int Precision = 2);
__inline QString FormatSizeEx(quint64 Size, bool bEx) { return bEx && (Size == 0) ? QString() : FormatSize(Size); }
COREHELPERS_EXPORT QString FormatRate(quint64 Size, int Precision = 2);
__inline QString FormatRateEx(quint64 Size, bool bEx) { return bEx && (Size == 0) ? QString() : FormatRate(Size); }
COREHELPERS_EXPORT QString FormatUnit(quint64 Size, int Precision = 0);
COREHELPERS_EXPORT QString	FormatTime(quint64 Time, bool ms = false);
COREHELPERS_EXPORT QString	FormatNumber(quint64 Number);
__inline QString FormatNumberEx(quint64 Number, bool bEx) { return bEx && (Number == 0) ? QString() : FormatNumber(Number); }
COREHELPERS_EXPORT QString	FormatAddress(quint64 Address, int length = 16);
// a process or thread id, shown decimal and hex
COREHELPERS_EXPORT QString	FormatID(quint64 ID);


inline bool operator < (const QHostAddress &key1, const QHostAddress &key2)
{
	// Note: toIPv6Address also works for IPv4 addresses
	Q_IPV6ADDR ip1 = key1.toIPv6Address();
	Q_IPV6ADDR ip2 = key2.toIPv6Address();
    return memcmp(&ip1, &ip2, sizeof(Q_IPV6ADDR)) < 0;
}

template <typename T>
QVariantList toVariantList( const QList<T> &list )
{
    QVariantList newList;
    foreach( const T &item, list )
        newList << item;

    return newList;
}

template <typename T>
QList<T> reversed( const QList<T> & in ) {
    QList<T> result;
    result.reserve( in.size() ); // reserve is new in Qt 4.7
    std::reverse_copy( in.begin(), in.end(), std::back_inserter( result ) );
    return result;
}

template <class T>
class CScoped
{
public:
	CScoped(T* Val = NULL)			{m_Val = Val;}
	~CScoped()						{delete m_Val;}

	CScoped<T>& operator=(const CScoped<T>& Scoped)	{ASSERT(0); return *this;} // copying is explicitly forbidden
	CScoped<T>& operator=(T* Val)	{ASSERT(!m_Val); m_Val = Val; return *this;}

	inline T* Val() const			{return m_Val;}
	inline T* &Val()				{return m_Val;}
	inline T* Detache()				{T* Val = m_Val; m_Val = NULL; return Val;}
    inline T* operator->() const	{return m_Val;}
    inline T& operator*() const     {return *m_Val;}
    inline operator T*() const		{return m_Val;}

private:
	T*	m_Val;
};

COREHELPERS_EXPORT bool ReadFromDevice(QIODevice* dev, char* data, int len, int timeout = 5000);

//
// The widget builders and the colour helpers moved to GuiHelpers. The guard
// stays so that every `#include "Common.h"` in the front end still reaches
// them, and the collector - which does not define TE_WITH_WIDGETS - still
// cannot see a QtGui declaration.
//
#ifdef TE_WITH_WIDGETS
#include "CommonGui.h"
#endif

template <typename T>
QSet<T> ListToSet(const QList<T>& qList) { return QSet<T>(qList.begin(), qList.end()); }

template <typename T>
QList<T> SetToList(const QSet<T>& qSet) { return QList<T>(qSet.begin(), qSet.end()); }

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
bool COREHELPERS_EXPORT operator < (const QVariant& l, const QVariant& r);
#endif


#ifdef WIN32
COREHELPERS_EXPORT bool InitConsole(bool bCreateIfNeeded = true);
#endif