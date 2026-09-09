#pragma once

#define _CRT_SECURE_NO_WARNINGS



// std includes
#include <string>
#include <sstream>
#include <deque>
#include <list>
#include <vector>
#include <map>
#include <set>
#include <memory>


// Qt includes
#include <QObject>
#include <QList>
#include <QVector>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QUrl>
#include <QFile>
#include <qglobal.h>
#include <QTime>
#include <QTimer>
#include <QTimerEvent>
#include <QThread>
#include <QProcess>
#include <QNetworkAccessManager>
#include <QNetworkCookieJar>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QNetworkProxy>
#include <QNetworkDiskCache>
#include <QTextStream>
#include <QFileInfo>
#include <QXmlStreamWriter>
#include <QLocalServer>
#include <QLocalSocket>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QBuffer>
#include <QDir>
#include <QTemporaryFile>
#include <QMutex>
#include <QMutexLocker>
#include <QReadWriteLock>
#include <QWaitCondition>
#include <QBitArray>
#include <QPointer>
#include <QSharedPointer>
#include <QFutureWatcher>
#include <QHostInfo>
#include <QSortFilterProxyModel>
#include <QIdentityProxyModel>
#include <QRandomGenerator>
#include <QElapsedTimer>

//
// ---- QtGui and QtWidgets ----
//
// Behind the same switch as everything else that draws. CoreHelpers is
// compiled without it and so cannot reach a widget header even by accident;
// GuiHelpers defines it. Both use this file as their precompiled header, and
// each gets its own PCH built from it.
//
#ifdef TE_WITH_WIDGETS

#include <QApplication>
#include <QClipboard>

#include <QMainWindow>
#include <QWidget>
#include <QHBoxLayout>
#include <QMenu>
#include <QAction>
#include <QSplitter>
#include <QTabWidget>
#include <QTextEdit>
#include <QLabel>
#include <QMenuBar>
#include <QStatusBar>
#include <QCloseEvent>
#include <QFileDialog>
#include <QMessageBox>
#include <QHeaderView>
#include <QToolBar>
#include <QScrollBar>
#include <QStyleFactory>
#include <QStackedLayout>
#include <QTreeWidget>
#include <QFormLayout>
#include <QLineEdit>
#include <QTextEdit>
#include <QWidgetAction>
#include <QCheckBox>
#include <QScrollArea>
#include <QDialogButtonBox>
#include <QStandardItemModel>
#include <QPainter>
#include <QGroupBox>
#include <QSpinBox>
#include <QComboBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSystemTrayIcon>
#include <QDesktopServices>
#include <QFileDialog>
#include <QProgressBar>
#include <QInputDialog>
#include <QToolTip>
#include <QColorDialog>
#include <QToolButton>
#include <QScreen>

#endif // TE_WITH_WIDGETS

//
// The serialisation moved here from TaskCore, and CBuffer/CVariant carry
// QByteArray and QVariant conveniences behind USING_QT. TaskExplorer/stdafx.h
// defines it; this one has to as well, or those members are declared to
// consumers but never emitted into CoreHelpers.dll - which on Windows is two
// unresolved externals and on Linux is silently nothing, since inline members
// there are simply emitted wherever they are used.
//
// TaskHelper deliberately does not define it: its own Qt-free stdafx.h comes
// first on its include path, and CBuffer without Qt is the whole point there.
//
#define USING_QT

// other includes

#define _T(x)      L ## x

#define STR2(X) #X
#define STR(X) STR2(X)

#define ARRSIZE(x)	(sizeof(x)/sizeof(x[0]))

#ifndef Max
#define Max(a,b)            (((a) > (b)) ? (a) : (b))
#endif

#ifndef Min
#define Min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

//#ifdef _DEBUG
//#define SAFE_MODE
//#endif

#include "Common/DebugHelpers.h"
