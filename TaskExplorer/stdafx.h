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
#include <QtConcurrent>
#include <QHostInfo>

//
// ---- QtWidgets ----
//
// TaskCore does not draw anything: it collects, and hands values to whoever is
// looking. It links Qt6Core, Qt6Gui and Qt6Network and nothing else, which
// `dumpbin /imports TaskCore.dll` confirms - but it was still *compiling*
// against QtWidgets, because this header is shared and included everything.
//
// TE_WITH_WIDGETS is defined by the front end alone. The polarity is
// deliberate: a target that says nothing gets no widgets, so the headless core
// planned for phase 5 needs no change here to stay headless, and a stray
// QWidget in the collector becomes a compile error rather than something to
// find later.
//
// A few classes below are QtGui or QtCore rather than QtWidgets - QClipboard,
// QPainter, QScreen, QAction, QCloseEvent, QSortFilterProxyModel. They are in
// here anyway because nothing in the core uses them; the ones it does use are
// included above, explicitly.
//
#ifdef TE_WITH_WIDGETS

#include <QPixmap>
#include <QIcon>
#include <QImage>

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
#include <QSortFilterProxyModel>
#include <QStackedLayout>
#include <QTreeWidget>
#include <QFormLayout>
#include <QLineEdit>
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
#include <QProgressBar>
#include <QInputDialog>
#include <QToolTip>
#include <QColorDialog>
#include <QToolButton>
#include <QScreen>
#include <QActionGroup>

#endif // TE_WITH_WIDGETS

#include <QRegularExpression>

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

#ifdef _DEBUG
#define SAFE_MODE
#endif

#include "../MiscHelpers/Common/DebugHelpers.h"

#include "../MiscHelpers/Common/ObjectTracker.h"

#include "taskcore_global.h"
#include "API/TaskStatus.h"

#define USING_QT

// USE_QEXTWIDGETS lives in MiscHelpers/guihelpers_global.h - see the note there
// for why it cannot be set per front end.

//
// The settings live in TaskCore: everything below the GUI reads them, and with
// the core in its own module the definition has to be on that side. main() still
// creates the object and assigns it.
//
extern TASKCORE_EXPORT class CSettings*		theConf;