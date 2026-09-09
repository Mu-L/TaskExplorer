#pragma once

#include "../guihelpers_global.h"

struct PixmapEntry {
	QString name;
	QPixmap pixmap;
};

typedef QVector<PixmapEntry> PixmapEntryList;

GUIHELPERS_EXPORT PixmapEntryList extractIcons(const QString &sourceFile, bool large);
GUIHELPERS_EXPORT PixmapEntryList extractShellIcons(const QString &sourceFile, bool addOverlays);