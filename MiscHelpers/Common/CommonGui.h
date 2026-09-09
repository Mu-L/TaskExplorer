#pragma once

#include "../guihelpers_global.h"

//
// Colour and image helpers, and builders for a user interface.
//
// These were declared in Common.h behind #ifdef TE_WITH_WIDGETS, which said
// "only where QtWidgets is in scope". Now that there are two libraries the
// guard has a file to be instead of a condition: this header is GuiHelpers',
// and the collector never includes it.
//
// Common.h still pulls it in when TE_WITH_WIDGETS is defined, so the front
// end's existing includes keep working unchanged.
//

typedef struct {
    double r;       // a fraction between 0 and 1
    double g;       // a fraction between 0 and 1
    double b;       // a fraction between 0 and 1
} my_rgb;

typedef struct {
    double h;       // angle in degrees
    double s;       // a fraction between 0 and 1
    double v;       // a fraction between 0 and 1
} my_hsv;

my_hsv GUIHELPERS_EXPORT rgb2hsv(my_rgb in);
my_rgb GUIHELPERS_EXPORT hsv2rgb(my_hsv in);

QRgb GUIHELPERS_EXPORT change_hsv_c(QRgb rgb, float fHue, float fSat, float fVal);
GUIHELPERS_EXPORT void GrayScale (QImage& Image);

GUIHELPERS_EXPORT QIcon MakeNormalAndGrayIcon(QIcon Icon);
GUIHELPERS_EXPORT QIcon MakeActionIcon(const QString& IconFile);
GUIHELPERS_EXPORT QAction* MakeAction(QToolBar* pParent, const QString& IconFile, const QString& Text = "");
GUIHELPERS_EXPORT QMenu* MakeMenu(QMenu* pParent, const QString& Text, const QString& IconFile = "");
GUIHELPERS_EXPORT QAction* MakeAction(QMenu* pParent, const QString& Text, const QString& IconFile = "");
GUIHELPERS_EXPORT QAction* MakeAction(QActionGroup* pGroup, QMenu* pParent, const QString& Text, const QVariant& Data);
GUIHELPERS_EXPORT void SetPaleteTexture(QPalette& palette, QPalette::ColorRole role, const QImage& image);
GUIHELPERS_EXPORT QAction* MakeActionCheck(QMenu* pParent, const QString& Text, const QVariant& Data, bool bTriState);

GUIHELPERS_EXPORT void SafeShow(QWidget* pWidget);
GUIHELPERS_EXPORT void SetFocus(QWidget* pWidget);

//
// From OtherFunctions.h, which is otherwise sorting, paths and file reads.
//
GUIHELPERS_EXPORT QIcon IconAddOverlay(const QIcon& Icon, const QString& Name, int Size = 24);
