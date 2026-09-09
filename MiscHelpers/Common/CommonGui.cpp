/*
 * Builders for a user interface.
 *
 * These were in Common.cpp, next to the formatting and container helpers that
 * everything uses. That was fine while there was one program; it stopped being
 * fine once the collector became a library of its own.
 *
 * A static library is linked one object file at a time: anything referencing
 * FormatAddress pulled in the whole of Common.obj, and with it every QToolBar
 * and QMenu reference in these ten functions. TaskCore does not draw anything
 * and calls none of them, but it could not avoid carrying them - which is what
 * kept a headless build out of reach.
 *
 * Their declarations sit behind TE_WITH_WIDGETS in Common.h; this file is one
 * of the places that defines it.
 */

#include "stdafx.h"
#include "Common.h"

//
// SetFocus below asks the window manager to raise a window, which on Windows
// means SetForegroundWindow. Common.cpp had this include for the same reason
// and kept it for its own Windows-only tail.
//
#ifdef WIN32
#include <windows.h>
#endif

//
// ---- colour and image helpers ----
//
// These came from Common.cpp. rgb2hsv and hsv2rgb touch no Qt type at all, but
// they exist only to serve change_hsv_c, and a group of four that is used as
// one belongs in one file.
//

my_hsv rgb2hsv(my_rgb in)
{
    my_hsv      out;
    double      min, max, delta;

    min = in.r < in.g ? in.r : in.g;
    min = min  < in.b ? min  : in.b;

    max = in.r > in.g ? in.r : in.g;
    max = max  > in.b ? max  : in.b;

    out.v = max;                                // v
    delta = max - min;
    if (delta < 0.00001)
    {
        out.s = 0;
        out.h = 0; // undefined, maybe nan?
        return out;
    }
    if( max > 0.0 ) { // NOTE: if Max is == 0, this divide would cause a crash
        out.s = (delta / max);                  // s
    } else {
        // if max is 0, then r = g = b = 0              
        // s = 0, h is undefined
        out.s = 0.0;
        out.h = NAN;                            // its now undefined
        return out;
    }
    if( in.r >= max )                           // > is bogus, just keeps compilor happy
        out.h = ( in.g - in.b ) / delta;        // between yellow & magenta
    else
    if( in.g >= max )
        out.h = 2.0 + ( in.b - in.r ) / delta;  // between cyan & yellow
    else
        out.h = 4.0 + ( in.r - in.g ) / delta;  // between magenta & cyan

    out.h *= 60.0;                              // degrees

    if( out.h < 0.0 )
        out.h += 360.0;

    return out;
}

my_rgb hsv2rgb(my_hsv in)
{
    double      hh, p, q, t, ff;
    long        i;
    my_rgb      out;

    if(in.s <= 0.0) {       // < is bogus, just shuts up warnings
        out.r = in.v;
        out.g = in.v;
        out.b = in.v;
        return out;
    }
    hh = in.h;
    if(hh >= 360.0) hh = 0.0;
    hh /= 60.0;
    i = (long)hh;
    ff = hh - i;
    p = in.v * (1.0 - in.s);
    q = in.v * (1.0 - (in.s * ff));
    t = in.v * (1.0 - (in.s * (1.0 - ff)));

    switch(i) {
    case 0:
        out.r = in.v;
        out.g = t;
        out.b = p;
        break;
    case 1:
        out.r = q;
        out.g = in.v;
        out.b = p;
        break;
    case 2:
        out.r = p;
        out.g = in.v;
        out.b = t;
        break;

    case 3:
        out.r = p;
        out.g = q;
        out.b = in.v;
        break;
    case 4:
        out.r = t;
        out.g = p;
        out.b = in.v;
        break;
    case 5:
    default:
        out.r = in.v;
        out.g = p;
        out.b = q;
        break;
    }
    return out;     
}

uint8_t clamp(float v) //define a function to bound and round the input float value to 0-255
{
    if (v < 0)
        return 0;
    if (v > 255)
        return 255;
    return (uint8_t)v;
}

// http://beesbuzz.biz/code/16-hsv-color-transforms
QRgb change_hsv_c(QRgb rgb, float fHue, float fSat, float fVal)
{
	float in_r = qRed(rgb);
	float in_g = qGreen(rgb);
	float in_b = qBlue(rgb);

    const float cosA = fSat*cos(fHue*3.14159265f/180); //convert degrees to radians
    const float sinA = fSat*sin(fHue*3.14159265f/180); //convert degrees to radians

    //helpers for faster calc //first 2 could actually be precomputed
    const float aThird = 1.0f/3.0f;
    const float rootThird = sqrtf(aThird);
    const float oneMinusCosA = (1.0f - cosA);
    const float aThirdOfOneMinusCosA = aThird * oneMinusCosA;
    const float rootThirdTimesSinA =  rootThird * sinA;
    const float plus = aThirdOfOneMinusCosA +rootThirdTimesSinA;
    const float minus = aThirdOfOneMinusCosA -rootThirdTimesSinA;

    //calculate the rotation matrix
    float matrix[3][3] = {
        {   cosA + oneMinusCosA / 3.0f  , minus                         , plus                          },
        {   plus                        , cosA + aThirdOfOneMinusCosA   , minus                         },
        {   minus                       , plus                          , cosA + aThirdOfOneMinusCosA   }
    };

    //Use the rotation matrix to convert the RGB directly
    float out_r = clamp((in_r*matrix[0][0] + in_g*matrix[0][1] + in_b*matrix[0][2])*fVal);
    float out_g = clamp((in_r*matrix[1][0] + in_g*matrix[1][1] + in_b*matrix[1][2])*fVal);
    float out_b = clamp((in_r*matrix[2][0] + in_g*matrix[2][1] + in_b*matrix[2][2])*fVal);
    return qRgb(out_r, out_g, out_b);
}

void GrayScale (QImage& Image)
{
	if (Image.depth () == 32)
	{
		uchar* r = (Image.bits ());
		uchar* g = (Image.bits () + 1);
		uchar* b = (Image.bits () + 2);

		uchar* end = (Image.bits() + Image.sizeInBytes());
		while (r != end)
		{
			*r = *g = *b = (((*r + *g) >> 1) + *b) >> 1; // (r + b + g) / 3

			r += 4;
			g += 4;
			b += 4;
		}
	}
	else
	{
		for (int i = 0; i < Image.colorCount (); i++)
		{
			uint r = qRed (Image.color (i));
			uint g = qGreen (Image.color (i));
			uint b = qBlue (Image.color (i));

			uint gray = (((r + g) >> 1) + b) >> 1;

			Image.setColor (i, qRgba (gray, gray, gray, qAlpha (Image.color (i))));
		}
	}
}

QIcon MakeNormalAndGrayIcon(QIcon Icon)
{
	QImage Image = Icon.pixmap(Icon.availableSizes().first()).toImage();
	Icon.addPixmap(QPixmap::fromImage(Image), QIcon::Normal);
	GrayScale(Image);
	Icon.addPixmap(QPixmap::fromImage(Image), QIcon::Disabled);
	return Icon;
}

QIcon MakeActionIcon(const QString& IconFile)
{
	QImage Image(IconFile);
	QIcon Icon;
	Icon.addPixmap(QPixmap::fromImage(Image), QIcon::Normal);
	GrayScale(Image);
	Icon.addPixmap(QPixmap::fromImage(Image), QIcon::Disabled);
	return Icon;
}

QAction* MakeAction(QToolBar* pParent, const QString& IconFile, const QString& Text)
{
	QAction* pAction = new QAction(Text, pParent);
	pAction->setIcon(MakeActionIcon(IconFile));
	pParent->addAction(pAction);
	return pAction;
}

QMenu* MakeMenu(QMenu* pParent, const QString& Text, const QString& IconFile)
{
	if(!IconFile.isEmpty())
	{
		QImage Image(IconFile);
		QIcon Icon;
		Icon.addPixmap(QPixmap::fromImage(Image), QIcon::Normal);
		GrayScale(Image);
		Icon.addPixmap(QPixmap::fromImage(Image), QIcon::Disabled);
		return pParent->addMenu(Icon, Text);
	}
	return pParent->addMenu(Text);
}

QAction* MakeAction(QMenu* pParent, const QString& Text, const QString& IconFile)
{
	QAction* pAction = new QAction(Text, pParent);
	if(!IconFile.isEmpty())
	{
		QImage Image(IconFile);
		QIcon Icon;
		Icon.addPixmap(QPixmap::fromImage(Image), QIcon::Normal);
		GrayScale(Image);
		Icon.addPixmap(QPixmap::fromImage(Image), QIcon::Disabled);
		pAction->setIcon(Icon);
	}
	pParent->addAction(pAction);
	return pAction;
}

QAction* MakeAction(QActionGroup* pGroup, QMenu* pParent, const QString& Text, const QVariant& Data)
{
	QAction* pAction = new QAction(Text, pParent);
	pAction->setCheckable(true);
	pAction->setData(Data);
	pAction->setActionGroup(pGroup);
	pParent->addAction(pAction);
	return pAction;
}

QAction* MakeActionCheck(QMenu* pParent, const QString& Text, const QVariant& Data, bool bTriState)
{
	QCheckBox *checkBox = new QCheckBox(Text, pParent);
	if(bTriState) checkBox->setTristate(true);
	QWidgetAction *pAction = new QWidgetAction(pParent);
	QObject::connect(checkBox, SIGNAL(stateChanged(int)), pAction, SLOT(trigger()));
	pAction->setDefaultWidget(checkBox);
	pAction->setData(Data);
	pParent->addAction(pAction);
	return pAction;
}

void SetPaleteTexture(QPalette& palette, QPalette::ColorRole role, const QImage& image)
{
	for (int i = 0; i < QPalette::NColorGroups; ++i) {
		QBrush brush(image);
		brush.setColor(palette.brush(QPalette::ColorGroup(i), role).color());
		palette.setBrush(QPalette::ColorGroup(i), role, brush);
	}
}

//
// avoid flashing a bright white window when in dark mode
//

void SafeShow(QWidget* pWidget) {
	static bool Lock = false;
	pWidget->setProperty("windowOpacity", 0.0);
	if (Lock == false) {
		Lock = true;
		pWidget->show();
		QApplication::processEvents(QEventLoop::ExcludeSocketNotifiers);
		Lock = false;
	} else
		pWidget->show();
	pWidget->setProperty("windowOpacity", 1.0);
}

void SetFocus(QWidget* pWidget)
{
	pWidget->setWindowState((pWidget->windowState() & ~Qt::WindowMinimized) | Qt::WindowActive);
#ifdef WIN32
	SetForegroundWindow((HWND)pWidget->winId());
#else
	// X11 window managers generally honour activateWindow(); under Wayland
	// focus stealing is blocked outright, so this may be a no-op there.
	pWidget->raise();
	pWidget->activateWindow();
#endif
}

//
// From OtherFunctions.cpp, which is otherwise sorting, paths and file reads -
// all of it core. This was the one function in it that draws.
//
QIcon IconAddOverlay(const QIcon& Icon, const QString& Name, int Size)
{
	QPixmap overlay = QPixmap(Name).scaled(Size, Size, Qt::IgnoreAspectRatio, Qt::SmoothTransformation);

	QPixmap base = Icon.pixmap(32, 32).scaled(32, 32, Qt::IgnoreAspectRatio, Qt::SmoothTransformation);
	QPixmap result(base.width(), base.height());
	result.fill(Qt::transparent); // force alpha channel
	QPainter painter(&result);
	painter.drawPixmap(0, 0, base);

	painter.drawPixmap(32 - Size, 32 - Size, overlay);
	return QIcon(result);
}
