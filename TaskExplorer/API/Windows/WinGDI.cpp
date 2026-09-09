#include "stdafx.h"
#include "WinGDI.h"
#include "ProcessHacker.h"
#define GDI_HANDLE_UNIQUE(Handle) ((ULONG)(Handle >> GDI_HANDLE_INDEX_BITS) & GDI_HANDLE_INDEX_MASK)


CWinGDI::CWinGDI(QObject *parent) : CGdiInfo(parent)
{
	m_Object = -1;
}

CWinGDI::~CWinGDI()
{
}

PPH_STRING PhpGetGdiHandleInformation(_In_ ULONG Handle)
{
    HGDIOBJ handle;

    handle = (HGDIOBJ)UlongToPtr(Handle);

    switch (GDI_CLIENT_TYPE_FROM_HANDLE(Handle))
    {
    case GDI_CLIENT_BITMAP_TYPE:
    case GDI_CLIENT_DIBSECTION_TYPE:
        {
            BITMAP bitmap;

            if (GetObject(handle, sizeof(BITMAP), &bitmap))
            {
                return PhFormatString(
                    L"Width: %u, Height: %u, Depth: %u",
                    bitmap.bmWidth,
                    bitmap.bmHeight,
                    bitmap.bmBitsPixel
                    );
            }
        }
        break;
    case GDI_CLIENT_BRUSH_TYPE:
        {
            LOGBRUSH brush;

            if (GetObject(handle, sizeof(LOGBRUSH), &brush))
            {
                return PhFormatString(
                    L"Style: %u, Color: 0x%08x, Hatch: 0x%Ix",
                    brush.lbStyle,
                    _byteswap_ulong(brush.lbColor),
                    brush.lbHatch
                    );
            }
        }
        break;
    case GDI_CLIENT_EXTPEN_TYPE:
        {
            EXTLOGPEN pen;

            if (GetObject(handle, sizeof(EXTLOGPEN), &pen))
            {
                return PhFormatString(
                    L"Style: 0x%x, Width: %u, Color: 0x%08x",
                    pen.elpPenStyle,
                    pen.elpWidth,
                    _byteswap_ulong(pen.elpColor)
                    );
            }
        }
        break;
    case GDI_CLIENT_FONT_TYPE:
        {
            LOGFONT font;

            if (GetObject(handle, sizeof(LOGFONT), &font))
            {
                return PhFormatString(
                    L"Face: %s, Height: %d",
                    font.lfFaceName,
                    font.lfHeight
                    );
            }
        }
        break;
    case GDI_CLIENT_PALETTE_TYPE:
        {
            USHORT count;

            if (GetObject(handle, sizeof(USHORT), &count))
            {
                return PhFormatString(
                    L"Entries: %u",
                    (ULONG)count
                    );
            }
        }
        break;
    case GDI_CLIENT_PEN_TYPE:
        {
            LOGPEN pen;

            if (GetObject(handle, sizeof(LOGPEN), &pen))
            {
                return PhFormatString(
                    L"Style: %u, Width: %u, Color: 0x%08x",
                    pen.lopnStyle,
                    pen.lopnWidth.x,
                    _byteswap_ulong(pen.lopnColor)
                    );
            }
        }
        break;
    }

    return NULL;
}


bool CWinGDI::InitData(quint32 index, struct _GDI_HANDLE_ENTRY* handle, const QString& ProcessName)
{
	QWriteLocker Locker(&m_Mutex);

	m_ProcessName = ProcessName;

	m_ProcessId = handle->Owner.ProcessId;

	m_HandleId = GDI_MAKE_HANDLE(index, handle->Unique);

	m_GdiType = DecodeGdiType(m_HandleId);

	m_Object = (quint64)handle->Object;
	m_Informations = CastPhString(PhpGetGdiHandleInformation(m_HandleId));

	return true;
}

quint32 CWinGDI::DecodeGdiType(quint32 HandleId)
{
	ulong Unique = GDI_HANDLE_UNIQUE(HandleId);
	switch (GDI_CLIENT_TYPE_FROM_UNIQUE(Unique))
	{
	case GDI_CLIENT_ALTDC_TYPE:			return eGdiAltDc;
	case GDI_CLIENT_BITMAP_TYPE:		return eGdiBitmap;
	case GDI_CLIENT_BRUSH_TYPE:			return eGdiBrush;
	case GDI_CLIENT_CLIENTOBJ_TYPE:		return eGdiClientObj;
	case GDI_CLIENT_DIBSECTION_TYPE:	return eGdiDibSection;
	case GDI_CLIENT_DC_TYPE:			return eGdiDc;
	case GDI_CLIENT_EXTPEN_TYPE:		return eGdiExtPen;
	case GDI_CLIENT_FONT_TYPE:			return eGdiFont;
	case GDI_CLIENT_METADC16_TYPE:		return eGdiMetaDc16;
	case GDI_CLIENT_METAFILE_TYPE:		return eGdiMetafile;
	case GDI_CLIENT_METAFILE16_TYPE:	return eGdiMetafile16;
	case GDI_CLIENT_PALETTE_TYPE:		return eGdiPalette;
	case GDI_CLIENT_PEN_TYPE:			return eGdiPen;
	case GDI_CLIENT_REGION_TYPE:		return eGdiRegion;
	}
	return eGdiUnknown;
}