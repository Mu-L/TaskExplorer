#include "stdafx.h"
#include "Status.h"

//
// Who knows how to put a platform's failure into words.
//
// Installed rather than called directly, because this library is below the one
// that knows: on Windows the wording comes out of PhGetStatusMessage, on Linux
// out of strerror and the helper's own table, and neither is reachable from
// here. TaskCore sets it once at start-up.
//
// Nothing installs it in TaskHelper or UpdUtil, which have no use for a
// sentence and no platform layer to ask - there a native failure keeps its
// number, which is all those two would have printed anyway.
//
static CStatus::FNativeFormatter g_pNativeFormatter = NULL;

void CStatus::SetNativeFormatter(FNativeFormatter pFn)
{
	g_pNativeFormatter = pFn;
}

CStatus CStatus::Native(long Status)
{
	//
	// The wording is fetched here, on the machine that failed, and travels as an
	// argument rather than as the message - see the note at the top of Status.h.
	// Without a formatter the number goes on its own, which is a poor sentence
	// but an honest one.
	//
	const QString Text = g_pNativeFormatter
		? g_pNativeFormatter(Status)
		: QString("0x%1").arg((quint32)Status, 8, 16, QLatin1Char('0'));

	return CStatus(MH_Native, QVariantList() << Text, Status);
}
