#pragma once
#include "../../zlib/zlib.h"


#include "../corehelpers_global.h"


QByteArray COREHELPERS_EXPORT Pack(const QByteArray& Data);
QByteArray COREHELPERS_EXPORT Unpack(const QByteArray& Data);

bool COREHELPERS_EXPORT gzip_arr(QByteArray& in);
bool COREHELPERS_EXPORT IsgZiped(const QByteArray& zipped);
QByteArray COREHELPERS_EXPORT ungzip_arr(z_stream* &zS, QByteArray& zipped, bool bGZip = true, int iRecursion = 0);

void COREHELPERS_EXPORT clear_z(z_stream* &zS);
