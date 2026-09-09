#include "stdafx.h"
#include "LinuxHeap.h"

CLinuxHeap::CLinuxHeap(QObject *parent)
	: CHeapInfo(parent)
{
}

CLinuxHeap::~CLinuxHeap()
{
}

quint32 CLinuxHeap::GetClass() const
{
	return 0;
}

quint32 CLinuxHeap::GetType() const
{
	return 0;
}

