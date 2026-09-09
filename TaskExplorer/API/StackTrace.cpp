#include "stdafx.h"
#include "StackTrace.h"

CStackTrace::CStackTrace(quint64 ProcessId, quint64 ThreadId)
{
	m_ProcessId = ProcessId;
	m_ThreadId = ThreadId;
}

void CStackTrace::AddFrame(const SStackFrame& Frame)
{
	m_StackFrames.append(Frame);
}

const CStackTrace::SStackFrame& CStackTrace::GetFrame(int index) const
{
	static SStackFrame dummy;
	if (index > GetCount())
		return dummy;
	return m_StackFrames.at(index);
}