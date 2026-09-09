#pragma once
#include "../taskcore_global.h"
#include <qobject.h>

class TASKCORE_EXPORT CStackTrace : public QSharedData
{
	TRACK_OBJECT(CStackTrace)
public:
	CStackTrace(quint64 ProcessId, quint64 ThreadId);

	quint64 GetThreadId()	const			{ return m_ThreadId; }
	quint64 GetProcessId()	const			{ return m_ProcessId; }

	
	void Clear()							{ m_StackFrames.clear(); }


	int	GetCount() const					{ return m_StackFrames.count(); }

	//
	// Why there are no frames, when there are none. An empty trace with no
	// reason is simply a thread that was not walked; one with a reason is a
	// failure the view should put in front of the user.
	//
	void SetFailure(const STATUS& Failure)	{ m_Failure = Failure; }
	STATUS GetFailure() const				{ return m_Failure; }

	struct SStackFrame
	{
		SStackFrame()
		{
			PcAddress = ReturnAddress = FrameAddress = StackAddress = BStoreAddress = 0;
			Params[0] = Params[1] = Params[2] = Params[3] = 0;
			Flags = 0;
			LineNumber = 0;
			bNoUnwindInfo = false;
			ManagedDisplacement = 0;
		}

		QString Symbol;
		quint64 PcAddress;
		quint64 ReturnAddress;
		quint64 FrameAddress;
		quint64 StackAddress;
		quint64 BStoreAddress;
		quint64 Params[4];
		quint32 Flags;

		//
		// Where the frame is in the source, when the symbols say. Kept as the
		// two values they are rather than as a line of text.
		//
		QString FileName;
		quint32 LineNumber;

		//
		// A frame the unwinder had to guess at, and a managed frame's native
		// caller. Both are things to say about the symbol, not part of it.
		//
		bool    bNoUnwindInfo;
		quint64 ManagedDisplacement;
		QString NativeSymbol;
	};

	void AddFrame(const SStackFrame& Frame);
	const SStackFrame& GetFrame(int index) const;

protected:

	quint64 m_ProcessId;
	quint64 m_ThreadId;
	STATUS  m_Failure;

	QList<SStackFrame>	m_StackFrames;
};

typedef QSharedDataPointer<CStackTrace> CStackTracePtr;
