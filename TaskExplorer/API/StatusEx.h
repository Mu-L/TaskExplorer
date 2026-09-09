#pragma once
#include "TaskStatus.h"
#include <QObject>


template <class T>
class CResult : public CStatus
{
public:
	CResult(const T& value = T()) : CStatus()
	{
		v = value;
	}
	//
	// A native status, not a message code - see CStatus::Native. The parameter
	// is an int and always was, which is precisely the case SMsgCode exists to
	// keep out of the code argument.
	//
	CResult(int Status, const T& value = T()) : CStatus(CStatus::Native(Status))
	{
		v = value;
	}
	//
	// These used to call the base's Attach(&other), which is both protected and
	// typed for the internal SMsg*, not CStatus*. MSVC never diagnosed it
	// because CResult is never instantiated; GCC checks template bodies before
	// instantiation and rejects it.
	//
	// Deferring to the base class copy constructor / assignment operator is
	// what was meant - they already do the refcounted attach correctly.
	//
	CResult(const CStatus& other) : CStatus(other)
	{
	}
	CResult(const CResult& other) : CStatus(other)
	{
		v = other.v;
	}

	CResult& operator=(const CResult& Status)
	{
		CStatus::operator=(Status);
		v = Status.v;
		return *this;
	}

	__inline T& GetValue() { return v; }

	//__inline T* operator->() const {return &v;}

private:
	T v;
};

#define RESULT(x) CResult<x>
#define RETURN(x) return CResult(x) // requires C++17


#define ERROR_OK (1)
#define OP_ASYNC (2)
#define OP_CONFIRM (3)
#define OP_CANCELED (4)

class CAsyncProgress : public QObject
{
	Q_OBJECT
public:
	//
	// OP_ASYNC is a native marker meaning "still running", not a code of ours -
	// hence Native() rather than a message code. Same for OP_CANCELED below.
	//
	CAsyncProgress() : m_Status(CStatus::Native(OP_ASYNC)), m_Canceled(false) {}

	void Cancel() { m_Canceled = true; emit Canceled(); }
	bool IsCanceled() { return m_Canceled; }

	void ShowMessage(const QString& text) { emit Message(text);}
	void SetProgress(int value) { emit Progress(value); }
	void Finish(STATUS status) { m_Status = m_Canceled ? CStatus::Native(OP_CANCELED) : status; emit Finished(); }

	STATUS GetStatus() { return m_Status; }
	bool IsFinished() { return m_Status.GetStatus() != OP_ASYNC; }

signals:
	//void Progress(int procent);
	void Message(const QString& text);
	void Progress(int value);
	void Canceled();
	void Finished();

protected:
	volatile bool m_Canceled;
	STATUS m_Status;
};

typedef QSharedPointer<CAsyncProgress> CAsyncProgressPtr;

#define PROGRESS CResult<CAsyncProgressPtr>