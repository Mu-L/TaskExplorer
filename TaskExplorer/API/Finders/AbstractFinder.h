#pragma once
#include "../../taskcore_global.h"

#include "../ProcessInfo.h"

class TASKCORE_EXPORT CAbstractFinder : public QThread
{
	Q_OBJECT

public:
	CAbstractFinder(QObject* parent);
	virtual ~CAbstractFinder();

	virtual void Cancel() { m_bCancel = true; }
	virtual bool IsCanceled() { return m_bCancel; }

	static CAbstractFinder* FindHandles(const QVariant& Type, const QRegularExpression& RegExp);
	static CAbstractFinder* FindModules(const QVariant& Type, const QRegularExpression& RegExp);

	struct SMemOptions
	{
		int MinLength;
		bool Unicode;
		bool ExtUnicode;
		// regions
		bool Private;
		bool Image;
		bool Mapped;
	};
	static CAbstractFinder* FindStrings(const SMemOptions& Options, const QRegularExpression& RegExp, const CProcessPtr& pProcess = CProcessPtr());

signals:
	void	Progress(float value, const QString& Info = QString());
	void	Results(QList<QSharedPointer<QObject>> List);
	void	Error(const STATUS& Error);
	void	Finished();

protected:
	bool	m_bCancel;

	// the system being searched - a finder always scans the machine it was
	// created for, and objects it produces have to carry that same owner
	//
	// Shared, not raw: a finder outlives a single refresh and hands the system
	// to every object it creates - see CAbstractInfo::SetSystem, which requires
	// one.
	//
	CSystemPtr	m_pSystem;
};