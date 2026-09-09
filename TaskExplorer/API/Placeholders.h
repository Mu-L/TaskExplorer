#pragma once
#include <qstring.h>

//
// Names the target could not supply.
//
// A name is a value: it comes from the machine being watched, and it is sorted,
// filtered and searched on exactly as it stands. But when there is no name to
// be had, something has to sit in the column anyway - and "Unknown process",
// "Waiting connections" or "Resolving..." are sentences, which belong to the
// viewer like every other sentence in this program.
//
// So the core writes a placeholder instead. Every one begins with '*', which no
// name from either platform does: neither Windows nor Linux permits it in a
// file name, and no SID or account name contains it. That makes the test a
// viewer runs on every name it displays a single character comparison - see
// IsPlaceholderName below - and only a name that passes it is looked at further.
//
// A placeholder that needs a value carries it after a colon, so
// MakePlaceholder(TE_NAME_UNKNOWN_PROCESS, 1234) reads "*UNKNOWN_PROCESS:1234*".
//

#define TE_PLACEHOLDER_CHAR				'*'

#define TE_NAME_UNKNOWN_PROCESS			"UNKNOWN_PROCESS"		// optional argument: the pid
#define TE_NAME_SYSTEM_IDLE_PROCESS		"SYSTEM_IDLE_PROCESS"
#define TE_NAME_WAITING_CONNECTIONS		"WAITING_CONNECTIONS"
#define TE_NAME_UNKNOWN_TRACER			"UNKNOWN_TRACER"
#define TE_NAME_RESOLVING				"RESOLVING"
#define TE_NAME_NOT_RESOLVED			"NOT_RESOLVED"
#define TE_NAME_UNKNOWN_SID				"UNKNOWN_SID"
#define TE_NAME_UNKNOWN_FILE			"UNKNOWN_FILE"
#define TE_NAME_UNKNOWN_ACTION			"UNKNOWN_ACTION"
#define TE_NAME_UNKNOWN_PATH			"UNKNOWN_PATH"

__inline QString MakePlaceholder(const char* Name)
{
	return QString(QLatin1Char(TE_PLACEHOLDER_CHAR)) + QLatin1String(Name) + QLatin1Char(TE_PLACEHOLDER_CHAR);
}

__inline QString MakePlaceholder(const char* Name, quint64 Argument)
{
	return QString(QLatin1Char(TE_PLACEHOLDER_CHAR)) + QLatin1String(Name)
		 + QLatin1Char(':') + QString::number(Argument) + QLatin1Char(TE_PLACEHOLDER_CHAR);
}

//
// The cheap test, meant to be run on every name on its way to the screen: one
// character, and almost always the answer is no.
//
__inline bool IsPlaceholderName(const QString& Name)
{
	return !Name.isEmpty() && Name.at(0) == QLatin1Char(TE_PLACEHOLDER_CHAR);
}

//
// Splits a placeholder into its name and the argument it carries, if any.
// Only worth calling once IsPlaceholderName has said yes.
//
__inline bool SplitPlaceholder(const QString& Placeholder, QString& Name, QString& Argument)
{
	if (!IsPlaceholderName(Placeholder) || !Placeholder.endsWith(QLatin1Char(TE_PLACEHOLDER_CHAR)) || Placeholder.length() < 3)
		return false;

	const QString Body = Placeholder.mid(1, Placeholder.length() - 2);

	const int Colon = Body.indexOf(QLatin1Char(':'));
	if (Colon < 0)
	{
		Name = Body;
		Argument.clear();
	}
	else
	{
		Name = Body.left(Colon);
		Argument = Body.mid(Colon + 1);
	}
	return true;
}
