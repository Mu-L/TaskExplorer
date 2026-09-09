#pragma once
#include <QDialog>
#include <QTreeWidget>
#include <QLineEdit>
#include <QLabel>
#include <QDialogButtonBox>

//
// Choose an account.
//
// Windows has a picker for this, but it is a COM object bound to the machine
// the process is running on, so it can only ever offer local answers. This one
// asks the target: the well-known SIDs are resolved through it, and the local
// users, groups and privileged accounts come from its own enumeration. A name
// it does not list can still be typed, which is how domain accounts get in.
//
class CPrincipalPicker : public QDialog
{
	Q_OBJECT
public:
	CPrincipalPicker(QWidget* parent = 0);

	QString				GetSid() const			{ return m_Sid; }
	QString				GetName() const			{ return m_Name; }

private slots:
	void				OnFilter(const QString& Text);
	void				OnSelectionChanged();
	void				OnDoubleClicked();
	void				OnAccept();

private:
	void				Load();
	void				Add(const QString& Name, const QString& Sid, const QString& Kind, const QString& Comment = QString());

	enum EColumns
	{
		eName = 0,
		eKind,
		eSid,
		eComment,
		eColumnCount
	};

	QLineEdit*			m_pFilter;
	QTreeWidget*		m_pList;
	QLineEdit*			m_pManual;
	QLabel*				m_pStatus;
	QDialogButtonBox*	m_pButtons;

	//
	// Every SID already offered, so the same account listed by two of the
	// enumerations - a privileged account is usually also a local user - only
	// appears once.
	//
	QSet<QString>		m_Seen;

	QString				m_Sid;
	QString				m_Name;
};
