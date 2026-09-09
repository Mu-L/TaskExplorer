#pragma once
#include <QDialog>
#include "../API/TaskStatus.h"

class QLineEdit;
class QLabel;
class QCheckBox;
class QDialogButtonBox;

//
// The one prompt the credential store ever raises.
//
// Two jobs in one dialog because they are the same question asked at two
// moments - "what is the password for the saved keys" and "what should it be" -
// and a user meets the second exactly once. A separate setup wizard for a single
// password field would be a whole screen nobody sees twice.
//
// It is deliberately not shown when the platform can open the store: see
// CCredentialStore::TryUnlock, which every caller runs first.
//
class CUnlockDialog : public QDialog
{
	Q_OBJECT

public:
	//
	// Opens the store, creating it if there is none, and returns whether it is
	// now unlocked. Everything - the prompt, the retry, the error box - happens
	// inside; callers have one question and get one answer.
	//
	static bool	Open(QWidget* pParent);

	CUnlockDialog(bool bCreating, QWidget* pParent = NULL);

	QString		GetPassword() const;
	bool		GetRemember() const;

private slots:
	void		OnChanged();

private:
	bool				m_bCreating;
	bool				m_bPlatformOffered;
	QLineEdit*			m_pPassword;
	QLineEdit*			m_pConfirm;
	QCheckBox*			m_pRemember;
	QLabel*				m_pHint;
	QDialogButtonBox*	m_pButtonBox;
};
