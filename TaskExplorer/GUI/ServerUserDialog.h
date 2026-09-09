#pragma once

#include <QDialog>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QLabel>
#include <QDialogButtonBox>

#include "../SVC/ServerSetup.h"

//
// One account on the server that may log in over the network.
//
// Small enough to be built in code rather than in a .ui file: five widgets and
// one rule between them, and the rule is the only interesting part.
//
// ---- the empty password ----
//
// Leaving the password blank does not mean "no password". It means this account
// has none of its own and the operating system is asked instead - so the name
// has to be a real account on the server's machine, and whatever that machine
// says about it (expired, locked, disabled) is the answer.
//
// That is a big enough difference to be said on screen rather than documented,
// which is why the hint below the field changes as it is typed in. It was
// tempting to make it a checkbox instead; a checkbox would be a second control
// that has to agree with the field, and this way there is only the field.
//
class CServerUserDialog : public QDialog
{
	Q_OBJECT
public:
	//
	// A blank Name means a new account, which is the only thing that decides
	// whether the name may be edited: renaming an existing one would be a
	// remove and an add, and it would silently lose the stored password.
	//
	CServerUserDialog(const SServerUserRecord& User, QWidget* pParent = NULL);

	SServerUserRecord GetUser() const;

private slots:
	void OnPasswordChanged();

private:
	bool				m_bNew;
	SServerUserRecord	m_Was;

	QLineEdit*			m_pName;
	QComboBox*			m_pRole;
	QCheckBox*			m_pActions;
	QLineEdit*			m_pPassword;
	QLineEdit*			m_pConfirm;
	QCheckBox*			m_pSetPassword;
	QLabel*				m_pHint;
	QDialogButtonBox*	m_pButtons;

	void				UpdateHint();
};
