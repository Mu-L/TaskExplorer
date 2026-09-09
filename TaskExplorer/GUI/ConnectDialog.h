#pragma once
#include <QDialog>
#include "../../MiscHelpers/Common/Credentials.h"

class QComboBox;
class QLineEdit;
class QLabel;
class QDialogButtonBox;
class QTimer;

//
// Where a machine to watch is named.
//
// Two fields rather than one, because the two answer different questions: the
// address is how to reach the daemon and may change when a box moves or a pipe
// is renamed, while the name is what the branch in the tree is called and is
// what the user recognises. Conflating them - which is what the one-line
// QInputDialog this replaces did - means a machine loses its identity the
// moment its address changes.
//
class CConnectDialog : public QDialog
{
	Q_OBJECT

public:
	CConnectDialog(QWidget* parent = NULL);

	//
	// Opens on an existing machine, to change it rather than to reach it.
	//
	// The same form, because it asks the same questions and a second one would
	// drift from this. What differs is what OK means: the name of the machine
	// being edited is not a clash with itself, and nothing connects.
	//
	// Returns whether anything was changed.
	//
	static bool	Edit(const QString& Name, QWidget* pParent);

	QString		GetName() const;

	//
	// The machine this dialog is editing, empty when it is not editing one.
	// UpdateOk asks, so that a name is only a clash when it is somebody else's.
	//
	QString		m_EditingName;
	QString		GetAddress() const;

	//
	// Empty for a local address, which authenticates by who the caller is and
	// has nothing to ask for. Never kept anywhere: what is typed here is used
	// for this connection and lives only as long as it does - see NEXT.md 5.6
	// for where it will be possible to keep it.
	//
	SCredentials GetCredentials() const;

	//
	// Whether the key should be kept for next time. Answered by the dialog
	// rather than acted on by it: nothing is saved until the connection has
	// actually worked, because a key that was mistyped is not worth
	// remembering.
	//
	bool		GetRemember() const;

private slots:
	void		OnTargetPicked(int Index);
	void		OnAddressChanged(const QString& Text);
	void		OnCredentialsChanged();
	void		OnRemember();
	void		FillTargets();

private:
	void		UpdateOk();
	void		FillFromStore();

	QComboBox*	m_pSaved;
	QWidget*	m_pSavedLabel;
	QLineEdit*	m_pAddress;
	QLineEdit*	m_pName;
	QLineEdit*	m_pPsk;
	QLineEdit*	m_pUser;
	QLineEdit*	m_pPassword;
	class QCheckBox* m_pRemember;
	QWidget*	m_pPskRow;
	QWidget*	m_pUserRow;
	QWidget*	m_pPasswordRow;
	QLabel*		m_pHint;
	class QFormLayout* m_pForm;
	QDialogButtonBox* m_pButtonBox;

	//
	// Whether the name still follows the address. It stops the moment the user
	// types a name of their own, and does not start again - a name that was
	// chosen deliberately must not be overwritten by a later edit to the
	// address.
	//
	bool		m_bNameFollowsAddress;
};
