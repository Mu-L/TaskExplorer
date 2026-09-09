#pragma once
#include <qwidget.h>
#include <QDialog>
#include <QTreeWidget>
#include <QLabel>
#include <QPushButton>
#include <QCheckBox>
#include <QTabBar>
#include <QDialogButtonBox>
#include "../API/SecurityInfo.h"

//
// The permissions dialog.
//
// Replaces PhEditSecurity, which showed Windows' own securable-object editor.
// That one drove a live handle through a callback; this one is handed a
// CSecurityEditable and works entirely on the descriptor it returns, so the
// same dialog serves a local process and - once the protocol exists - a remote
// one, without knowing which it is looking at.
//
// The layout follows the shape people already know: principals on top, the
// rights of whichever principal is selected below. A tab switches between the
// access list and the audit list, which are the same shape - entries naming a
// principal and a mask - differing in what the two checkbox columns mean and
// in the success/failure choice the audit list carries per entry.
//
class CSecurityDialog : public QDialog
{
	Q_OBJECT
public:
	CSecurityDialog(const CSecurityEditablePtr& pObject, QWidget* parent = 0);
	virtual ~CSecurityDialog();

private slots:
	void				OnListChanged(int Index);
	void				OnPrincipalChanged();
	void				OnRightToggled(QTreeWidgetItem* pItem, int Column);
	void				OnAuditFlagChanged();
	void				OnChangeOwner();
	void				OnAdd();
	void				OnRemove();
	void				OnApply();
	void				OnOk();

private:
	bool				Save();
	void				Load();
	void				ShowOwner();
	void				FillPrincipals();
	void				FillRights();

	//
	// Rebuilding a list from inside that list's own signal deletes the item
	// the signal is still reporting on, so a toggle updates in place.
	//
	void				UpdateRightChecks();
	void				UpdatePrincipalRow(int Index);
	int					CurrentAce() const;
	void				SetStatus(const QString& Text, bool bError = false);

	//
	// Which list is on screen, and whether it may be edited. Each list is
	// read-only on its own terms: the access list when it held entries this
	// dialog cannot describe, the audit list likewise - see SkippedAces.
	//
	bool				IsAuditing() const;
	QList<SAce>&		CurrentList();
	const QList<SAce>&	CurrentList() const;
	bool				IsListReadOnly() const;

	//
	// A permission row can be on, off, or - for a general right like "Full
	// control" whose bits are only partly present - somewhere in between.
	//
	enum EColumns
	{
		ePermission = 0,
		eAllow,			// "Success" while the audit list is shown
		eDeny,			// "Failure" while the audit list is shown
		eColumnCount
	};

	CSecurityEditablePtr	m_pObject;
	SSecurityInfo			m_Info;
	QList<SAccessRight>		m_Rights;

	//
	// True once anything has been changed, so Apply and the close prompt only
	// fire when there is something to write.
	//
	bool					m_bDirty;

	//
	// Set when the access list held entries this dialog cannot describe, which
	// makes that list read-only - see SSecurityInfo::SkippedAces.
	//
	bool					m_bReadOnly;

	// set while filling a list, so the change handlers ignore themselves
	bool					m_bFilling;

	QLabel*					m_pHeader;
	QLabel*					m_pOwner;
	QPushButton*			m_pOwnerChange;
	QTabBar*				m_pLists;
	QTreeWidget*			m_pPrincipals;
	QWidget*				m_pAuditFlags;
	QCheckBox*				m_pAuditSuccess;
	QCheckBox*				m_pAuditFailure;
	QTreeWidget*			m_pRights;
	QPushButton*			m_pAdd;
	QPushButton*			m_pRemove;
	QLabel*					m_pStatus;
	QDialogButtonBox*		m_pButtons;
};
