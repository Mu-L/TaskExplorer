#pragma once

#include <QtWidgets/QMainWindow>

//
// Forward declared rather than included: this header is pulled in by the moc
// output and by whoever opens the dialog, and none of them need the whole of
// the system interface to hold a pointer to one.
//
class CSystemAPI;

#include "ui_RunAsDialog.h"

class CRunAsDialog : public QMainWindow
{
	Q_OBJECT

public:
	CRunAsDialog(CSystemAPI* pSystem = NULL, quint64 PID = 0, QWidget *parent = Q_NULLPTR);
	~CRunAsDialog();

public slots:
	void accept();
	void reject();

	void OnBrowse();
	void OnUserName(const QString& userName);

protected:
	void closeEvent(QCloseEvent *e);
	bool event(QEvent* event);

	quint64			m_PID;

private:
	//
	// Which machine the program is to start on.
	//
	// Everything this dialog offers describes that machine and comes from it -
	// the accounts, the sessions, the desktops, even whether an account needs a
	// password. See the note above CSystemAPI::GetRunAsChoices, which says as
	// much: a dialog cannot fill itself in.
	//
	// Null means this computer, which is what every caller meant before there
	// was another one to mean.
	//
	CSystemAPI*			m_pSystem;

	Ui::RunAsDialog ui;
};
