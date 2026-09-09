#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_SettingsWindow.h"

class CSettingsWindow : public QMainWindow
{
	Q_OBJECT

public:
	CSettingsWindow(QWidget *parent = Q_NULLPTR);
	~CSettingsWindow();

signals:
	void OptionsChanged();

public slots:
	void apply();
	void accept();
	void reject();

private slots:
	void			OnCertChanged();
	void			OnSerialChanged();
	void			OnGetCert();
	void			OnStartEval();
	void			OnCertData(const QByteArray& Certificate, const QVariantMap& Params);

	void OnChangeColor(QListWidgetItem* pItem);
	void OnChange();

	void OnSelectUiFont();
	void OnResetUiFont();

	void GetUpdates();
	void OnUpdateData(const QVariantMap& Data, const QVariantMap& Params);
	void OnUpdate(const QString& Channel);
	void UpdateUpdater();

	void OnTab();

	void OnServerToggled();
	void OnStartServer();
	void OnAddUser();
	void OnEditUser();
	void OnRemoveUser();
	void OnUserSelectionChanged();
	void OnStopServer();
	void OnGenerateServerKey();
	void OnShowServerKey();
	void OnForgetKeys();
	void OnEditMachine();
	void OnRemoveMachine();
	void OnMachineSelectionChanged();
	void OnRememberPassword();
	void OnDiscoveryToggled();

protected:
	void closeEvent(QCloseEvent *e);

	QVariantMap m_UpdateData;

	//
	// What was installed when the dialog opened. Kept so that apply() can tell
	// a changed setting from an unchanged one: reinstalling a service that
	// nobody touched would stop and restart it, and every viewer watching this
	// machine would see it drop.
	//
	struct SServerSetup* m_pServerWas = NULL;

	//
	// What Show put in the key field, when it was pressed.
	//
	// Kept so that revealing a key is not mistaken for setting one: the field is
	// read on apply, and text that is still exactly what was shown means nothing
	// was changed. Without it, looking at the key would reinstall the service and
	// every viewer watching this machine would see it drop.
	//
	QString m_ShownServerKey;

	void LoadServerSetup();
	void LoadServerUsers();
	void UpdateServerState();
	void ApplyServerSetup();
	void UpdateSavedKeys();
	void LoadMachines();

	//
	// ---- the supporter certificate ----
	//
	// The page is MajorPrivacy's License page, field for field: it is the same
	// certificate, from the same issuer, obtained the same way, and somebody who
	// has done this once should not have to work out where everything went.
	//
	// What it shows and what a certificate *means* are separate. Parsing,
	// signatures and dates are in TaskCommon/Support.cpp, which is not compiled
	// into the viewer at all - this page asks the remote module, because the
	// module is the thing that refuses, and a second reader here could show one
	// answer while the module acted on another.
	//
	void InitCertificate();
	void UpdateCertState();

	//
	// Writes what is in the text area to Certificate.dat and re-reads the state.
	// Called from OK, because a certificate typed and not applied is the one
	// thing on this page that would otherwise be lost silently.
	//
	bool ApplyCertificate();

	//
	// The text area shows a shortened certificate until somebody puts the cursor
	// in it, and shortens it again when they leave without changing anything.
	//
	// On focus rather than on the first keystroke: swapping the contents from
	// inside textChanged means the keystroke that triggered it has already been
	// applied to the text being replaced, so the first character somebody types
	// is eaten and the rest lands after the restored text.
	//
	bool eventFilter(QObject* pSource, QEvent* pEvent) override;

	QByteArray m_Certificate;			// what the file holds
	bool m_bCertChanged = false;
	bool m_bCertHidden = false;			// the text area is showing the short form

private:
	Ui::SettingsWindow ui;

};
