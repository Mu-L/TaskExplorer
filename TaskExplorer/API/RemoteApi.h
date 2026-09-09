#pragma once
//
// A named guard as well as the pragma.
//
// This header is reached both as API/RemoteApi.h from inside TaskExplorer and
// as ../TaskExplorer/API/RemoteApi.h from inside TaskRemote, and on a build
// tree that lives on a 9p mount - WSL reading /mnt/c - GCC's #pragma once does
// not always recognise the two spellings as one file. The result is a
// redefinition error in the moc translation unit and nowhere else, which is a
// confusing way to find that out.
//
#ifndef TASKEXPLORER_API_REMOTEAPI_H
#define TASKEXPLORER_API_REMOTEAPI_H

#include "../taskcore_global.h"
#include "TaskStatus.h"
#include <QObject>
#include "../../MiscHelpers/Common/Credentials.h"
#include <QSet>
#include <QString>

class CSystemAPI;

//
// ---- watching a machine that is not this one ----
//
// Everything that can only be asked of a remote machine, as an interface rather
// than a class.
//
// The implementation lives in TaskRemote, which is a module the GUI loads if it
// is there and works without if it is not - so the same build can be shipped
// with or without the ability to connect to anything, and an installer can add
// it later by dropping the file in. Nothing above this line links it.
//
// Why an interface and not the class: the GUI used to say
// qobject_cast<CRemoteSystem*>(pSystem) to mean "is this a remote machine",
// which needs the class definition, its vtable and its typeinfo - and on Linux
// a module loaded RTLD_LOCAL does not share typeinfo, so that cast would have
// compiled and then silently returned null. CSystemAPI::GetRemote() answers the
// same question with a virtual call, which is one word in a vtable the header
// describes and both sides agree on.
//
class IRemoteSystem
{
public:
	virtual ~IRemoteSystem() {}

	//
	// The same object seen as a machine. Every system in the tree is a
	// CSystemAPI; this is how the two faces of one object are gone between
	// without a cast either way.
	//
	virtual CSystemAPI*		AsSystem() = 0;

	//
	// ---- the connection ----
	//
	virtual STATUS			Connect(const QString& Name, int TimeoutMs,
								const SCredentials& Cred) = 0;
	virtual void			Disconnect() = 0;
	virtual bool			IsConnected() const = 0;

	//
	// Retried from the cluster's timer, so it has to be callable without the
	// class - it used to be reached with invokeMethod and a method name, which
	// is a string the compiler does not check.
	//
	virtual void			TryReconnect() = 0;

	//
	// ---- who answered ----
	//
	virtual QString			GetAddress() const = 0;
	virtual bool			IsNetworkTransport() const = 0;
	virtual QString			GetMachineId() const = 0;
	virtual void			SetExpectedMachineId(const QString& Id) = 0;
	virtual QString			GetServerVersion() const = 0;
	virtual quint32			GetProtocolVersion() const = 0;
	virtual int				GetFeatureCount() const = 0;
	//
	// Whether the far side can answer one of CSystemAPI::EFeature. The
	// translation to a command id lives on the other side of this interface,
	// because the command ids are the module's business - see WireFeatureOf.
	//
	virtual bool			CanAnswer(quint32 Feature) const = 0;

	//
	// The same question asked in the protocol's own terms, for something that
	// is reporting on the protocol rather than using it - TaskConsole prints
	// the four characters of each id it got. Not for views: a view that names a
	// command id is a view that has to be changed when the wire is.
	//
	virtual bool			HasFeatureId(quint32 Command) const = 0;
	virtual quint64			GetConnectedSince() const = 0;
	virtual quint64			GetBytesReceived() const = 0;
	virtual qint64			GetTimeOffset() const = 0;

	//
	// Which processes the viewer has a detail tab open on, so that the rest are
	// not asked about every round.
	//
	virtual void			SetDetailWanted(const QSet<quint64>& Pids) = 0;

	//
	// The connection died: mark every list entry as gone so the views draw
	// them leaving, rather than leaving a branch that claims to be current.
	//
	virtual void			MarkEverythingGone() = 0;
};

//
// ---- the module ----
//
// What TaskRemote exports, and nothing else. Two functions and a number.
//
// The number is checked before the other two are called. It is not an ABI
// version in the sense of a plugin contract that outlives a release - TaskCore
// says of itself that it and the executables loading it are one unit built
// together, and this module is built with them. It is here to turn "somebody
// left an old TaskRemote next to a new TaskExplorer" from a crash into a
// message.
//
#define TASKREMOTE_ABI_VERSION	5

class CRemoteDiscovery;

extern "C"
{
	typedef quint32				(*FnRemoteAbiVersion)();
	typedef CSystemAPI*			(*FnCreateRemoteSystem)();
	typedef void				(*FnDestroyRemoteSystem)(CSystemAPI*);
	typedef CRemoteDiscovery*	(*FnCreateRemoteDiscovery)();
	typedef void				(*FnDestroyRemoteDiscovery)(CRemoteDiscovery*);
	typedef bool				(*FnProbeEndpoint)(const QString&);
	typedef quint64				(*FnCertificateState)(bool);
	typedef quint32				(*FnCertificateStatus)(bool);
	typedef QString				(*FnCertificateString)();
}

//
// ---- machines announcing themselves ----
//
// Listening for announcements is the module's job, and so is taking one apart.
// The cluster used to do both: it owned a CDiscovery and decoded the payload
// itself, reading API_AN_PORT and the rest straight out of a CVariant - which
// is a viewer parsing a wire format, and the last of that in TaskCore.
//
// It also ran on a build that could not connect to anything. Discovery only
// means something if a row in the list can be acted on, so without the module
// it was a multicast listener kept open for nothing.
//
// A QObject rather than a plain interface, because what crosses here is an
// event and the cluster wants it as a signal - the same reason CSystemAPI
// carries ConnectionLost. Only the three decoded fields cross; the packet does
// not.
//
class TASKCORE_EXPORT CRemoteDiscovery : public QObject
{
	Q_OBJECT
public:
	CRemoteDiscovery(QObject* parent = NULL) : QObject(parent) {}
	virtual ~CRemoteDiscovery() {}

	//
	// Groups, port and interval are settings and are read on the far side of
	// this call: they are named in terms of the protocol's own defaults, and
	// nothing here should have to know what those are.
	//
	virtual bool			Start(QString* pError) = 0;
	virtual void			Query() = 0;

signals:
	//
	// Address is "host:port" and ready to connect to, built from where the
	// packet came from rather than from anything inside it. The other two are
	// what the machine says about itself - unauthenticated claims, fit for a
	// label and nothing else.
	//
	void					Found(const QString& Address, const QString& HostName, const QString& MachineId);
};

//
// Finds the module, or reports that there is none.
//
// Loaded once, on the first ask, and never unloaded: a CSystemAPI it made may
// still be alive, and the tree holds those for the persistence window after a
// connection dies. Unloading under a live vtable is the one way this could
// crash, so it does not.
//
// IsAvailable() is what the GUI greys the "connect to machine" entries on. It
// answers without loading anything on the second and later calls.
//
class TASKCORE_EXPORT CRemoteLoader
{
public:
	static bool			IsAvailable();

	//
	// A new, unconnected remote machine, or null if there is no module.
	//
	// The caller owns it and must give it back to Destroy - not to delete.
	// Everything here is /MD and one heap, so delete would work today, but the
	// module made it and the module knows how: this one calls deleteLater,
	// because the socket lives in the object's own thread and has to be shut
	// down while that thread still runs.
	//
	static CSystemAPI*	Create();
	static void			Destroy(CSystemAPI* pSystem);

	//
	// A discovery feed, or null when there is no module - in which case there is
	// nothing to discover *for*, which is the point.
	//
	static CRemoteDiscovery*	CreateDiscovery();
	static void					DestroyDiscovery(CRemoteDiscovery* pDiscovery);

	//
	// Whether something is answering on a local endpoint - a connect and an
	// immediate close.
	//
	// Behind the module because it is the transport doing it, and because the
	// answer is only worth having if the connection it predicts could be made:
	// with no module, "is there a daemon I could use" is no whatever is
	// listening. The caller resolves the name and passes it, so the endpoint it
	// probes and the one it goes on to connect to are the same string.
	//
	static bool					ProbeEndpoint(const QString& Name);

	//
	// Why there is no module, for the one place that says so out loud.
	// Empty when there is one.
	//
	static QString		GetError();

	//
	// What the module makes of the supporter certificate.
	//
	// Asked of the module rather than read here, even though both would read
	// the same file: the module is what refuses, so the module is what should
	// say why. A viewer that checked for itself could show one answer while
	// CreateRemoteSystem acted on another.
	//
	// Zero with no module, which reads the same as "no certificate" and is the
	// right answer for the one thing the caller does with it.
	//
	static quint64		CertificateState(bool bReload = false);

	//
	// Why, as the code - the words are the viewer's, see
	// GUI/SettingsWindow.cpp. eCertNotFound when there is no module, which is
	// the same thing as far as anything that acts on this is concerned;
	// GetError says the rest.
	//
	static quint32		CertificateStatus(bool bReload = false);

	//
	// Who the certificate was issued to, which machine this is, and where the
	// file is looked for. All three come from the module because the module is
	// what reads them - see CertificateState.
	//
	static QString		CertificateName();
	static QString		CertificateHwid();
	static QString		CertificateFile();

	//
	// Where it looked. Beside the executable, which is where the installer puts
	// it and where a developer's build directory has it.
	//
	static QString		GetModulePath();

private:
	static void			Load();
};

#endif // TASKEXPLORER_API_REMOTEAPI_H
