#pragma once
#include "../version.h"
#include "../taskcore_global.h"
#include "../API/TaskStatus.h"

#include <QString>
#include <QByteArray>

//
// Turning "serve this machine" into something that survives a reboot.
//
// A TaskServer started from a console serves until that console closes, which
// is right for trying it out and wrong for everything else. What a watched
// machine actually needs is a service on Windows and a systemd unit on Linux,
// started before anyone logs in and restarted when it dies. That is what this
// installs.
//
// It lives in TaskCore rather than in any one program because three of them
// need it and none of them owns it: the settings dialog drives it, TaskConsole
// exposes it to a script or an unattended install, and TaskServer itself is what
// gets installed. Putting it anywhere else would have meant one of the three
// shelling out to another to ask a question it could answer itself.
//
// Nothing here words an error. TaskCore reports codes and values - see
// GUI/TaskStrings.cpp - so a failure carries the platform's own text as an
// argument and the front end decides how to say it.
//

//
// What the service is set up to do, and what it is doing.
//
// The identity and key are part of it because a network listener without them
// is not a configuration anybody wants: a server that starts and then refuses
// every connection is a fault report waiting to happen. Query() fills them in
// only when the caller can read the key file, which on both platforms means
// only when the caller is already privileged.
//
struct SServerSetup
{
	bool		bInstalled = false;		// a service or unit exists
	bool		bRunning = false;		// and it is up right now
	bool		bAutoStart = false;		// and it starts without being asked

	quint16		Port = 28333;

	//
	// Empty means every address the machine has. A machine with an interface
	// facing something it does not trust wants the other thing, and the choice
	// belongs here rather than in a firewall rule somebody has to remember.
	//
	QString		Bind;

	//
	// Whether any user on this machine may reach the local endpoint. A service
	// runs as LocalSystem or root, so without this its pipe names only that
	// account and no ordinary user's viewer can open it - see the note in
	// IPCServer.h. What each of them may then *see* is decided per connection.
	//
	bool		bAllUsers = true;

	//
	// What this instance is called.
	//
	// One name for two things that must agree: the local pipe or unix socket the
	// daemon listens on, and - when it is not the default - the service it is
	// installed as. A machine can then run more than one of these side by side,
	// or a packaging can rename it, without either instance reaching into the
	// other's.
	//
	// The default keeps the service called what it has always been called, so
	// an installation that never touches this is untouched by it existing. See
	// CServerSetup::ServiceNameFor.
	//
	QString		Name = MY_DAEMON_NAME_STRING;

	//
	// Whether the server listens on the local pipe or socket at all.
	//
	// Off by default, because a viewer on this machine does not need it. It has
	// its own collector and uses it: self-contained is the better way to watch
	// the computer you are sitting at - no second process to keep alive, no
	// serialising a process list to hand it back to the same machine, and
	// nothing that stops working when a service does. What the daemon is *for*
	// is being reached from somewhere else.
	//
	// So the local endpoint is a thing to ask for rather than a thing to turn
	// off: it is the one door on this machine that is open to every account,
	// and a machine that is only watched from elsewhere has nobody meant to be
	// walking through it. It remains the way a viewer here reaches a daemon
	// deliberately - a service running as SYSTEM that can see what an
	// unelevated viewer cannot - which is why it is a setting and not gone.
	//
	bool		bLocalPipe = false;

	//
	// Whether the daemon writes its transcript to TaskServer.log beside the
	// configuration file.
	//
	// Off by default. A service has no console, so with this off it says
	// nothing anywhere - including why it would not start, which is the one
	// message anybody ever wants from a service. That is the cost, and it is
	// taken deliberately: the transcript is a line per request, it names every
	// process a viewer asked about, and left on it grows without end on a
	// machine nobody is watching. Thirteen megabytes of it is what prompted
	// this.
	//
	// A console run is unaffected either way - it writes to the console it has.
	//
	bool		bLog = false;

	//
	// Whether this machine answers discovery queries, how often it announces
	// unprompted (zero: only when asked), and on which UDP port.
	//
	// Kept with the rest of the service configuration because that is what it
	// changes - the switch belongs to the daemon, not to the viewer that happens
	// to be setting it up. Looking for machines is the viewer's own setting and
	// is not here.
	//
	bool		bAnnounce = false;

	//
	// Whether the daemon takes part in the driver's process-creation gate.
	//
	// Not whether it watches process creation - it still does, and that is
	// where the earliest command line and image path for a new process come
	// from. This is the reply: with it on, the kernel holds each creation until
	// the daemon answers and refuses it if the daemon says so.
	//
	// Off, and deliberately. It makes the machine's ability to start programs
	// depend on a service being alive and prompt, which is a claim over the
	// computer rather than a view of it, and nobody installing a process viewer
	// asked for that. See DRIVER-EXPOSURE.md.
	//
	// A setting rather than a deletion because it is the foundation of anything
	// that would block processes system-wide, which is worth having later.
	// Turning it on is then one line in the file, written by somebody who meant
	// it.
	//
	bool		bProcessBlocking = false;

	//
	// Whether the daemon uses the kernel driver at all.
	//
	// On, because the driver is most of what makes a daemon worth asking.
	// Without it this is an ordinary elevated process: a protected process's
	// threads, a handle's true object, a working set walked without opening the
	// process all come back empty or refused, and the viewer that asked cannot
	// tell "there is nothing there" from "I was not allowed to look".
	//
	// Off is for a machine where loading a kernel driver is not wanted whatever
	// it buys - a hardened server, a policy that says so, an installation being
	// compared against one without it. It is the daemon's own switch and not the
	// viewer's: a self-contained TaskExplorer on this machine has its own, and
	// the two are separate because they are two different processes deciding
	// separately what they are willing to load. See DRIVER-EXPOSURE.md.
	//
	// Windows only in effect. The field exists on both platforms so that the
	// configuration and the code that reads it are the same everywhere, and
	// nothing on Linux looks at it.
	//
	bool		bUseDriver = true;

	int			AnnounceInterval = 0;
	quint16		DiscoveryPort = 28334;

	//
	// The shared transport secret, as typed. Any length; it is hashed to the
	// length TLS needs when it is used - see SCredentials::DeriveTlsKey.
	//
	// Everyone who may reach this machine holds it, and holding it is worth one
	// thing: a tunnel. Who somebody is gets settled inside that tunnel, against
	// the user list below.
	//
	QString		Psk;

	//
	// Read back instead of the secret itself: whether one is set at all.
	//
	// Query() and ReadConfig() never fetch the value. Nothing above them has a
	// use for it, and a value that is never fetched cannot be shown in a dialog,
	// written to a log or copied into a message by accident. What a dialog needs
	// is exactly this bit.
	//
	bool		bHasPsk = false;
};

//
// One account that may log in over the network.
//
// The password is not in here as a password. It is in the file as a salt and a
// slow hash, and this carries one only when it is being *changed* - which is
// why there are two fields for it: an empty NewPassword with bSetPassword set
// means "this account has no password of its own, check the operating system",
// and an empty one without it means "leave whatever is stored alone". Those are
// two different instructions and one field could not tell them apart.
//
struct SServerUserRecord
{
	QString		Name;
	bool		bAdmin = false;
	bool		bActions = false;

	//
	// Read back only: true when the record carries no hash, so logging in as
	// this name asks the operating system instead.
	//
	bool		bSystemAccount = false;

	QString		NewPassword;
	bool		bSetPassword = false;
};

class TASKCORE_EXPORT CServerSetup
{
public:
	//
	// Whether this process could install anything: elevated on Windows, uid 0
	// on Linux. Asked before offering rather than after failing.
	//
	static bool			IsPrivileged();

	//
	// The service or unit name, and where TaskServer is expected to be. The
	// binary is looked for beside the running program, because an installed
	// service pointing somewhere else is how a working setup becomes a broken
	// one after an update.
	//
	static QString		ServiceName();

	//
	// The service name an instance of this name would be installed as.
	//
	// Pure, so that a rename can ask about the name being left behind as well as
	// the one being taken up - ServiceName() answers for whatever the
	// configuration says right now, which during a rename is already the new
	// one.
	//
	static QString		ServiceNameFor(const QString& InstanceName);
	static QString		ServerBinaryPath();

	//
	// Whether this installation has a server to set up at all.
	//
	// TaskServer ships beside the viewer but is not part of it, and a build or
	// a package can leave it out. Everything on the server page then describes
	// a program that is not there, which is worth saying once rather than
	// letting each button fail in turn.
	//
	static bool			IsAvailable();


	//
	// The machine-wide server configuration, beside the key file.
	//
	// The service's command line is only "--service" - everything it does is in
	// here instead. A command line is the wrong place for a configuration: it can
	// only be changed by reconfiguring the service, it is read back by parsing it
	// again, and every process on the machine can see it. A file can be edited by
	// hand, read by a server somebody started themselves, and kept where only
	// administrators can write it.
	//
	// Which is the other half of why it is here and not beside the executable:
	// the same settings serve an installed service and a hand-started server, so
	// they cannot live in either one's private directory.
	//
	static QString		ConfigFilePath();

	//
	// The configurable half of SServerSetup - port, address, discovery, and who
	// may reach the local endpoint. Not bInstalled/bRunning/bAutoStart, which are
	// the service manager's to answer, and not the key, which is in its own file.
	//
	// False when there is no file yet, with pSetup left at its defaults. That is
	// not an error: a machine nobody has configured is a machine running the
	// defaults.
	//
	// Path names a file other than ConfigFilePath(), which is what --keys does:
	// it moves the whole file, secrets and settings alike, since they are one
	// file now. Empty means the machine-wide one.
	//
	static bool			ReadConfig(SServerSetup* pSetup, const QString& Path = QString());

	//
	// Writes it, creating the directory locked down the same way the key file's
	// is. Needs privileges. Independent of Install() on purpose: the settings are
	// worth keeping for a server started by hand, so they can be saved without a
	// service being installed at all.
	//
	static STATUS		WriteConfig(const SServerSetup& Setup);

	//
	// What is installed, if anything. Needs no privileges: both platforms let
	// anyone ask whether a service exists and what it was configured with. The
	// key comes back empty when it cannot be read, which is not an error - it
	// is the file's permissions doing their job.
	//
	static bool			Query(SServerSetup* pSetup);

	//
	// Installs or reconfigures, and starts. Needs privileges.
	//
	// Reconfiguring rather than removing and recreating: a service that
	// disappears and comes back loses anything else somebody had set on it -
	// recovery actions, a dependency, a description - and there is no reason to
	// make them notice.
	//
	// An empty Key leaves whatever key file is already there alone. That is how
	// the port can be changed without the caller having to know the key.
	//
	static STATUS		Install(const SServerSetup& Setup);

	//
	// Stops and removes. The key file is deliberately left behind: it is the
	// only copy of something the other machines' viewers were told, and
	// deleting it as a side effect of turning a checkbox off would be a
	// surprise nobody could undo.
	//
	//
	// Removes the service. An empty name means the one the configuration
	// currently describes; a name is passed when an instance is being renamed
	// and it is the *old* service that has to go.
	//
	static STATUS		Remove(const QString& ServiceName = QString());

	//
	// Starts and stops what is installed, without changing it. Named Server
	// rather than Service because <winsvc.h> defines StartService as a macro
	// for StartServiceW, which would rename this method in every translation
	// unit that included windows.h and leave it alone in the rest.
	//
	// Reinstalling to restart is what this replaces. A configuration change has
	// to go round anyway, but wanting the server to stop for an hour is not a
	// configuration change and should not read like one.
	//
	static STATUS		StartServer();
	static STATUS		StopServer();


	//
	// The accounts that may log in over the network, read from and written to
	// the [Users/*] groups of the configuration file.
	//
	// One function per account rather than one for the whole list, because that
	// is what the editing actually is - adding one, removing one, changing one -
	// and because rewriting the list wholesale would mean holding every stored
	// hash in memory in order to put the untouched ones back.
	//
	static bool			ReadUsers(QList<SServerUserRecord>* pUsers);

	//
	// Creates or updates one. Needs privileges.
	//
	// The password is hashed here and the plain text never leaves this call: a
	// fresh salt, PBKDF2, and the iteration count written beside the result so
	// that it can be raised later without invalidating what is already stored.
	//
	static STATUS		WriteUser(const SServerUserRecord& User);
	static STATUS		RemoveUser(const QString& Name);

	//
	// A transport secret worth using, as hex. Not a password - nobody has to
	// remember it, both ends can paste it, and it is the one secret here that
	// protects nothing by itself.
	//
	static QString		GenerateTransportKey();

	//
	// The stored transport key, for showing to somebody who is entitled to it.
	//
	// Deliberately not part of ReadConfig() or Query(), which never fetch it - a
	// value that is never read cannot be shown, logged or copied into a message
	// by accident, and everything that asks what is installed wants none of it.
	// Fetching it is a separate act with a separate reason, and this is it.
	//
	// Needs privileges, which is not the only thing standing in the way: the file
	// is in a directory only administrators can read, so an unprivileged caller
	// would fail at the open even without the check. The check is here so the
	// refusal is the one the caller asked about rather than a file error.
	//
	static bool			ReadTransportKey(QString* pKey);
	//
	// Builds the argument list an installed server runs with. Public because
	// TaskConsole prints it and the tests read it, and because a service whose
	// command line is a mystery is one nobody can debug.
	//
	static QStringList	BuildArguments(const SServerSetup& Setup);
};
