#include "stdafx.h"
#include "RemoteApi.h"
#include "../../TaskCommon/Support.h"
#include "SystemAPI.h"

#include <QLibrary>
#include <QCoreApplication>
#include <QFileInfo>
#include <QDir>

//
// One QLibrary for the process, resolved once.
//
// QLibrary rather than dlopen/LoadLibrary behind an #ifdef: it is the same two
// calls on both platforms and it already knows that the file is called
// TaskRemote.dll here and libTaskRemote.so there.
//
static QLibrary*			g_pLibrary = NULL;
static bool					g_bTried = false;
static QString				g_Error;
static QString				g_Path;
static FnCreateRemoteSystem	g_pCreate = NULL;
static FnDestroyRemoteSystem g_pDestroy = NULL;
static FnCreateRemoteDiscovery	g_pCreateDisc = NULL;
static FnDestroyRemoteDiscovery	g_pDestroyDisc = NULL;
static FnProbeEndpoint			g_pProbe = NULL;
static FnCertificateState		g_pCertState = NULL;
static FnCertificateStatus		g_pCertStatus = NULL;
static FnCertificateString		g_pCertName = NULL;
static FnCertificateString		g_pCertHwid = NULL;
static FnCertificateString		g_pCertFile = NULL;

void CRemoteLoader::Load()
{
	if (g_bTried)
		return;
	g_bTried = true;

	//
	// Beside the executable, and only there. Not the working directory and not
	// the system search path: what this loads runs with the viewer's own
	// privileges, and a module picked up from wherever the program happened to
	// be started from is a way to be handed one somebody else wrote.
	//
	const QString Dir = QCoreApplication::applicationDirPath();
	g_Path = Dir + "/" + QString(
#ifdef WIN32
		"TaskRemote.dll"
#else
		"libTaskRemote.so"
#endif
	);

	if (!QFile::exists(g_Path))
	{
		g_Error = QString("no remote module at %1").arg(QDir::toNativeSeparators(g_Path));
		return;
	}

	g_pLibrary = new QLibrary(g_Path);
	if (!g_pLibrary->load())
	{
		g_Error = g_pLibrary->errorString();
		delete g_pLibrary;
		g_pLibrary = NULL;
		return;
	}

	//
	// The version first, and by itself: if this one symbol is missing the file
	// is not a TaskRemote at all, and asking it for a factory would be asking
	// an arbitrary library for an arbitrary entry point.
	//
	FnRemoteAbiVersion pVersion = (FnRemoteAbiVersion)g_pLibrary->resolve("TaskRemoteAbiVersion");
	if (!pVersion)
	{
		g_Error = QString("%1 is not a remote module").arg(QDir::toNativeSeparators(g_Path));
		g_pLibrary->unload();
		delete g_pLibrary;
		g_pLibrary = NULL;
		return;
	}

	const quint32 Version = pVersion();
	if (Version != TASKREMOTE_ABI_VERSION)
	{
		g_Error = QString("remote module is version %1, this build needs %2")
			.arg(Version).arg((quint32)TASKREMOTE_ABI_VERSION);
		g_pLibrary->unload();
		delete g_pLibrary;
		g_pLibrary = NULL;
		return;
	}

	g_pCreate = (FnCreateRemoteSystem)g_pLibrary->resolve("CreateRemoteSystem");
	g_pDestroy = (FnDestroyRemoteSystem)g_pLibrary->resolve("DestroyRemoteSystem");
	g_pCreateDisc = (FnCreateRemoteDiscovery)g_pLibrary->resolve("CreateRemoteDiscovery");
	g_pDestroyDisc = (FnDestroyRemoteDiscovery)g_pLibrary->resolve("DestroyRemoteDiscovery");
	g_pProbe = (FnProbeEndpoint)g_pLibrary->resolve("ProbeEndpoint");
	g_pCertState = (FnCertificateState)g_pLibrary->resolve("CertificateState");
	g_pCertStatus = (FnCertificateStatus)g_pLibrary->resolve("CertificateStatus");
	g_pCertName = (FnCertificateString)g_pLibrary->resolve("CertificateName");
	g_pCertHwid = (FnCertificateString)g_pLibrary->resolve("CertificateHwid");
	g_pCertFile = (FnCertificateString)g_pLibrary->resolve("CertificateFile");

	//
	// All of them or none. A module missing one passed the version check and is
	// therefore lying about what it is; carrying on with the half that resolved
	// would fail later and somewhere less obvious.
	//
	if (!g_pCreate || !g_pDestroy || !g_pCreateDisc || !g_pDestroyDisc || !g_pProbe
	 || !g_pCertState || !g_pCertStatus || !g_pCertName || !g_pCertHwid || !g_pCertFile)
	{
		g_Error = QString("remote module is incomplete");
		g_pCreate = NULL;
		g_pDestroy = NULL;
		g_pCreateDisc = NULL;
		g_pDestroyDisc = NULL;
		g_pProbe = NULL;
		g_pCertState = NULL;
		g_pCertStatus = NULL;
		g_pCertName = NULL;
		g_pCertHwid = NULL;
		g_pCertFile = NULL;
		g_pLibrary->unload();
		delete g_pLibrary;
		g_pLibrary = NULL;
		return;
	}

	//
	// Deliberately not unloaded from here on, and QLibrary is left alive to say
	// so. An object it made can outlive the connection that made it - the tree
	// keeps a machine's branch for the persistence window after the server goes
	// away - and unloading the code its vtable points at would turn that into a
	// crash at a moment nothing else explains.
	//
}

bool CRemoteLoader::IsAvailable()
{
	Load();
	return g_pCreate != NULL;
}

CSystemAPI* CRemoteLoader::Create()
{
	Load();
	return g_pCreate ? g_pCreate() : NULL;
}

void CRemoteLoader::Destroy(CSystemAPI* pSystem)
{
	if (!pSystem)
		return;

	//
	// If this is reached with no module the object cannot have come from one,
	// so there is nothing that could safely be done with it - and dropping it
	// leaks rather than crashes, which is the right way round.
	//
	if (g_pDestroy)
		g_pDestroy(pSystem);
}

CRemoteDiscovery* CRemoteLoader::CreateDiscovery()
{
	Load();
	return g_pCreateDisc ? g_pCreateDisc() : NULL;
}

void CRemoteLoader::DestroyDiscovery(CRemoteDiscovery* pDiscovery)
{
	if (pDiscovery && g_pDestroyDisc)
		g_pDestroyDisc(pDiscovery);
}

bool CRemoteLoader::ProbeEndpoint(const QString& Name)
{
	Load();
	return g_pProbe ? g_pProbe(Name) : false;
}

QString CRemoteLoader::GetError()
{
	Load();
	return g_Error;
}

//
// Asked of the module, not read here.
//
// Both would read the same file from the same directory, and that is exactly
// why this goes across: the module is what refuses to create a connection, so
// the module is what should say whether it would. A second reader here could
// answer yes while CreateRemoteSystem answered no, and the person would be
// looking at a certificate the program had already accepted while nothing
// worked.
//
quint64 CRemoteLoader::CertificateState(bool bReload)
{
	Load();
	return g_pCertState ? g_pCertState(bReload) : 0;
}

quint32 CRemoteLoader::CertificateStatus(bool bReload)
{
	Load();
	return g_pCertStatus ? g_pCertStatus(bReload) : (quint32)eCertNotFound;
}

QString CRemoteLoader::CertificateName()
{
	Load();
	return g_pCertName ? g_pCertName() : QString();
}

QString CRemoteLoader::CertificateHwid()
{
	Load();
	return g_pCertHwid ? g_pCertHwid() : QString();
}

//
// Where the module looks, which is beside the executable - so with no module
// this is still the right answer and is worked out here rather than left empty.
//
QString CRemoteLoader::CertificateFile()
{
	Load();
	return g_pCertFile ? g_pCertFile()
	                   : QCoreApplication::applicationDirPath() + "/Certificate.dat";
}

QString CRemoteLoader::GetModulePath()
{
	Load();
	return g_Path;
}
