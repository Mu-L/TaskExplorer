#include "stdafx.h"
#include "HandleSearch.h"
#include "../TaskExplorer.h"
#include "../../API/Finders/AbstractFinder.h"

CHandleSearch::CHandleSearch(QWidget *parent) 
	: CSearchWindow(parent)
{
	setObjectName("HandleSearch");

	this->setWindowTitle(tr("Handle search..."));

	//
	// The type filter is whatever the target reports; systems with no notion of
	// handle types return an empty list and the combo stays at "All".
	//
	QList<CSystemAPI::SHandleType> Types = theSystem->GetHandleTypes();
	if (!Types.isEmpty())
	{
		m_pType->addItem(tr("All"), -1);
		foreach(const CSystemAPI::SHandleType& Type, Types)
			m_pType->addItem(Type.Name, Type.Index);
	}

	//m_pType->setEditable(true); // just in case we forgot a type

	m_pHandleView = new CHandlesView(2, this);
	m_pMainLayout->addWidget(m_pHandleView);

	m_pType->setCurrentIndex(m_pType->findText(theConf->GetString("HandleSearch/Type", "")));

	restoreGeometry(theConf->GetBlob("HandleSearch/Window_Geometry"));
}

CHandleSearch::~CHandleSearch()
{
	theConf->SetValue("HandleSearch/Type", m_pType->currentText());

	theConf->SetBlob("HandleSearch/Window_Geometry",saveGeometry());
}

CAbstractFinder* CHandleSearch::NewFinder()
{
	m_Handles.clear();
	m_pHandleView->ShowHandles(m_Handles);

	QString Exp;
	if (m_pRegExp->isChecked())
		Exp = m_pSearch->text();
	else
		Exp = ".*" + m_pSearch->text().replace("\\*",".*").replace("\\?",".") + ".*";
	QRegularExpression RegExp = QRegularExpression(Exp, QRegularExpression::CaseInsensitiveOption);

	bool bOk;
	int Type = m_pType->currentData().toInt(&bOk);
	if (!bOk)
		Type = -1;
	return CAbstractFinder::FindHandles(Type, RegExp);
}

void CHandleSearch::OnResults(QList<QSharedPointer<QObject>> List)
{
	foreach(const QSharedPointer<QObject>& pObject, List)
	{
		CHandlePtr pHandle = pObject.staticCast<CHandleInfo>();
		m_Handles.insert(pHandle->GetHandleId(), pHandle);
	}

	if (!CheckCountAndAbbort(m_Handles.count()))
		return;

	m_pHandleView->ShowHandles(m_Handles);
}
