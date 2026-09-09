#pragma once

#include "../guihelpers_global.h"

class GUIHELPERS_EXPORT CExitDialog : public QDialog
{
	//
	// A QDialog subclass without this is a QDialog as far as the meta-object is
	// concerned: no signals or slots of its own would work, and tr() here
	// resolved to QDialog::tr, filing this dialog's one string under a context
	// belonging to somebody else. lupdate said so and was right.
	//
	// The header is moc'd on both sides - listed as QtMoc in GuiHelpers.vcxproj
	// and in the source list MiscHelpers/CMakeLists.txt hands to AUTOMOC.
	//
	Q_OBJECT

public:
	CExitDialog(const QString& Prompt, QWidget* parent = 0)
	 : QDialog(parent)
	{
		m_pMainLayout = new QGridLayout(this);
 
		QLabel* pLabel = new QLabel(Prompt);
		m_pMainLayout->addWidget(pLabel, 0, 0, 1, 1);

		m_pButtonBox = new QDialogButtonBox();
		m_pButtonBox->setOrientation(Qt::Horizontal);
		m_pButtonBox->setStandardButtons(QDialogButtonBox::Yes|QDialogButtonBox::No);
		m_pMainLayout->addWidget(m_pButtonBox, 2, 0, 1, 1);
 
		connect(m_pButtonBox,SIGNAL(accepted()),this,SLOT(accept()));
		connect(m_pButtonBox,SIGNAL(rejected()),this,SLOT(reject()));

		m_TimerId = startTimer(1000);
		m_CountDown = 15;
	}
	~CExitDialog()
	{
		killTimer(m_TimerId);
	}

protected:
	void timerEvent(QTimerEvent *e)
	{
		if (e->timerId() != m_TimerId) 
		{
			QDialog::timerEvent(e);
			return;
		}

		if(m_CountDown != 0)
		{
			m_CountDown--;
			m_pButtonBox->button(QDialogButtonBox::Yes)->setText(tr("Yes (%1)").arg(m_CountDown));
			if(m_CountDown == 0)
				accept();
		}
	}

	void reject()
	{
		hide();
	}

	void closeEvent(QCloseEvent *e)
	{
		hide();
		e->ignore();
	}

	int					m_TimerId;
	int					m_CountDown;

	QGridLayout*		m_pMainLayout;
	QDialogButtonBox *	m_pButtonBox;
};
