#pragma once

#include "../../taskcore_global.h"

#include "../../../MiscHelpers/Common/Common.h"
#include "../MiscStats.h"

class TASKCORE_EXPORT CDiskMonitor : public QObject
{
	Q_OBJECT

	TRACK_OBJECT(CDiskMonitor)
public:
	CDiskMonitor(QObject *parent = nullptr);
	virtual ~CDiskMonitor();

	virtual bool		Init() = 0;

	virtual bool		UpdateDisks() = 0;

	virtual void		UpdateDiskStats() = 0;

	struct SDiskInfo: SIOStats
	{
		SDiskInfo()
		{
			DeviceIndex = ULONG_MAX;
			DevicePresent = false;
			DeviceSupported = true;

			LastStatUpdate = GetCurTick();

			ResponseTime = 0;
			ActiveTime = 0;
			QueueDepth = 0;
			SplitCount = 0;

			TotalSize = 0;

			DiskIndex = ULONG_MAX;
		}

		quint32 DeviceIndex;
		bool DevicePresent;
		bool DeviceSupported;
		QString DevicePath;
		QString DeviceName;
		QString DeviceMountPoints;

		//
		// What the driver calls the device. Kept apart from the mount points so
		// the row's label can be put together for reading rather than shipped
		// as one string.
		//
		QString DeviceDescription;
		quint32 DiskNumber = ULONG_MAX;

		quint64	LastStatUpdate;
		//SDelta64 BytesReadDelta;
		//SDelta64 BytesWrittenDelta;
		SDelta64 ReadTimeDelta;
		SDelta64 WriteTimeDelta;
		SDelta64 IdleTimeDelta;
		//SDelta32_64 ReadCountDelta;
		//SDelta32_64 WriteCountDelta;
		SDelta64 QueryTimeDelta;

		float ResponseTime;
		float ActiveTime;
		quint32 QueueDepth;
		quint32 SplitCount;

		quint64 TotalSize;

		quint32 DiskIndex;
	};

	virtual QMap<QString, SDiskInfo>	GetAllDiskList() const { QReadLocker Locker(&m_StatsMutex); return m_DiskList; }
	virtual SDiskInfo					GetDiskInfo(const QString& DevicePath) const { QReadLocker Locker(&m_StatsMutex); return m_DiskList.value(DevicePath); }
	virtual QMap<QString, SDiskInfo>	GetDiskList() const;

	struct SDataRates
	{
		SDataRates()
		{
			DiskCount = 0;
			Supported = 0;

			ReadRate = 0;
			WriteRate = 0;
		}

		int DiskCount;
		int Supported;

		quint64 ReadRate;
		quint64 WriteRate;
	};

	virtual SDataRates	GetAllDiskDataRates() const;
	virtual bool		AllDisksSupported() const;

protected:
	QMap<QString, SDiskInfo>	m_DiskList;

	mutable QReadWriteLock		m_StatsMutex;
};