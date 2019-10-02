/*
  +----------------------------------------------------------------------+
  | CoogleIOT for ESP8266                                                |
  +----------------------------------------------------------------------+
  | Copyright (c) 2017-2019 John Coggeshall                              |
  +----------------------------------------------------------------------+
  | Licensed under the Apache License, Version 2.0 (the "License");      |
  | you may not use this file except in compliance with the License. You |
  | may obtain a copy of the License at:                                 |
  |                                                                      |
  | http://www.apache.org/licenses/LICENSE-2.0                           |
  |                                                                      |
  | Unless required by applicable law or agreed to in writing, software  |
  | distributed under the License is distributed on an "AS IS" BASIS,    |
  | WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or      |
  | implied. See the License for the specific language governing         |
  | permissions and limitations under the License.                       |
  +----------------------------------------------------------------------+
  | Authors: John Coggeshall <john@thissmarthouse.com>                   |
  +----------------------------------------------------------------------+
*/
#include "CoogleIOT_NTP.h"

CoogleIOT_NTP& CoogleIOT_NTP::setReadyCallback(void(*cb)())
{
	this->readyCallback = cb;
	return *this;
}


CoogleIOT_NTP& CoogleIOT_NTP::setWifiManager(CoogleIOT_Wifi *_wifi)
{
	WiFiManager = _wifi;
	return *this;
}

CoogleIOT_NTP& CoogleIOT_NTP::setLogger(CoogleIOT_Logger *_logger)
{
	logger = _logger;
	return *this;
}

CoogleIOT_NTP& CoogleIOT_NTP::setOffsetSeconds(int offset)
{
	offsetSeconds = offset;
	return *this;
}

CoogleIOT_NTP& CoogleIOT_NTP::setDaylightOffsetSeconds(int offset)
{
	daylightOffsetSecs = offset;
	return *this;
}

bool CoogleIOT_NTP::sync()
{
	connectAttempts = 0;

	if(!WiFiManager) {
		return false;
	}

	if(!WiFiManager->connected()) {
		return false;
	}

	if(attemptingSync) {
		return false;
	}

	configTime(offsetSeconds, daylightOffsetSecs, CIOT_NTP_SERVERS);

	attemptingSync = true;

	os_timer_arm(&connectTimer, COOGLEIOT_NTP_SYNC_TIMEOUT, false);

	return true;
}

time_t CoogleIOT_NTP::getNow()
{
	return time(nullptr);
}

bool CoogleIOT_NTP::active()
{
	// This is kind of hacky but if we don't have an epoch that makes sense, it's not active.
	return time(nullptr) > 1000000000;
}

void CoogleIOT_NTP::loop()
{
	if(connectTimerTick) {
		connectTimerTick = false;
		connectAttempts++;

		if(connectAttempts > COOGLEIOT_NTP_MAX_ATTEMPTS) {
			if(logger)
				logger->error(F("[NTP] Failed to synchronize local time with NTP"));
			attemptingSync = false;
		} else {
			if(!active()) {
				if(logger)
					logger->logPrintf(DEBUG, F("NTP Sync attempt #%d"), connectAttempts);
				os_timer_arm(&connectTimer, COOGLEIOT_NTP_SYNC_TIMEOUT, false);
			} else {
				now = time(nullptr);

				if(logger)
					logger->info(F("[NTP] Time successfully synchronized with NTP server"));

				attemptingSync = false;

				if(readyCallback) {
					readyCallback();
				}
			}
		}
	}

	if(!active() && !attemptingSync) {
		if(WiFiManager) {
			if(WiFiManager->connected()) {
				if(logger)
					logger->debug(F("[NTP] No NTP Sync active, retrying sync"));

				sync();
			}
		}
	}

}

extern "C" void __coogleiot_ntp_connect_timer_callback(void *self)
{
	CoogleIOT_NTP *obj = static_cast<CoogleIOT_NTP *>(self);
	obj->connectTimerTick = true;
}

CoogleIOT_NTP::~CoogleIOT_NTP()
{
	if(timerSet) {
		os_timer_disarm(&connectTimer);
	}
}

bool CoogleIOT_NTP::initialize()
{
	if(logger)
		logger->info(F("[NTP] Initializing NTP"));

	os_timer_setfn(&connectTimer, __coogleiot_ntp_connect_timer_callback, this);
	timerSet = true;

	if(WiFiManager) {
		if(WiFiManager->connected()) {
			sync();
		}
	}

	return true;
}
