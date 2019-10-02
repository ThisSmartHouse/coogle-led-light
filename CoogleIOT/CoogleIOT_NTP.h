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
#ifndef COOGLEIOT_NTP_H
#define COOGLEIOT_NTP_H

#include <time.h>
#include "CoogleIOT_Logger.h"
#include "CoogleIOT_Wifi.h"

#ifndef CIOT_NTP_SERVERS
#define CIOT_NTP_SERVERS  "pool.ntp.org", "time.nist.gov", "time.google.com"
#endif

#ifndef COOGLEIOT_NTP_MAX_ATTEMPTS
#define COOGLEIOT_NTP_MAX_ATTEMPTS 10
#endif

#ifndef COOGLEIOT_NTP_SYNC_TIMEOUT
#define COOGLEIOT_NTP_SYNC_TIMEOUT 1000
#endif

#ifndef COOGLEIOT_NTP_DEFAULT_TZ_OFFSET
#define COOGLEIOT_NTP_DEFAULT_TZ_OFFSET -18000 // EST
#endif

#ifndef COOGLEIOT_NTP_DEFAULT_DAYLIGHT_OFFSET
#define COOGLEIOT_NTP_DEFAULT_DAYLIGHT_OFFSET 3600 // 1 hour
#endif

class CoogleIOT_Logger;
class CoogleIOT_Wifi;

class CoogleIOT_NTP
{
	public:
		~CoogleIOT_NTP();

		CoogleIOT_NTP& setWifiManager(CoogleIOT_Wifi *);
		CoogleIOT_NTP& setLogger(CoogleIOT_Logger *);

		bool sync();
		bool initialize();
		void loop();

		CoogleIOT_NTP& setOffsetSeconds(int);
		CoogleIOT_NTP& setDaylightOffsetSeconds(int);
		CoogleIOT_NTP& setReadyCallback(void (*)());
		time_t getNow();
		bool active();
		bool connectTimerTick = false;

	private:
		time_t now;

		int offsetSeconds = COOGLEIOT_NTP_DEFAULT_TZ_OFFSET;
		int daylightOffsetSecs = COOGLEIOT_NTP_DEFAULT_DAYLIGHT_OFFSET;

		os_timer_t connectTimer;
		int connectAttempts = 0;
		bool attemptingSync = false;
		bool timerSet = false;

		void (* readyCallback)() = NULL;

		CoogleIOT_Wifi *WiFiManager = NULL;
		CoogleIOT_Logger *logger = NULL;
};

#endif
