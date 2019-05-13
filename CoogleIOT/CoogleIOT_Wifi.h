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
#ifndef COOGLEIOT_WIFI_H_
#define COOGLEIOT_WIFI_H_

#include <ESP8266WiFi.h>
#include <WiFiClient.h>
#include "CoogleIOT_Logger.h"


#ifndef COOGLEIOT_WIFI_CONNECT_TIMEOUT
#define COOGLEIOT_WIFI_CONNECT_TIMEOUT 1000
#endif

#ifndef COOGLEIOT_WIFI_MAX_ATTEMPTS
#define COOGLEIOT_WIFI_MAX_ATTEMPTS 10
#endif

class CoogleIOT_Logger;

class CoogleIOT_Wifi
{
	public:

		bool wifiConnectTimerTick = false;

		void loop();
		bool initialize();

		char *getRemoteAPName();
		char *getRemoteAPPassword();
		char *getLocalAPName();
		char *getLocalAPPassword();
		char *getRemoteStatus();

		CoogleIOT_Wifi& setRemoteAPName(const char *);
		CoogleIOT_Wifi& setRemoteAPPassword(const char *);
		CoogleIOT_Wifi& setLocalAPName(const char *);
		CoogleIOT_Wifi& setLocalAPPassword(const char *);

		CoogleIOT_Wifi& setRemoteAPName(String &);
		CoogleIOT_Wifi& setRemoteAPPassword(String &);
		CoogleIOT_Wifi& setLocalAPName(String &);
		CoogleIOT_Wifi& setLocalAPPassword(String &);

		CoogleIOT_Wifi& setLogger(CoogleIOT_Logger *);

		bool connected();

	private:

		char remoteAPName[33];
		char remoteAPPassword[65];
		char localAPName[33];
		char localAPPassword[65];

		os_timer_t wifiConnectTimer;

		int wifiFailuresCount = 0;

		CoogleIOT_Logger *logger = NULL;

		bool attemptingConnection = false;

		bool connect();
};
#endif
