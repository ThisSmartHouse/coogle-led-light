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
#ifndef COOGLEIOT_MQTT_H_
#define COOGLEIOT_MQTT_H_

#include <PubSubClient.h>
#include <ESP8266WiFi.h>
#include "CoogleIOT_Wifi.h"
#include "CoogleIOT_Config.h"

#ifndef COOGLEIOT_MQTT_MAX_HOSTNAME_LEN
#define COOGLEIOT_MQTT_MAX_HOSTNAME_LEN 255
#endif

#ifndef COOGLEIOT_MQTT_MAX_USERNAME_LEN
#define COOGLEIOT_MQTT_MAX_USERNAME_LEN 16
#endif

#ifndef COOGLEIOT_MQTT_MAX_PASSWORD_LEN
#define COOGLEIOT_MQTT_MAX_PASSWORD_LEN 32
#endif

#ifndef COOGLEIOT_MQTT_MAX_LWT_TOPIC_LEN
#define COOGLEIOT_MQTT_MAX_LWT_TOPIC_LEN 255
#endif

#ifndef COOGLEIOT_MQTT_MAX_LWT_MSG_LEN
#define COOGLEIOT_MQTT_MAX_LWT_MSG_LEN 255
#endif

#ifndef COOGLEIOT_MQTT_MAX_CLIENT_ID_LEN
#define COOGLEIOT_MQTT_MAX_CLIENT_ID_LEN 32
#endif

#ifndef COOGLEIOT_MQTT_CONNECT_RETRY
#define COOGLEIOT_MQTT_CONNECT_RETRY 1000
#endif


class CoogleIOT_Logger;
class CoogleIOT_Wifi;
class CoogleIOT_Config;
class PubSubClient;

class CoogleIOT_MQTT
{
	public:

		bool connectTimerTick = false;

		bool initialize();
		void connect();
		void disconnect();
		bool connected();
		void loop();

		CoogleIOT_MQTT& setPort(uint16_t);
		CoogleIOT_MQTT& setHostname(const char *);
		CoogleIOT_MQTT& setUsername(const char *);
		CoogleIOT_MQTT& setPassword(const char *);
		CoogleIOT_MQTT& setLWTTopic(const char *);
		CoogleIOT_MQTT& setLWTMessage(const char *);
		CoogleIOT_MQTT& setClientId(const char *);
		
		const char *getClientId();

		CoogleIOT_MQTT& setLogger(CoogleIOT_Logger *);
		CoogleIOT_MQTT& setWifiManager(CoogleIOT_Wifi *);
		CoogleIOT_MQTT& setConfigManager(CoogleIOT_Config *);

		CoogleIOT_MQTT& setClient(WiFiClient *);
		CoogleIOT_MQTT& setClient(WiFiClientSecure *);

		PubSubClient* getClient();
		CoogleIOT_MQTT& setConnectCallback(void (*)());
	private:

		bool doConnect();

		WiFiClient *espClient = NULL;
		WiFiClientSecure *espClientSecure = NULL;

		PubSubClient *mqttClient = NULL;

		bool active = false;
		bool attempting = false;
		bool useSecure = false;

		os_timer_t connectTimer;

		CoogleIOT_Logger *logger = NULL;
		CoogleIOT_Wifi *wifiManager = NULL;
		CoogleIOT_Config *configManager = NULL;

		void (* connectCallback)() = NULL;

		uint16_t port = 1883;
		char hostname[COOGLEIOT_MQTT_MAX_HOSTNAME_LEN + 1] = {NULL};
		char username[COOGLEIOT_MQTT_MAX_USERNAME_LEN + 1] = {NULL};
		char password[COOGLEIOT_MQTT_MAX_PASSWORD_LEN + 1] = {NULL};
		char lwt_topic[COOGLEIOT_MQTT_MAX_LWT_TOPIC_LEN + 1] = {NULL};
		char lwt_msg[COOGLEIOT_MQTT_MAX_LWT_MSG_LEN + 1];
		char client_id[COOGLEIOT_MQTT_MAX_CLIENT_ID_LEN + 1] = "coogleiot";
};

#endif
