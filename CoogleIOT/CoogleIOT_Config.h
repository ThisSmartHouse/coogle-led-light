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
#ifndef __COOGLEIOT_CONFIG_H
#define __COOGLEIOT_CONFIG_H

#include "ArduinoJson.h"
#include <ESP8266WiFi.h>
#include <ESP8266WiFiType.h>
#include <FS.h>
#include "CoogleIOT_OTA.h"
#include "CoogleIOT_Logger.h"

#ifndef COOGLEIOT_CONFIG_FILE
#define COOGLEIOT_CONFIG_FILE "/config.json"
#endif

typedef struct coogleiot_config_base_t {
	WiFiMode_t wifi_mode;
	char wifi_ssid[33];
	char wifi_pass[64];

	char mqtt_host[256];
	uint16_t mqtt_port;

	char ota_endpoint[128 + 253 + 5 + 1];
	bool ota_check_on_boot;

	bool sec_allow_insecure_ssl;
};

#define DEBUG_COOGLEIOT_CONFIG(c) \
			if(logger) { \
				logger->debug("WiFi"); \
				logger->logPrintf(DEBUG, "\tWMode: %d", c->wifi_mode); \
				logger->logPrintf(DEBUG, "\tSSID: %s", c->wifi_ssid); \
				logger->logPrintf(DEBUG, "\tPass: %s", c->wifi_pass); \
				logger->debug("MQTT"); \
				logger->logPrintf(DEBUG, "\tHost: %s", c->mqtt_host); \
				logger->logPrintf(DEBUG, "\tPort: %d", c->mqtt_port); \
				logger->debug("OTA"); \
				logger->logPrintf(DEBUG, "\tEndpoint: %s", c->ota_endpoint); \
				logger->logPrintf(DEBUG, "\tCheck On Boot: %s", c->ota_check_on_boot ? "true" : "false"); \
				logger->debug("Security"); \
				logger->logPrintf(DEBUG, "\tAllow Insecure SSL: %s", c->sec_allow_insecure_ssl ? "true" : "false"); \
			}

class CoogleIOT_Logger;

class CoogleIOT_Config
{
   public:

	bool setConfigJson(const char *);
	void initialize();

	CoogleIOT_Config& setConfigStruct(coogleiot_config_base_t *);
	CoogleIOT_Config& setParseCallback(bool (*)(DynamicJsonDocument&));
	CoogleIOT_Config& setLogger(CoogleIOT_Logger *);

	coogleiot_config_base_t *getConfig();

	bool loaded = false;

   private:

	size_t json_config_size = JSON_OBJECT_SIZE(1) + 3*JSON_OBJECT_SIZE(2) + 2*JSON_OBJECT_SIZE(3) + JSON_OBJECT_SIZE(4) + 552;

	coogleiot_config_base_t *config = NULL;

	bool (* parseCallback)(DynamicJsonDocument&) = NULL;

	CoogleIOT_Logger *logger = NULL;

};

#endif
