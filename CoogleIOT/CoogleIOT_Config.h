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
#include <ESP8266WebServer.h>
#include <FS.h>
#include "CoogleIOT_OTA.h"
#include "CoogleIOT_Logger.h"

#ifndef COOGLEIOT_CONFIG_MAX_WIFI_NETWORKS
#define COOGLEIOT_CONFIG_MAX_WIFI_NETWORKS 16
#endif

#define COOGLEIOT_MAX_WIFI_NETWORKS_OUTPUT_SIZE 1024

#ifndef COOGLEIOT_CONFIG_FILE
#define COOGLEIOT_CONFIG_FILE "/config.json"
#endif

typedef struct coogleiot_config_base_t {
	WiFiMode_t wifi_mode;
	char wifi_ssid[33];
	char wifi_pass[64];
	char hostname[256];

	char ap_name[33];
	char ap_pass[65];

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

#ifndef COOGLEIOT_CONFIG_JSON_OUTPUT_SIZE
#define COOGLEIOT_CONFIG_JSON_OUTPUT_SIZE 768
#endif 
			
extern "C" void __coogleiot_on_config_get();
extern "C" void __coogleiot_on_config_set();
extern "C" void __coogleiot_config_on_not_found();
extern "C" void __coogleiot_on_reboot();
extern "C" void __coogleiot_on_scan();

class CoogleIOT_Logger;

class CoogleIOT_Config
{
   public:

	bool setConfigJson(const char *);
	void initialize();
	void loop();

	CoogleIOT_Config& setConfigStruct(coogleiot_config_base_t *);
	CoogleIOT_Config& setParseCallback(bool (*)(DynamicJsonDocument&));
	CoogleIOT_Config& setSerializeCallback(void (*)(JsonObject&));
	CoogleIOT_Config& setRebootCallback(void (*)());
	CoogleIOT_Config& setJsonConfigSize(size_t);

	CoogleIOT_Config& setLogger(CoogleIOT_Logger *);
	CoogleIOT_Logger* getLogger();
	bool saveConfig();

	ESP8266WebServer* getConfigServer();

	char *asJson();

	CoogleIOT_Config& enableConfigServer();
	CoogleIOT_Config& disableConfigServer();

	coogleiot_config_base_t *getConfig();

	static CoogleIOT_Config* getInstance();

	CoogleIOT_Config(CoogleIOT_Config&) = delete;
	CoogleIOT_Config& operator=(const CoogleIOT_Config&) = delete;

	bool loaded = false;

	bool restart = false;
	void (* rebootCallback)() = NULL;

	~CoogleIOT_Config();

   private:

	CoogleIOT_Config();

	size_t json_config_size = JSON_OBJECT_SIZE(1) + 3*JSON_OBJECT_SIZE(2) + 2*JSON_OBJECT_SIZE(3) + JSON_OBJECT_SIZE(4) + 552;

	coogleiot_config_base_t *config = NULL;

	bool (* parseCallback)(DynamicJsonDocument&) = NULL;

	CoogleIOT_Logger *logger = NULL;
	ESP8266WebServer *server = NULL;

};

#endif
