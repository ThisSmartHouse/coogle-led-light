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

#include "CoogleIOT_Config.h"

void CoogleIOT_Config::initialize()
{
	File configFile;
	char *buffer;
	size_t readBytes;

	if(config == NULL) {
		return;
	}

	if(!SPIFFS.begin()) {
		if(logger)
			logger->error("[CONFIG] Failed to start SPIFFS, cannot initialize");
		return;
	}

	if(!SPIFFS.exists(COOGLEIOT_CONFIG_FILE)) {
		if(logger)
			logger->logPrintf(WARNING, "[CONFIG] Cannot locate configuration file %s", COOGLEIOT_CONFIG_FILE);
		return;
	}

	configFile = SPIFFS.open(COOGLEIOT_CONFIG_FILE, "r");

	buffer = (char *)os_zalloc(configFile.size() + 1);

	readBytes = configFile.readBytes(buffer, configFile.size());

	if(readBytes != configFile.size()) {
		if(logger)
			logger->error("[CONFIG] Failed to read full config file into buffer");
		configFile.close();
		free(buffer);
		return;
	}

	if(!setConfigJson(buffer)) {
		if(logger)
			logger->error("[CONFIG] Failed to parse configuration JSON");
	} else {
		//DEBUG_COOGLEIOT_CONFIG(config);
	}

	free(buffer);
	configFile.close();
}

bool CoogleIOT_Config::setConfigJson(const char *jsonData)
{
	DynamicJsonDocument doc(json_config_size);
	DeserializationError err;
	JsonObject coogleiot, wifi, mqtt, ota, security;

	err = deserializeJson(doc, jsonData);

	if(err) {
		if(logger)
			logger->logPrintf(ERROR, "[CONFIG] Failed to deserialize JSON Config: %s", err.c_str());
		return false;
	}

	if(!doc["coogleiot"].is<JsonObject>()) {
		if(logger)
			logger->error("[CONFIG] Invalid Config, no valid 'coogleiot' section");
		return false;
	}

	coogleiot = doc["coogleiot"].as<JsonObject>();

	if(coogleiot["wifi"].is<JsonObject>()) {
		wifi = coogleiot["wifi"].as<JsonObject>();

		if(wifi["mode"].is<const char *>()) {
			if(strcmp(wifi["mode"].as<const char *>(), "station") == 0) {
				config->wifi_mode = WIFI_STA;
			} else if(strcmp(wifi["mode"].as<const char *>(), "ap") == 0) {
				config->wifi_mode = WIFI_AP;
			} else if(strcmp(wifi["mode"].as<const char *>(), "ap-station") == 0) {
				config->wifi_mode = WIFI_AP_STA;
			} else {
				config->wifi_mode = WIFI_OFF;
			}
		} else {
			config->wifi_mode = WIFI_OFF;
		}

		if(wifi["ssid"].is<const char *>()) {
			strlcpy(config->wifi_ssid, wifi["ssid"] | "", sizeof(config->wifi_ssid));
		} else {
			config->wifi_ssid[0] = NULL;
		}

		if(wifi["pass"].is<const char *>()) {
			strlcpy(config->wifi_pass, wifi["pass"] | "", sizeof(config->wifi_pass));
		} else {
			config->wifi_pass[0] = NULL;
		}

	}
	if(coogleiot["mqtt"].is<JsonObject>()) {
		mqtt = coogleiot["mqtt"].as<JsonObject>();

		if(mqtt["host"].is<const char *>()) {
			strlcpy(config->mqtt_host, mqtt["host"] | "", sizeof(config->mqtt_host));
		} else {
			config->mqtt_host[0] = NULL;
		}

		config->mqtt_port = mqtt["port"] | 1883;
	}

	if(coogleiot["ota"].is<JsonObject>()) {
		ota = coogleiot["ota"].as<JsonObject>();

		if(ota["endpoint"].is<const char *>()) {
			strlcpy(config->ota_endpoint, ota["endpoint"] | "", sizeof(config->ota_endpoint));
		} else {
			config->ota_endpoint[0] = NULL;
		}

		config->ota_check_on_boot = (bool)ota["check_on_boot"] | false;
	}

	if(coogleiot["security"].is<JsonObject>()) {
		security = coogleiot["security"].as<JsonObject>();

		config->sec_allow_insecure_ssl = (bool)security["allow_insecure_ssl"] | false;
	}


	if(parseCallback != NULL) {
		if(parseCallback(doc)) {
			loaded = true;
			return true;
		}

		return false;
	}

	loaded = true;
	return true;
}

coogleiot_config_base_t * CoogleIOT_Config::getConfig()
{
	return config;
}

CoogleIOT_Config& CoogleIOT_Config::setConfigStruct(coogleiot_config_base_t *base)
{
	config = base;
	return *this;
}

CoogleIOT_Config& CoogleIOT_Config::setLogger(CoogleIOT_Logger *_logger)
{
	logger = _logger;
	return *this;
}
CoogleIOT_Config& CoogleIOT_Config::setParseCallback(bool (*cb)(DynamicJsonDocument&))
{
	parseCallback = cb;
	return *this;
}
