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

CoogleIOT_Config::~CoogleIOT_Config()
{
	if(server) {
		delete server;
	}
}

bool CoogleIOT_Config::saveConfig()
{
	char *json = asJson();
	File configFile;
	size_t written;

	configFile = SPIFFS.open(COOGLEIOT_CONFIG_FILE, "w");

	if(!configFile) {
		if(logger)
			logger->error(F("Error opening config file for writing!"));

		configFile.close();
		free(json);
		return false;
	}

	written = configFile.write((byte *)json, strlen(json) + 1);

	if(written != (strlen(json) +1)) {
		if(logger)
			logger->logPrintf(ERROR, F("Config write failed, wrote %d instead of %d byte(s)"), written, strlen(json));

		configFile.close();
		free(json);
		return false;
	}

	configFile.close();
	free(json);

	if(logger)
		logger->logPrintf(INFO, F("Successfully stored config file as '%s' (%d byte(s))"), COOGLEIOT_CONFIG_FILE, written);

	return true;
}

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
			logger->error(F("[CONFIG] Failed to start SPIFFS, cannot initialize"));
		return;
	}

	if(!SPIFFS.exists(COOGLEIOT_CONFIG_FILE)) {
		if(logger)
			logger->logPrintf(WARNING, F("[CONFIG] Cannot locate configuration file %s"), COOGLEIOT_CONFIG_FILE);
		return;
	}

	configFile = SPIFFS.open(COOGLEIOT_CONFIG_FILE, "r");

	buffer = (char *)os_zalloc(configFile.size() + 1);

	readBytes = configFile.readBytes(buffer, configFile.size());

	if(readBytes != configFile.size()) {
		if(logger)
			logger->error(F("[CONFIG] Failed to read full config file into buffer"));
		configFile.close();
		free(buffer);
		return;
	}

	if(!setConfigJson(buffer)) {
		if(logger)
			logger->error(F("[CONFIG] Failed to parse configuration JSON"));
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
			logger->logPrintf(ERROR, F("[CONFIG] Failed to deserialize JSON Config: %s"), err.c_str());
		return false;
	}

	if(!doc["coogleiot"].is<JsonObject>()) {
		if(logger)
			logger->error(F("[CONFIG] Invalid Config, no valid 'coogleiot' section"));
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

		if(wifi["hostname"].is<const char *>()) {
			snprintf(config->hostname, sizeof(config->hostname), wifi["hostname"] | "coogleiot-%06x", ESP.getChipId());
		} else {
			config->hostname[0] = NULL;
		}

		if(wifi["ap-name"].is<const char *>()) {
			snprintf(config->ap_name, sizeof(config->ap_name), wifi["ap-name"] | "coogleiot-%06x", ESP.getChipId());
		} else {
			snprintf(config->ap_name, sizeof(config->ap_name), "coogleiot-%06x", ESP.getChipId());
		}

		if(wifi["ap-pass"].is<const char *>()) {
			strlcpy(config->ap_pass, wifi["ap-pass"] | "", sizeof(config->ap_pass));
		} else {
			config->ap_pass[0] = NULL;
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

CoogleIOT_Config::CoogleIOT_Config() { /* ... */ }

CoogleIOT_Config* CoogleIOT_Config::getInstance()
{
	static CoogleIOT_Config instance;
	return &instance;
}

CoogleIOT_Config& CoogleIOT_Config::enableConfigServer()
{
	if(server) {
		if(logger)
			logger->warn(F("Cannot enable config server, server already exists."));
		return *this;
	}

	server = new ESP8266WebServer(80);

	server->on(F("/config"), HTTP_GET, __coogleiot_on_config_get);
	server->on(F("/config"), HTTP_POST, __coogleiot_on_config_set);
	server->on(F("/reboot"), HTTP_POST, __coogleiot_on_reboot);
	server->on(F("/scan"), HTTP_GET, __coogleiot_on_scan);

	server->onNotFound(__coogleiot_config_on_not_found);

	server->begin();

	if(logger)
		logger->info(F("Started Configuration Web Server"));

	return *this;
}

CoogleIOT_Logger* CoogleIOT_Config::getLogger()
{
	return logger;
}

ESP8266WebServer* CoogleIOT_Config::getConfigServer()
{
	return server;
}

char * CoogleIOT_Config::asJson()
{
	DynamicJsonDocument doc(json_config_size);
	JsonObject root, coogleiot, wifi, mqtt, ota, security;

	/* @todo We shouldn't do this, we should use measureJson() instead with a max cap */
	char *output = (char *)os_zalloc(COOGLEIOT_CONFIG_JSON_OUTPUT_SIZE);

	root = doc.to<JsonObject>();
	coogleiot = root.createNestedObject(F("coogleiot"));
	wifi = coogleiot.createNestedObject(F("wifi"));
	mqtt = coogleiot.createNestedObject(F("mqtt"));
	ota = coogleiot.createNestedObject(F("ota"));
	security = coogleiot.createNestedObject(F("security"));

	switch(config->wifi_mode) {
		case WIFI_STA:
			wifi["mode"] = "station";
			break;
		case WIFI_AP:
			wifi["mode"] = "ap";
			break;
		case WIFI_AP_STA:
			wifi["mode"] = "ap-station";
			break;
	}

	wifi["ssid"] = config->wifi_ssid;
	wifi["pass"] = config->wifi_pass;
	wifi["hostname"] = config->hostname;
	wifi["ap-name"] = config->ap_name;
	wifi["ap-pass"] = config->ap_pass;

	mqtt["host"] = config->mqtt_host;
	mqtt["port"] = config->mqtt_port;

	ota["endpoint"] = config->ota_endpoint;
	ota["check_on_boot"] = config->ota_check_on_boot;

	security["allow_insecure_ssl"] = config->sec_allow_insecure_ssl;

	serializeJson(doc, output, COOGLEIOT_CONFIG_JSON_OUTPUT_SIZE);

	return output;
}

CoogleIOT_Config& CoogleIOT_Config::setJsonConfigSize(size_t s)
{
	json_config_size = s;
	return *this;
}

CoogleIOT_Config& CoogleIOT_Config::setRebootCallback(void (*cb)())
{
	rebootCallback = cb;
	return *this;
}

extern "C" void __coogleiot_on_scan()
{
	int numNetworks;
	
	ESP8266WebServer *server;
	CoogleIOT_Config *config;
	CoogleIOT_Logger *logger;
	size_t jsonSize;

	char *json;
	
	JsonObject network;
	JsonArray networkList;

	config = CoogleIOT_Config::getInstance();
	logger = config->getLogger();
	server = config->getConfigServer();

	numNetworks = WiFi.scanNetworks(false, true);

	if(numNetworks == 0) {
		server->send(200, F("application/json"), F("[]"));
		return;
	}

	if(numNetworks > COOGLEIOT_CONFIG_MAX_WIFI_NETWORKS) {
		numNetworks = COOGLEIOT_CONFIG_MAX_WIFI_NETWORKS;
	}

	DynamicJsonDocument doc(JSON_ARRAY_SIZE(numNetworks) + (numNetworks * JSON_OBJECT_SIZE(3)));

	networkList = doc.to<JsonArray>();

	for(int i = 0; i < numNetworks; ++i) {
		network = networkList.createNestedObject();
		network["ssid"] = WiFi.SSID(i);
		network["rssi"] = WiFi.RSSI(i);
		network["enc"] = WiFi.encryptionType(i);
	}

	jsonSize = measureJson(doc) + 1;

	if(jsonSize > COOGLEIOT_MAX_WIFI_NETWORKS_OUTPUT_SIZE) {
		jsonSize = COOGLEIOT_MAX_WIFI_NETWORKS_OUTPUT_SIZE;
	}

	json = (char *)os_zalloc(jsonSize);

	serializeJson(doc, json, jsonSize);

	server->send(200, F("application/json"), json);
	free(json);

}

extern "C" void __coogleiot_on_config_get()
{
	CoogleIOT_Logger *logger;
	CoogleIOT_Config *config;
	ESP8266WebServer *server;
	char *json;

	config = CoogleIOT_Config::getInstance();
	logger = config->getLogger();
	server = config->getConfigServer();

	if(!server) {
		if(logger)
			logger->error(F("Cannot process request, no config server found!"));
		return;
	}

	if(logger)
		logger->info(F("handling Configuration Get Request"));

	json = config->asJson();

	server->send(200, F("application/json"), json);

	free(json);
}

extern "C" void __coogleiot_on_reboot()
{
	CoogleIOT_Logger *logger;
	CoogleIOT_Config *config;
	ESP8266WebServer *server;

	config = CoogleIOT_Config::getInstance();
	logger = config->getLogger();
	server = config->getConfigServer();

	server->send(200, F("text/plain"), F("ok"));

	if(config->rebootCallback) {
		config->rebootCallback();
	}

}

extern "C" void __coogleiot_on_config_set()
{
	CoogleIOT_Logger *logger;
	CoogleIOT_Config *config;
	ESP8266WebServer *server;
	const char *json;

	config = CoogleIOT_Config::getInstance();
	logger = config->getLogger();
	server = config->getConfigServer();

	if(!server) {
		if(logger)
			logger->error(F("Cannot process request, no config server found!"));
		return;
	}

	if(logger)
		logger->info(F("Handling Configuration Set Request"));

	if(server->args() == 0) {
		if(logger)
			logger->warn(F("Bad HTTP Request, invalid arguments"));

		server->send(500, F("text/plain"), F("Invalid Argument(s)"));
		return;
	}

	json = server->arg(0).c_str();

	if(logger)
		logger->logPrintf(DEBUG, F("Received Config: %s"), json);

	if(!config->setConfigJson(json)) {
		server->send(422, F("text/plain"), F("Invalid JSON"));
		return;
	}

	config->saveConfig();


	server->send(200, F("text/plain"), F("ok"));
}

extern "C" void __coogleiot_config_on_not_found()
{
	CoogleIOT_Logger *logger;
	CoogleIOT_Config *config;
	ESP8266WebServer *server;

	config = CoogleIOT_Config::getInstance();
	logger = config->getLogger();
	server = config->getConfigServer();

	if(logger)
		logger->warn(F("[Config] Server 404"));

	server->send(404, F("text/plain"), F("404: Not Found"));
}

CoogleIOT_Config& CoogleIOT_Config::disableConfigServer()
{
	if(!server) {
		if(logger)
			logger->warn(F("Cannot disable config server, no server exists!"));
		return *this;
	}

	delete server;

	return *this;
}

void CoogleIOT_Config::loop()
{
	if(restart) {
		ESP.restart();
		return;
	}

	if(!server) {
		return;
	}

	server->handleClient();
}
