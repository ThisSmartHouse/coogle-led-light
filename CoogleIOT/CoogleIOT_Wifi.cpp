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
#include "CoogleIOT_Wifi.h"

CoogleIOT_Wifi& CoogleIOT_Wifi::setConfigManager(CoogleIOT_Config *c)
{
	configManager = c;
	return *this;
}

CoogleIOT_Wifi& CoogleIOT_Wifi::setLogger(CoogleIOT_Logger *_logger)
{
	logger = _logger;
	return *this;
}

char *CoogleIOT_Wifi::getRemoteAPName()
{
	char *retval = (char *)malloc(strlen(remoteAPName) + 1);

	if(strlen(remoteAPName) > 0) {
		memcpy(retval, &remoteAPName[0], strlen(remoteAPName) + 1);
	}

	return retval;
}

char *CoogleIOT_Wifi::getRemoteAPPassword()
{
	char *retval = (char *)malloc(strlen(remoteAPPassword) + 1);

	if(strlen(remoteAPPassword) > 0) {
		memcpy(retval, &remoteAPPassword[0], strlen(remoteAPPassword) + 1);
	}

	return retval;
}

char *CoogleIOT_Wifi::getLocalAPName()
{
	char *retval = (char *)malloc(strlen(localAPName) + 1);

	if(strlen(localAPName) > 0) {
		memcpy(retval, &localAPName[0], strlen(localAPName) + 1);
	}

	return retval;
}

char *CoogleIOT_Wifi::getLocalAPPassword()
{
	char *retval = (char *)malloc(strlen(localAPPassword) + 1);

	if(strlen(localAPPassword)) {
		memcpy(retval, &localAPPassword[0], strlen(localAPPassword) + 1);
	}

	return retval;
}

const char *CoogleIOT_Wifi::getRemoteStatus()
{
    switch(WiFi.status()) {
        case WL_CONNECTED:
            return PSTR("Connected");
        case WL_NO_SSID_AVAIL:
            return PSTR("No SSID Available");
        case WL_CONNECT_FAILED:
            return PSTR("Failed to Connect");
        case WL_IDLE_STATUS:
            return PSTR("Idle");
        case WL_DISCONNECTED:
        	return PSTR("Disconnected");
        default:
            return PSTR("Unknown");
    }
}

CoogleIOT_Wifi& CoogleIOT_Wifi::setRemoteAPName(String &name)
{
	return setRemoteAPName(name.c_str());
}

CoogleIOT_Wifi& CoogleIOT_Wifi::setRemoteAPName(const char *name)
{
	memset(&remoteAPName[0], NULL, 33);
	memcpy(&remoteAPName[0], name, (strlen(name) > 32) ? 32 : strlen(name));
	return *this;
}

CoogleIOT_Wifi& CoogleIOT_Wifi::setRemoteAPPassword(String &pass)
{
	return setRemoteAPPassword(pass.c_str());
}

CoogleIOT_Wifi& CoogleIOT_Wifi::setRemoteAPPassword(const char *pass)
{
	memset(&remoteAPPassword[0], NULL, 65);
	memcpy(&remoteAPPassword[0], pass, (strlen(pass) > 64) ? 64 : strlen(pass));
	return *this;
}

CoogleIOT_Wifi& CoogleIOT_Wifi::setLocalAPName(String &name)
{
	return setLocalAPName(name.c_str());
}

CoogleIOT_Wifi& CoogleIOT_Wifi::setLocalAPName(const char *name)
{
	memset(&localAPName[0], NULL, 33);
	memcpy(&localAPName[0], name, (strlen(name) > 32) ? 32 : strlen(name));
	return *this;
}

CoogleIOT_Wifi& CoogleIOT_Wifi::setLocalAPPassword(String &pass)
{
	return setLocalAPPassword(pass.c_str());
}

CoogleIOT_Wifi& CoogleIOT_Wifi::setHostname(String &host)
{
	return setHostname(host.c_str());
}

CoogleIOT_Wifi& CoogleIOT_Wifi::setHostname(const char *host)
{
	memset(&hostname[0], NULL, 64);
	memcpy(&hostname[0], host, (strlen(host) > 63) ? 63 : strlen(host));
	return *this;
}

CoogleIOT_Wifi& CoogleIOT_Wifi::setLocalAPPassword(const char *pass)
{
	memset(&localAPPassword[0], NULL, 65);
	memcpy(&localAPPassword[0], pass, (strlen(pass) > 64) ? 64 : strlen(pass));
	return *this;

}

bool CoogleIOT_Wifi::connect()
{
	if(connected()) {
		return true;
	}

	if(attemptingConnection) {
		return false;
	}

	wifiFailuresCount = 0;

	if(strlen(remoteAPName) == 0) {
		return false;
	}

	if(logger)
		logger->logPrintf(INFO, F("[WIFI] Attempting to Connect to SSID: %s"), remoteAPName);

	if(strlen(remoteAPPassword) == 0) {
		if(logger)
			logger->warn(F("[WIFI] Remote AP is an open network"));

		WiFi.begin(remoteAPName, NULL, 0, NULL, true);
	} else {
		WiFi.begin(remoteAPName, remoteAPPassword, 0, NULL, true);
	}

	attemptingConnection = true;

	os_timer_arm(&wifiConnectTimer, COOGLEIOT_WIFI_CONNECT_TIMEOUT, false);

	return true;
}

extern "C" void __coogleiot_wifi_connect_timer_callback(void *self)
{
	CoogleIOT_Wifi *obj = static_cast<CoogleIOT_Wifi *>(self);
	obj->wifiConnectTimerTick = true;
}

void CoogleIOT_Wifi::loop()
{
	if(wifiConnectTimerTick) {
		wifiConnectTimerTick = false;

		wifiFailuresCount++;

		if(logger)
			logger->logPrintf(INFO, F("[WIFI] Waiting for connection, current status: %s"), getRemoteStatus());

		if(wifiFailuresCount > COOGLEIOT_WIFI_MAX_ATTEMPTS) {
			if(logger)
				logger->error(F("[WIFI] Failed to connect to WiFi"));
			attemptingConnection = false;
		} else {
			if(!connected()) {
				os_timer_arm(&wifiConnectTimer, COOGLEIOT_WIFI_CONNECT_TIMEOUT, false);
			} else {
				
				if(logger) {
					logger->logPrintf(INFO, F("[WIFI] Connect success! IP Address: %s"), WiFi.localIP().toString().c_str());
					logger->logPrintf(INFO, F("[WIFI] DNS Server: %s"), WiFi.dnsIP(0).toString().c_str());
				}

				attemptingConnection = false;
			}
		}
	}

	if(!ap_mode) {

		if(!connected() && !attemptingConnection) {
			connect();
		}
	} else {
		setAPMode();
	}
}

CoogleIOT_Wifi& CoogleIOT_Wifi::setStationMode()
{
	WiFi.persistent(false);
	WiFi.disconnect(true);

	WiFi.setAutoConnect(false);
	WiFi.setAutoReconnect(true);
	WiFi.mode(WIFI_STA);

	os_timer_setfn(&wifiConnectTimer, __coogleiot_wifi_connect_timer_callback, this);

	connect();
}

CoogleIOT_Wifi& CoogleIOT_Wifi::setAPMode()
{
	char *ap_name;
	IPAddress ourIP(192,168,57,1);
	IPAddress subnet(255,255,255,0);
	IPAddress ap_ip;

	if(ap_active) {
		return *this;
	}

	ap_name = getLocalAPName();

	WiFi.mode(WIFI_AP_STA);
	
	WiFi.softAPConfig(ourIP, ourIP, subnet);

	if(!WiFi.softAP(ap_name)) {
		if(logger)
			logger->error(F("[WIFI] Failed to initialize Soft AP"));

		free(ap_name);
		return *this;
	}

	if(logger) {
		ap_ip = WiFi.softAPIP();
		logger->logPrintf(INFO, F("[WIFI] Initialized Soft AP '%s' with IP %u.%u.%u.%u"), ap_name, ap_ip[0], ap_ip[1], ap_ip[2], ap_ip[3]);
	}

	ap_active = true;

	free(ap_name);

	return *this;
}

CoogleIOT_Wifi& CoogleIOT_Wifi::enableAP()
{
	if(ap_active) {
		return *this;
	}

	ap_mode = true;
	ap_active = false;

	return *this;
}

CoogleIOT_Wifi& CoogleIOT_Wifi::disableAP()
{
	if(!ap_active) {
		return *this;
	}

	ap_mode = false;
	ap_active = false;

	WiFi.softAPdisconnect(true);

	if(logger)
		logger->info(F("[WIFI] Disabling Soft AP"));

	return *this;
}

bool CoogleIOT_Wifi::initialize()
{
	coogleiot_config_base_t *config;

	if(logger)
		logger->info(F("[WIFI] Initializing Wifi Management"));

	if(configManager) {
		if(configManager->loaded) {
			config = configManager->getConfig();
			setRemoteAPName(config->wifi_ssid);
			setRemoteAPPassword(config->wifi_pass);
			setHostname(config->hostname);
			setLocalAPName(config->ap_name);
			setLocalAPPassword(config->ap_pass);
		}
	}

	if(!ap_mode) {
		setStationMode();
	} else {
		setAPMode();
	}

}

bool CoogleIOT_Wifi::connected()
{
	return (WiFi.status() == WL_CONNECTED);
}
