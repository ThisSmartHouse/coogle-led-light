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
#ifndef COOGLEIOT_OTA_H_
#define COOGLEIOT_OTA_H_

#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClientSecureBearSSL.h>

#include "CoogleIOT_Logger.h"
#include "CoogleIOT_Wifi.h"
#include "CoogleIOT_NTP.h"
#include "CoogleIOT_Config.h"
#include "CoogleIOT_Utils.h"
#include "SPIFFSCertStoreFile.h"
#include "ArduinoJson.h"
#include "rboot-api.h"

#ifndef COOGLEIOT_OTA_HTTP_TIMEOUT
#define COOGLEIOT_OTA_HTTP_TIMEOUT 5000
#endif

#ifndef COOGLEIOT_OTA_CHECK_FOR_UPGRADE_DELAY
#define COOGLEIOT_OTA_CHECK_FOR_UPGRADE_DELAY 300000
#endif

#ifndef COOGLEIOT_OTA_VERIFICATION_WAIT_TIME
#define COOGLEIOT_OTA_VERIFICATION_WAIT_TIME 20000
#endif

#ifndef COOGLEIOT_OTA_MAX_MANIFEST_PATH_LEN
#define COOGLEIOT_OTA_MAX_MANIFEST_PATH_LEN 128
#endif

#ifndef COOGLEIOT_OTA_MAX_VERSION_LEN
#define COOGLEIOT_OTA_MAX_VERSION_LEN 16
#endif

#define COOGLEIOT_MAX_MANIFEST_LEN (COOGLEIOT_OTA_MAX_MANIFEST_PATH_LEN + 253 + 5)

#define COOGLEIOT_FLASH_BY_ADDR 0xff

#define COOGLEIOT_UPGRADE_IDLE			0x00
#define COOGLEIOT_UPGRADE_STARTED		0x01
#define COOGLEIOT_UPGRADE_FINISHED		0x02

class CoogleIOT_Logger;
class CoogleIOT_Wifi;
class CoogleIOT_NTP;
class CoogleIOT_Config;

class CoogleIOT_OTA
{
	public:

		~CoogleIOT_OTA();
		void loop();
		void initialize();
		void check();

		CoogleIOT_OTA& setLogger(CoogleIOT_Logger *);
		CoogleIOT_OTA& setWifiManager(CoogleIOT_Wifi *);
		CoogleIOT_OTA& setNTPManager(CoogleIOT_NTP *);
		CoogleIOT_OTA& setConfigManager(CoogleIOT_Config *);
		CoogleIOT_OTA& setCurrentVersion(const char *);
		CoogleIOT_OTA& setOTAManifestEndpoint(const char *);
		CoogleIOT_OTA& setManifestSize(size_t);
		CoogleIOT_OTA& verifyOTAComplete();
		CoogleIOT_OTA& setSSLClient(BearSSL::WiFiClientSecure *);
		CoogleIOT_OTA& setWiFiClient(WiFiClient *);
		CoogleIOT_OTA& useSSL(bool);

		CoogleIOT_OTA& disableOtaCheckTimer();
		CoogleIOT_OTA& enableOtaCheckTimer();

		CoogleIOT_OTA& disableAutoOTAVerify();

		CoogleIOT_OTA& setUpgradeAvailableCallback(void (*)(const JsonDocument &));
		CoogleIOT_OTA& setOTACompleteCallback(void (*)());
		CoogleIOT_OTA& setPreUpgradeCheckCallback(bool (*)());
		CoogleIOT_OTA& setPostUpgradeCheckCallback(void (*)());
		CoogleIOT_OTA& setUpgradeVerifyCallback(void (*)());

		CoogleIOT_OTA& enable();
		CoogleIOT_OTA& disable();

		void upgrade(const char *);

		bool updateTimerTick = false;

	private:

		char *cur_version = NULL;
		char *endpoint = NULL;
		char *ca = NULL;

		bool loadAuthorities();
		bool writeChunk();
		bool finishUpgrade();

		bool enabled = true;
		bool auto_ota_verify = true;
		bool use_ssl = true;

		size_t firmware_remaining;
		size_t firmware_size;

		uint8_t upgrade_target;
		rboot_write_status upgrade_write_status;
		rboot_config boot_config;

		void (* completeCallback)() = NULL;
		void (* upgradeAvailableCallback)(const JsonDocument &) = NULL;
		bool (* preUpgradeCheckCallback)() = NULL;
		void (* postUpgradeCheckCallback)() = NULL;
		void (* upgradeVerifyCallback)() = NULL;

		os_timer_t ota_check_timer;

		CoogleIOT_Logger *logger = NULL;
		CoogleIOT_NTP *ntp = NULL;
		CoogleIOT_Wifi *wifiManager = NULL;
		CoogleIOT_Config *configManager = NULL;

		HTTPClient *client = NULL;
		HTTPClient *insecureClient = NULL;
		BearSSL::WiFiClientSecure *sslClient = NULL;
		WiFiClient *insecureWiFiClient = NULL;

		SPIFFSCertStoreFile *certs_idx = NULL;
		SPIFFSCertStoreFile *certs_ar = NULL;
		BearSSL::CertStore  *cert_store = NULL;

		size_t manifest_size = JSON_OBJECT_SIZE(3) + 120;

};
#endif
