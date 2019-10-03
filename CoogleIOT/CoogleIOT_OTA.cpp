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
#include "CoogleIOT_OTA.h"

extern "C" void __coogleiot_ota_check_callback(void *self)
{
	CoogleIOT_OTA *obj = static_cast<CoogleIOT_OTA *>(self);
	obj->updateTimerTick = true;
}

CoogleIOT_OTA& CoogleIOT_OTA::setUpgradeAvailableCallback(void (*cb)(const JsonDocument &)) 
{
	upgradeAvailableCallback = cb;
	return *this;
}

CoogleIOT_OTA& CoogleIOT_OTA::setPostUpgradeCheckCallback(void (*cb)())
{
	postUpgradeCheckCallback = cb;
	return *this;
}

CoogleIOT_OTA& CoogleIOT_OTA::disableAutoOTAVerify()
{
	auto_ota_verify = false;
}

CoogleIOT_OTA& CoogleIOT_OTA::verifyOTAComplete()
{
	uint8_t last_boot_mode;
	uint8_t newRom;

	if(!rboot_get_last_boot_mode(&last_boot_mode)) {
		if(logger)
			logger->error(F("[OTA] Failed to get last boot mode"));
		return *this;
	}

	if(last_boot_mode != MODE_TEMP_ROM) {
		if(logger)
			logger->error(F("[OTA] Cannot call verifyOTAComplete() if not booted into temporary ROM"));
		return *this;
	}

	if(logger)
		logger->info(F("[OTA] Firmware lives! Setting temporary firmware as real firmware"));

	newRom = boot_config.current_rom == 0 ? 1 : 0;

	if(!rboot_set_current_rom(newRom)) {
		if(logger)
			logger->logPrintf(ERROR, F("[OTA] Failed to set new current rom to %d"), newRom);
		return *this;
	}

	if(logger)
		logger->logPrintf(INFO, F("[OTA] Verification complete! New ROM for device is slot %d"), newRom);

	return *this;
}

CoogleIOT_OTA& CoogleIOT_OTA::setOTAManifestEndpoint(const char *end)
{
	size_t endpoint_len = strlen(end) > COOGLEIOT_MAX_MANIFEST_LEN ?
							(COOGLEIOT_MAX_MANIFEST_LEN + 1) :
							(strlen(end) + 1);

	endpoint = (char *)os_zalloc(endpoint_len);
	memcpy(endpoint, end, endpoint_len);

	return *this;
}

CoogleIOT_OTA& CoogleIOT_OTA::setCurrentVersion(const char *ver)
{
	size_t version_len = strlen(ver) > COOGLEIOT_OTA_MAX_VERSION_LEN ?
							(COOGLEIOT_OTA_MAX_VERSION_LEN + 1) :
							(strlen(ver) + 1);

	cur_version = (char *)os_zalloc(version_len);
	memcpy(cur_version, ver, version_len);

	return *this;
}

CoogleIOT_OTA& CoogleIOT_OTA::setManifestSize(size_t s)
{
	manifest_size = s;
	return *this;
}

CoogleIOT_OTA& CoogleIOT_OTA::useSSL(bool b)
{
	use_ssl = b;
	return *this;
}

void CoogleIOT_OTA::check()
{
	int httpResponseCode;
	String response;
	char *endpoint_complete;
	DynamicJsonDocument manifest(manifest_size);
	DeserializationError err;
	bool beginResult;

	if(system_upgrade_flag_check() == COOGLEIOT_UPGRADE_STARTED) {
		return;
	}

	if(!enabled) {

		if(postUpgradeCheckCallback) {
			postUpgradeCheckCallback();
		}

		return;
	}

	if(!ntp->active()) {
		if(logger)
			logger->warn(F("[OTA] Cannot perform OTA check, NTP is not active"));

		if(postUpgradeCheckCallback) {
			postUpgradeCheckCallback();
		}

		return;
	}

	if(strlen(endpoint) < 10) {
		if(logger)
			logger->warn(F("[OTA] End point not set"));

		if(postUpgradeCheckCallback) {
			postUpgradeCheckCallback();
		}

		return;
	}

	if(preUpgradeCheckCallback) {
		if(!preUpgradeCheckCallback()) {
			if(logger)
				logger->info(F("[OTA] Skipping check on instruction from callback"));

			if(postUpgradeCheckCallback) {
				postUpgradeCheckCallback();
			}

			return;
		}
	}

	if(cur_version != NULL) {
		size_t endpoint_len;
		char *encoded_ver;

		encoded_ver = CoogleIOT_Utils::url_encode(cur_version);

		endpoint_len = snprintf(NULL, 0, "%s?current_version=%s", endpoint, encoded_ver) + 1;
		endpoint_complete = (char *)os_zalloc(endpoint_len);

		sprintf(endpoint_complete, "%s?current_version=%s", endpoint, encoded_ver);

		free(encoded_ver);

	} else {

		endpoint_complete = (char *)os_zalloc(strlen(endpoint) + 1);
		strcpy(endpoint_complete, endpoint);
	}

	if(logger)
		logger->logPrintf(INFO, F("[OTA] Checking %s for new firmware"), endpoint_complete);

	if(use_ssl) {
		beginResult = client->begin(*sslClient, endpoint_complete);
	} else {
		beginResult = client->begin(*insecureWiFiClient, endpoint_complete);
	}

	if(!beginResult) {
		if(logger)
			logger->logPrintf(ERROR, F("Failed to connect to end point: %s"), endpoint_complete);

		free(endpoint_complete);

		if(postUpgradeCheckCallback) {
			postUpgradeCheckCallback();
		}

		return;
	}

	httpResponseCode = client->GET();

	if(httpResponseCode < 0) {
		if(logger)
			logger->logPrintf(ERROR, F("[OTA] HTTP request to end point '%s' failed: %s"), endpoint_complete, client->errorToString(httpResponseCode).c_str());

		client->end();

		free(endpoint_complete);

		if(postUpgradeCheckCallback) {
			postUpgradeCheckCallback();
		}

		return;
	}

	switch(httpResponseCode) {

		case HTTP_CODE_OK:
			response = client->getString();

			if(logger)
				logger->debug(response.c_str());

			// This is important to cast to (const char *)
			// ArduinoJson otherwise uses a zero-copy and response.c_str()
			// won't be around long enough to pass into a callback
			err = deserializeJson(manifest, (const char *)response.c_str());

			if(err) {
				if(logger)
					logger->logPrintf(ERROR, F("Failed to deserialize JSON Manifest: %s"), err.c_str());
				break;
			}

			if(!manifest["version"].is<const char *>()) {
				if(logger)
					logger->error(F("Manifest malformed, invalid version"));

				break;
			}

			if(!manifest["url"].is<const char *>()) {
				if(logger)
					logger->error(F("Manifest malformed, invalid firmware URL"));
				break;
			}

			if(strcmp(manifest["version"].as<const char *>(), cur_version) == 0) {
				if(logger)
					logger->logPrintf(INFO, F("Version available '%s' matches current firmware version"), cur_version);
				break;
			}

			if(logger)
				logger->logPrintf(INFO, F("New version '%s' available for upgrade!"), manifest["version"].as<const char *>());

			client->end();

			free(endpoint_complete);

			if(upgradeAvailableCallback) {
				upgradeAvailableCallback(manifest);
			} else {
				upgrade(manifest["url"].as<const char *>());
			}

			return;
		default:

			if(logger)
				logger->logPrintf(ERROR, F("[OTA] Unexpected HTTP Response Code: %d"), httpResponseCode);

			break;
	}

	client->end();

	free(endpoint_complete);

	if(postUpgradeCheckCallback) {
		postUpgradeCheckCallback();
	}

}

CoogleIOT_OTA& CoogleIOT_OTA::setPreUpgradeCheckCallback(bool (*cb)())
{
	preUpgradeCheckCallback = cb;
	return *this;
}

CoogleIOT_OTA& CoogleIOT_OTA::setOTACompleteCallback(void (*cb)())
{
	completeCallback = cb;
	return *this;
}

void CoogleIOT_OTA::upgrade(const char *url)
{
	int httpResponseCode;
	
	if(!insecureClient->begin(url)) {
		if(logger)
			logger->logPrintf(ERROR, F("Failed to connect to end point: %s"), url);
		return;
	}

	httpResponseCode = insecureClient->GET();

	if(httpResponseCode < 0) {
		if(logger)
			logger->logPrintf(ERROR, F("[OTA] HTTP request to end point '%s' failed: %s"), url, insecureClient->errorToString(httpResponseCode).c_str());

		if(insecureClient->connected())
			insecureClient->end();

		return;
	}

	if(httpResponseCode != HTTP_CODE_OK) {
		if(logger)
			logger->logPrintf(ERROR, F("[OTA] Unexpected HTTP Response Code: %d"), httpResponseCode);

		if(insecureClient->connected())
			insecureClient->end();

		return;
	}

	firmware_remaining = insecureClient->getSize();
	firmware_size = firmware_remaining;

	upgrade_target = (boot_config.current_rom == 0) ? 1 : 0;

	upgrade_write_status = rboot_write_init(boot_config.roms[upgrade_target]);

	system_upgrade_flag_set(COOGLEIOT_UPGRADE_STARTED);

	if(logger) {
		logger->info(F("Firmware Upgrade"));
		logger->logPrintf(INFO, F("Firmware Size: %d"), firmware_size);
		logger->logPrintf(INFO, F("Upgrade Slot: %d"), upgrade_target);
		logger->info(F("Downloading Firmware...."));
	}

}

bool CoogleIOT_OTA::writeChunk()
{
	uint8_t readBuffer[512] = {NULL};
	size_t available_data, bytes_read;
	
	int percentage;
	static int next_percentage = 0;

	if(firmware_remaining == 0) {
		return finishUpgrade();
	}

	if(!insecureClient->connected()) {
		if(logger)
			logger->error(F("Client is unexpectantly disconnected!"));

		return false;
	}

	available_data = insecureClient->getStreamPtr()->available();

	if(available_data > 0) {
		bytes_read = insecureClient->getStreamPtr()->readBytes(readBuffer, ((available_data > sizeof(readBuffer)) ? sizeof(readBuffer) : available_data));

		if(!rboot_write_flash(&upgrade_write_status, &readBuffer[0], bytes_read)) {
			if(logger)
				logger->logPrintf(ERROR, F("[OTA] Failed to write chunk (%d byte(s)) to flash!"), bytes_read);

			return false;
		}

		if((firmware_remaining > 0) && (bytes_read > 0)) {
			firmware_remaining -= bytes_read;
		}

		if(logger) {

			percentage = ((float)(firmware_size - firmware_remaining) / (float)firmware_size) * 100;

			if(next_percentage == 0) {
				next_percentage = percentage;
			}

			if((percentage >= next_percentage) && (percentage > 0)) {
				logger->logPrintf(INFO, F("[OTA] Upgrade %d%% complete"), percentage);
				next_percentage = percentage - (percentage % 10) + 10;
			}
		}

	}

	return true;
}

bool CoogleIOT_OTA::finishUpgrade()
{
	uint8_t newRom;

	if(logger)
		logger->info(F("[OTA] Firmware write complete!"));

	system_upgrade_flag_set(COOGLEIOT_UPGRADE_FINISHED);

	newRom = (rboot_get_current_rom() == 0) ? 1 : 0;

	if(logger)
		logger->logPrintf(INFO, F("Switching to ROM #%d"), newRom);

	if(!rboot_set_temp_rom(newRom)) {
		if(logger)
			logger->logPrintf(ERROR, F("Failed to set temporary boot target #%d"), newRom);
		return false;
	}

	if(completeCallback) {
		completeCallback();
	}

	return true;
}

CoogleIOT_OTA::~CoogleIOT_OTA()
{
	if(insecureClient) {
		delete insecureClient;
	}
	
	if(client) {
		delete client;
	}

	if(sslClient) {
		delete sslClient;
	}

	if(ca) {
		free(ca);
	}

	if(endpoint) {
		free(endpoint);
	}

	if(cur_version) {
		free(cur_version);
	}

	if(certs_idx) {
		delete certs_idx;
	}

	if(certs_ar) {
		delete certs_ar;
	}

	if(cert_store) {
		delete cert_store;
	}
}

CoogleIOT_OTA& CoogleIOT_OTA::setWiFiClient(WiFiClient *c)
{
	insecureWiFiClient = c;
	return *this;
}

CoogleIOT_OTA& CoogleIOT_OTA::setSSLClient(BearSSL::WiFiClientSecure *c)
{
	sslClient = c;
	return *this;
}

CoogleIOT_OTA& CoogleIOT_OTA::disableOtaCheckTimer()
{
	os_timer_disarm(&ota_check_timer);
	updateTimerTick = false;
	return *this;
}

CoogleIOT_OTA& CoogleIOT_OTA::enableOtaCheckTimer()
{
	os_timer_arm(&ota_check_timer, COOGLEIOT_OTA_CHECK_FOR_UPGRADE_DELAY, true);
	return *this;
}

CoogleIOT_OTA& CoogleIOT_OTA::setUpgradeVerifyCallback(void (*cb)())
{
	upgradeVerifyCallback = cb;
	return *this;
}

void CoogleIOT_OTA::initialize()
{
	uint8_t last_boot_mode;
	coogleiot_config_base_t *config;

	if(logger)
		logger->info(F("[OTA] Initializing Over-The-Air Firmware Updates"));

	os_timer_setfn(&ota_check_timer, __coogleiot_ota_check_callback, this);

	enableOtaCheckTimer();

	client = new HTTPClient;
	insecureClient = new HTTPClient;

	if(!sslClient) {
		sslClient = new BearSSL::WiFiClientSecure;

		if(!loadAuthorities()) {
			disable();

			if(logger)
				logger->error(F("[OTA] Failed to load certificate authorities for SSL, OTA disabled."));
		}

	}

	if(!insecureWiFiClient) {
		insecureWiFiClient = new WiFiClient;
	}

	if(ntp == NULL) {
		disable();

		if(logger)
			logger->error(F("[OTA] OTA requires the NTP Manager, OTA disabled."));

	}

	system_upgrade_flag_set(COOGLEIOT_UPGRADE_IDLE);

	boot_config = rboot_get_config();

	if(!rboot_get_last_boot_mode(&last_boot_mode)) {
		if(logger)
			logger->error(F("[OTA] Failed to get last boot mode from rBoot!"));

		last_boot_mode = MODE_STANDARD;
	}

	if((last_boot_mode == MODE_TEMP_ROM) ) {
		if(upgradeVerifyCallback) {
			upgradeVerifyCallback();
		}
	}

	if(configManager) {
		if(configManager->loaded) {
			config = configManager->getConfig();

			if(config->ota_check_on_boot) {
				if(last_boot_mode == MODE_TEMP_ROM) {
					if(logger)
						logger->info(F("[OTA] Skipping OTA on initialize request, currently booted in temporary ROM"));
				} else {
					updateTimerTick = true;
				}
			}

			if(strlen(config->ota_endpoint) > 0) {
				setOTAManifestEndpoint(config->ota_endpoint);

				if(logger)
					logger->logPrintf(INFO, F("[OTA] Upgrade Manifest URL set to %s"), config->ota_endpoint);
			}
		}
	}
}

void CoogleIOT_OTA::loop()
{
	if(updateTimerTick) {
		disableOtaCheckTimer();
		yield();
		check();
		enableOtaCheckTimer();
	}

	if(system_upgrade_flag_check() == COOGLEIOT_UPGRADE_STARTED) {
		if(!writeChunk()) {
			if(logger)
				logger->error(F("[OTA] Failed to write firmware chunk, aborting"));

			if(client->connected())
				client->end();

			system_upgrade_flag_set(COOGLEIOT_UPGRADE_IDLE);
		}
	}
}

bool CoogleIOT_OTA::loadAuthorities()
{
	int numCertificates;

	if(!SPIFFS.exists("/certs.ar")) {
		if(logger)
			logger->warn(F("[OTA] Cannot locate /certs.ar - no certificates loaded"));

		return false;
	}

	certs_idx = new SPIFFSCertStoreFile("/certs.idx");
	certs_ar  = new SPIFFSCertStoreFile("/certs.ar");
	cert_store = new BearSSL::CertStore;

	numCertificates = cert_store->initCertStore(certs_idx, certs_ar);

	sslClient->setCertStore(cert_store);

	if(logger)
		logger->logPrintf(INFO, F("[OTA] Loaded %d certificates into certificate store"), numCertificates);

#ifdef COOGLEIOT_ALLOW_INSECURE_SSL
	if(logger)
		logger->warn(F("[OTA] Allowing Insecure SSL connections"));

	sslClient->setInsecure();
#endif

	if(logger)
		logger->info(F("[OTA] Certificate Authority Loaded"));

	return true;
}

CoogleIOT_OTA& CoogleIOT_OTA::enable()
{
	enabled = true;
}

CoogleIOT_OTA& CoogleIOT_OTA::disable()
{
	enabled = false;
}

CoogleIOT_OTA& CoogleIOT_OTA::setNTPManager(CoogleIOT_NTP *_ntp)
{
	ntp = _ntp;
	return *this;
}

CoogleIOT_OTA& CoogleIOT_OTA::setWifiManager(CoogleIOT_Wifi *wifi)
{
	wifiManager = wifi;
	return *this;
}

CoogleIOT_OTA& CoogleIOT_OTA::setConfigManager(CoogleIOT_Config *c)
{
	configManager = c;
	return *this;
}

CoogleIOT_OTA& CoogleIOT_OTA::setLogger(CoogleIOT_Logger *_logger)
{
	logger = _logger;
	return *this;
}
