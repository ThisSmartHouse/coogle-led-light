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
#include "CoogleIOT_MQTT.h"

extern "C" void __coogleiot_mqtt_connect_timer_callback(void *self)
{
	CoogleIOT_MQTT *obj = static_cast<CoogleIOT_MQTT *>(self);
	obj->connectTimerTick = true;
}

CoogleIOT_MQTT& CoogleIOT_MQTT::setClient(WiFiClient *c)
{
	espClient = c;

	if(espClientSecure) {
		espClientSecure = NULL;
	}

	if(mqttClient) {
		delete mqttClient;
		mqttClient = new PubSubClient(*c);
	}

	useSecure = false;
	return *this;
}

CoogleIOT_MQTT& CoogleIOT_MQTT::setClient(WiFiClientSecure *c)
{
	espClientSecure = c;

	if(espClient) {
		espClient = NULL;
	}

	if(mqttClient) {
		delete mqttClient;
		mqttClient = new PubSubClient(*c);
	}

	useSecure = true;
	return *this;
}

bool CoogleIOT_MQTT::initialize()
{
	coogleiot_config_base_t *config;

	if(!espClient && !espClientSecure) {
		espClient = new WiFiClient();
		useSecure = false;

		if(logger)
			logger->warn(F("[MQTT] No WiFi client specified, using insecure by default"));
	}

	if(useSecure) {
		mqttClient = new PubSubClient(*espClientSecure);
	} else {
		mqttClient = new PubSubClient(*espClient);
	}

	os_timer_setfn(&connectTimer, __coogleiot_mqtt_connect_timer_callback, this);

	if(configManager) {
		if(configManager->loaded) {
			config = configManager->getConfig();

			setPort(config->mqtt_port);
			setHostname(config->mqtt_host);

			if(logger)
				logger->info(F("[MQTT] Loaded Configuration from Config Manager"));
		}
	}
}

void CoogleIOT_MQTT::disconnect()
{
	active = false;

	if(connected()) {
		mqttClient->disconnect();
	}
}

void CoogleIOT_MQTT::connect()
{
	active = true;
	attempting = true;

	if(!doConnect()) {
		os_timer_arm(&connectTimer, COOGLEIOT_MQTT_CONNECT_RETRY, false);
	}
}

bool CoogleIOT_MQTT::doConnect()
{
	bool cResult;

	if(!wifiManager) {
		return false;
	}

	if(!wifiManager->connected()) {
		return false;
	}

	if(!strlen(hostname)) {
		if(logger)
			logger->debug(F("[MQTT] Cannot connect, no host name provided"));
		return false;
	}

	if((port < 1) || (port > 65535)) {
		if(logger)
			logger->debug(F("[MQTT] Cannot connect, invalid port"));
		return false;
	}

	if(!strlen(client_id)) {
		if(logger) 
			logger->debug(F("[MQTT] Cannot Connect, no client_id"));
		return false;
	}

	mqttClient->setServer(hostname, port);

	if(mqttClient->connected()) {
		return true;
	}

	if(logger)
		logger->logPrintf(DEBUG, F("[MQTT] Attempting to connect to %s:%d (client: %s)"), hostname, port, client_id);

	if(strlen(username) == 0) {
		if(strlen(lwt_topic) == 0) {
			yield();
			cResult = mqttClient->connect(client_id);
		} else {
			if(strlen(lwt_msg) > 0) {

				cResult = mqttClient->connect(client_id, lwt_topic, 0, false, lwt_msg);

			} else {

				if(logger)
					logger->warn(F("[MQTT] Cannot register LWT topic, no message provided."));

				cResult = mqttClient->connect(client_id);
			}
		}
	} else {
		if(strlen(lwt_topic) == 0) {
			cResult = mqttClient->connect(client_id, username, password);
		} else {
			if(strlen(lwt_msg) > 0) {
				cResult = mqttClient->connect(client_id, username, password, lwt_topic, 0, false, lwt_msg);
			} else {
				if(logger)
					logger->warn(F("[MQTT] Cannot register LWT topic, no message provided."));
				cResult = mqttClient->connect(client_id, username, password, lwt_topic, 0, false, lwt_msg);
			}
		}
	}

	if(logger)
		logger->debug("[MQTT] Checking to see if it's connected");

	if(!mqttClient->connected()) {

		if(logger) {
			switch(mqttClient->state()) {

				case MQTT_CONNECTION_TIMEOUT:
					logger->error(F("[MQTT] Failure: Connection Timeout (server didn't respond within keep alive time)"));
					break;
				case MQTT_CONNECTION_LOST:
					logger->error(F("[MQTT] Failure: Connection Lost (the network connection was broken)"));
					break;
				case MQTT_CONNECT_FAILED:
					logger->error(F("[MQTT] Failure: Connection Failed (the network connection failed)"));
				case MQTT_DISCONNECTED:
					logger->error(F("[MQTT] Failure: Disconnected (the client is disconnected)"));
					break;
				case MQTT_CONNECTED:
					logger->error(F("[MQTT] reported as not connected, but state says it is!"));
					break;
				case MQTT_CONNECT_BAD_PROTOCOL:
					logger->error(F("[MQTT] Failure: Bad Protocol (the server doesn't support the requested version of MQTT)"));
					break;
				case MQTT_CONNECT_BAD_CLIENT_ID:
					logger->error(F("[MQTT] Failure: Bad Client ID (the server rejected the client identifier)"));
					break;
				case MQTT_CONNECT_UNAVAILABLE:
					logger->error(F("[MQTT] Failure: Unavailable (the server was unable to accept the connection)"));
					break;
				case MQTT_CONNECT_BAD_CREDENTIALS:
					logger->error(F("[MQTT] Failure: Bad Credentials (the user name/password were rejected)"));
					break;
				case MQTT_CONNECT_UNAUTHORIZED:
					logger->error(F("[MQTT] Failure: Unauthorized (the client was not authorized to connect)"));
					break;
				default:
					logger->error(F("[MQTT] Failure: Unknown Error"));
					break;
			}

			if(useSecure) {
				char buf[256];
				espClientSecure->getLastSSLError(buf, 256);
				logger->logPrintf(DEBUG, "[MQTT] Last SSL Error: %s", buf);
			}

			logger->error(F("[MQTT] Failed to connect to server!"));
		}

		return false;
	}

	if(logger)
		logger->debug(F("[MQTT] Connected"));

	if(connectCallback) {
		connectCallback();
	}

	attempting = false;

	return true;
}

CoogleIOT_MQTT& CoogleIOT_MQTT::setConnectCallback(void(*cb)())
{
	this->connectCallback = cb;
	return *this;
}

PubSubClient* CoogleIOT_MQTT::getClient()
{
	return mqttClient;
}

bool CoogleIOT_MQTT::connected()
{
	if(!active) {
		return false;
	}
	
	return mqttClient->connected();
}

void CoogleIOT_MQTT::loop()
{
	if(active) {
		if(mqttClient) {
			mqttClient->loop();
		}
	}

	if(connectTimerTick) {
		connectTimerTick = false;

		if(!connected() && active) {

			if(!wifiManager) {
				os_timer_arm(&connectTimer, COOGLEIOT_MQTT_CONNECT_RETRY, false);
			} else {
				if(!wifiManager->connected()) {
					os_timer_arm(&connectTimer, COOGLEIOT_MQTT_CONNECT_RETRY, false);
				}
			}

			if(!doConnect()) {
				os_timer_arm(&connectTimer, COOGLEIOT_MQTT_CONNECT_RETRY, false);
			}
		}

		return;
	}

	if(active && !attempting) {
		if(!connected()) {
			connect();
		}
	}

}

CoogleIOT_MQTT& CoogleIOT_MQTT::setPort(uint16_t port)
{
	this->port = port;
	return *this;
}

CoogleIOT_MQTT& CoogleIOT_MQTT::setHostname(const char *hostname)
{
	memset(&this->hostname[0], NULL, COOGLEIOT_MQTT_MAX_HOSTNAME_LEN + 1);
	memcpy(&this->hostname[0], hostname, (strlen(hostname) > COOGLEIOT_MQTT_MAX_HOSTNAME_LEN) ?
											COOGLEIOT_MQTT_MAX_HOSTNAME_LEN : strlen(hostname));
	return *this;
}

CoogleIOT_MQTT& CoogleIOT_MQTT::setUsername(const char *username)
{
	memset(&this->username[0], NULL, COOGLEIOT_MQTT_MAX_USERNAME_LEN + 1);
	memcpy(&this->username[0], username, (strlen(username) > COOGLEIOT_MQTT_MAX_USERNAME_LEN) ?
											COOGLEIOT_MQTT_MAX_USERNAME_LEN : strlen(username));

	return *this;
}

CoogleIOT_MQTT& CoogleIOT_MQTT::setPassword(const char *password)
{
	memset(&this->password[0], NULL, COOGLEIOT_MQTT_MAX_PASSWORD_LEN + 1);
	memcpy(&this->password[0], password, (strlen(password) > COOGLEIOT_MQTT_MAX_PASSWORD_LEN) ?
											COOGLEIOT_MQTT_MAX_PASSWORD_LEN : strlen(password));
	return *this;
}

CoogleIOT_MQTT& CoogleIOT_MQTT::setLWTTopic(const char *topic)
{
	memset(&this->lwt_topic[0], NULL, COOGLEIOT_MQTT_MAX_LWT_TOPIC_LEN + 1);
	memcpy(&this->lwt_topic[0], topic, (strlen(topic) > COOGLEIOT_MQTT_MAX_LWT_TOPIC_LEN) ?
											COOGLEIOT_MQTT_MAX_LWT_TOPIC_LEN : strlen(topic));

	return *this;
}

CoogleIOT_MQTT& CoogleIOT_MQTT::setLWTMessage(const char *msg)
{
	memset(&this->lwt_msg[0], NULL, COOGLEIOT_MQTT_MAX_LWT_MSG_LEN + 1);
	memcpy(&this->lwt_msg[0], msg, (strlen(msg) > COOGLEIOT_MQTT_MAX_LWT_MSG_LEN) ?
											COOGLEIOT_MQTT_MAX_LWT_MSG_LEN : strlen(msg));

	return *this;
}

CoogleIOT_MQTT& CoogleIOT_MQTT::setClientId(const char *id)
{
	memset(&this->client_id[0], NULL, COOGLEIOT_MQTT_MAX_CLIENT_ID_LEN + 1);
	memcpy(&this->client_id[0], id, (strlen(id) > COOGLEIOT_MQTT_MAX_CLIENT_ID_LEN) ?
											COOGLEIOT_MQTT_MAX_CLIENT_ID_LEN : strlen(id));

	return *this;
}

const char *CoogleIOT_MQTT::getClientId()
{
	return &client_id[0];
}

CoogleIOT_MQTT& CoogleIOT_MQTT::setLogger(CoogleIOT_Logger *log)
{
	this->logger = log;
	return *this;
}

CoogleIOT_MQTT& CoogleIOT_MQTT::setWifiManager(CoogleIOT_Wifi *wifi)
{
	this->wifiManager = wifi;
	return *this;
}

CoogleIOT_MQTT& CoogleIOT_MQTT::setConfigManager(CoogleIOT_Config *c)
{
	this->configManager = c;
	return *this;
}
