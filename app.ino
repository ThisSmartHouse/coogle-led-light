/*
  +----------------------------------------------------------------------+
  | Coogle LED lighting                                                  |
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

/**
 * Arduino libs must be included in the .ino file to be detected by the build system
 */
#include <FS.h>
#include <ESP8266WiFi.h>
#include <WiFiClient.h>
#include <FastLED.h>
#include <Hash.h>
#include <PubSubClient.h>
#include "ArduinoJson.h"
#include "app.h"

FASTLED_USING_NAMESPACE

CRGB leds[NUM_LEDS];

void onMQTTCommand(const char *topic, byte *payload, unsigned int length)
{
	DynamicJsonDocument doc(json_state_size);
	DeserializationError err;
	JsonObject color;
	CoogleIOT_Logger *logger = _ciot_log;
	char *buffer;

	buffer = (char *)malloc(length);

	memcpy(buffer, payload, length+1);
	buffer[length] = '\0';

	if(logger)
		logger->logPrintf(DEBUG, "Message Received: %s (%d bytes)", buffer, strlen(buffer));

	if(new_state) {
		if(new_state->effect) {
			free(new_state->effect);
		}

		if(new_state->state) {
			free(new_state->state);
		}

		free(new_state);
	}

	err = deserializeJson(doc, buffer);

	if(err) {
		LOG_PRINTF(ERROR, "Failed to deserialize JSON Document: %s", err.c_str());
		free(buffer);
		return;
	}

	new_state = (app_light_state *)malloc(sizeof(app_light_state));

	memset(new_state, NULL, sizeof(app_light_state));

	color = doc["color"];

	new_state->brightness = doc["brightness"];
	new_state->color.r = color["r"];
	new_state->color.g = color["g"];
	new_state->color.b = color["b"];
	new_state->transition = doc["transition"];

	if(strlen(doc["effect"]) > 0) {
		memcpy(&new_state->effect, doc["effect"].as<const char*>(), strlen(doc["effect"]));
	}

	if(strlen(doc["state"]) > 0) {
		memcpy(&new_state->state, doc["state"].as<const char*>(), strlen(doc["state"]));
	}

	free(buffer);
	processNewState();
}

void processNewState()
{
	CoogleIOT_Logger *logger = _ciot_log;

	DEBUG_LIGHT_STATE(new_state, "New State");

	for(int i = 0; i < NUM_LEDS; i++) {
		memcpy(&leds[i], &new_state->color, sizeof(CRGB));
	}

	free(new_state);
	new_state = NULL;
}


void onMQTTConnect()
{
	LOG_PRINTF(DEBUG, "Subscribed to %s", STRINGIZE_VALUE_OF(SET_TOPIC));
	mqtt->subscribe(STRINGIZE_VALUE_OF(SET_TOPIC));
}

void setupSerial()
{
	if(Serial) {
		return;
	}

	Serial.begin(SERIAL_BAUD);

	for(int i = 0; (i < 500000) && !Serial; i++) {
		yield();
	}

	Serial.printf(APP_NAME " v%s (%s) (built: %s)\r\n", _BuildInfo.src_version, _BuildInfo.env_version, _BuildInfo.date);
}

void setupMQTT()
{
	mqttManager = new CoogleIOT_MQTT;
	mqttManager->setLogger(_ciot_log);
	mqttManager->setHostname(STRINGIZE_VALUE_OF(MQTT_SERVER));
	mqttManager->setPort(MQTT_PORT);
	mqttManager->setWifiManager(WiFiManager);
	mqttManager->initialize();
	mqttManager->setConnectCallback(onMQTTConnect);
	mqttManager->connect();

	mqtt = mqttManager->getClient();
	mqtt->setCallback(onMQTTCommand);
}

void setupNTP()
{
    NTPManager = new CoogleIOT_NTP;
	NTPManager->setLogger(_ciot_log);
    NTPManager->setWifiManager(WiFiManager);
    NTPManager->initialize();

}

void setupLogging()
{
	setupSerial();
    _ciot_log = new CoogleIOT_Logger(&Serial);
    _ciot_log->initialize();

}

void setupLeds()
{
    FastLED.addLeds<LED_TYPE,DATA_PIN,COLOR_ORDER>(leds, NUM_LEDS).setCorrection(TypicalLEDStrip);
    FastLED.setBrightness(BRIGHTNESS);

    // Turn on the Leds when we boot up as normal white
    for(int i = 0; i < NUM_LEDS; i++) {
    	leds[i] = CRGB::White;
    }
}

void setupWiFi()
{
    WiFiManager = new CoogleIOT_Wifi;
    WiFiManager->setLogger(_ciot_log);
    WiFiManager->setRemoteAPName(STRINGIZE_VALUE_OF(APP_SSID));
    WiFiManager->setRemoteAPPassword(STRINGIZE_VALUE_OF(APP_PASS));

    WiFiManager->initialize();
}

void setup()
{
    randomSeed(micros());

    setupLogging();

    LOG_PRINTF(INFO, APP_NAME " v%s (%s) (built: %s)", _BuildInfo.src_version, _BuildInfo.env_version, _BuildInfo.date);

    setupWiFi();
    setupNTP();
    setupMQTT();

    // Give the logger an NTP Manager so it can record timestamps with logs
    _ciot_log->setNTPManager(NTPManager);

    setupLeds();

}

void loop()
{
	WiFiManager->loop();
	NTPManager->loop();
	mqttManager->loop();

	//LOG_PRINTF(DEBUG, "Heap Size: %d", ESP.getFreeHeap());

	FastLED.show();
}
