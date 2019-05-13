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
	JsonObject stateJson;
	CoogleIOT_Logger *logger = _ciot_log;
	char *buffer;

	// Make local copy of payload string
	buffer = (char *)malloc(length + 1);
	memcpy(buffer, payload, length);
	buffer[length] = '\0';

	if(logger)
		logger->logPrintf(DEBUG, "Message Received: %s (%d bytes)", buffer, strlen(buffer));

	err = deserializeJson(doc, buffer);

	if(err) {
		LOG_PRINTF(ERROR, "Failed to deserialize JSON Document: %s", err.c_str());
		free(buffer);
		return;
	}

	new_state = (app_light_state *)malloc(sizeof(app_light_state));
	memset(new_state, NULL, sizeof(app_light_state));

	stateJson = doc.as<JsonObject>();

	for(JsonPair p : stateJson) {

		if(strcmp(p.key().c_str(), "brightness") == 0) {

			if(p.value().is<unsigned int>()) {
				new_state->brightness = p.value().as<unsigned int>();
				new_state->has_brightness = true;
			}

		} else if(strcmp(p.key().c_str(), "transition") == 0) {

			if(p.value().is<unsigned int>()) {
				new_state->transition = p.value().as<unsigned int>();
				new_state->has_transition = true;
			}

		} else if(strcmp(p.key().c_str(), "color") == 0) {

			if(p.value().is<JsonObject>()) {
				color = p.value().as<JsonObject>();

				new_state->has_color = true;

				if(color.containsKey("r")) {
					if(color["r"].is<unsigned int>()) {
						new_state->color.r = color["r"].as<unsigned int>();
					} else {
						new_state->color.r = 0;
					}
				}

				if(color.containsKey("g")) {
					if(color["g"].is<unsigned int>()) {
						new_state->color.g = color["g"].as<unsigned int>();
					} else {
						new_state->color.g = 0;
					}
				}

				if(color.containsKey("b")) {
					if(color["b"].is<unsigned int>()) {
						new_state->color.b = color["b"].as<unsigned int>();
					} else {
						new_state->color.b = 0;
					}
				}
			}

		} else if(strcmp(p.key().c_str(), "effect") == 0) {

			if(p.value().is<const char *>()) {

				new_state->has_effect = true;

				memcpy(&new_state->effect[0],
						p.value().as<const char *>(),
						strlen(p.value().as<const char *>()) < APP_MAX_EFFECT_NAME_LEN ?
							APP_MAX_EFFECT_NAME_LEN : strlen(p.value().as<const char *>())
				);
			}

		} else if(strcmp(p.key().c_str(), "state") == 0) {

			if(p.value().is<const char *>()) {

				new_state->has_state = true;

				if(strcmp(p.value().as<const char *>(), "OFF") == 0) {
					new_state->state = LIGHT_STATE_OFF;
				} else if(strcmp(p.value().as<const char *>(), "ON") == 0) {
					new_state->state = LIGHT_STATE_ON;
				}
			}

		} else {
			if(logger)
				logger->logPrintf(WARNING, "Unknown JSON Key '%s'", p.key().c_str());
		}
	}

	DEBUG_LIGHT_STATE(new_state, "New State");

	if(new_state->has_state) {

		if(new_state->state == LIGHT_STATE_ON) {

			current_state.state = new_state->state;
			current_state.brightness = current_state.stored_brightness;

			if(new_state->has_brightness) {
				current_state.brightness = new_state->brightness;
				current_state.stored_brightness = new_state->brightness;
			}

			if(new_state->has_color) {
				current_state.color.r = new_state->color.r;
				current_state.color.g = new_state->color.g;
				current_state.color.b = new_state->color.b;
			}

		} else {
			current_state.brightness = 0;
			current_state.state = LIGHT_STATE_OFF;
		}

	}

	current_state.state_changed = true;

	app_light_state *temp = &current_state;
	DEBUG_LIGHT_STATE(temp, "New Current State");

	free(buffer);
	free(new_state);
	new_state = NULL;

	return;
}

void publishCurrentState()
{
	DynamicJsonDocument doc(json_state_size);
	JsonObject color = doc.createNestedObject("color");

	char buffer[1024];
	size_t jsonSize;

	doc["brightness"] = current_state.brightness;
	doc["state"] = (current_state.state == LIGHT_STATE_ON) ? "ON" : "OFF";
	color["r"] = current_state.color.r;
	color["g"] = current_state.color.g;
	color["b"] = current_state.color.b;
	doc["transition"] = current_state.transition;
	doc["effect"] = current_state.effect;

	jsonSize = serializeJson(doc, buffer);

	if(mqttManager->connected()) {
		mqtt->publish(STRINGIZE_VALUE_OF(STATE_TOPIC), buffer, jsonSize);
	}
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

	if(current_state.state_changed) {
		current_state.state_changed = false;

		publishCurrentState();

		if(strlen(current_state.effect) > 0) {

		} else {
			FastLED.setBrightness(current_state.brightness);

			for(int i = 0; i < NUM_LEDS; i++) {
				memcpy(&leds[i], &current_state.color, sizeof(CRGB));
			}
		}
	}

	FastLED.show();
}
