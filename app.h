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
#ifndef __APP_H_
#define __APP_H_

#include "buildinfo.h"
#include "rboot.h"
#include "ArduinoJson.h"
#include <rboot-api.h>
#include "CoogleIOT_Logger.h"
#include "CoogleIOT_Wifi.h"
#include "CoogleIOT_NTP.h"
#include "CoogleIOT_MQTT.h"
#include "CoogleIOT_OTA.h"
#include "CoogleIOT_Config.h"
#include "logger.h"
#include "led_patterns.h"
#include <PubSubClient.h>

#ifndef SERIAL_BAUD
#define SERIAL_BAUD 115200
#endif

#ifndef DEBUG_HOSTNAME
#define DEBUG_HOSTNAME "coogle-light"
#endif

#ifndef APP_NAME
#define APP_NAME "Coogle-Lights"
#endif

#ifndef DATA_PIN
#define DATA_PIN 8
#endif

#ifndef LED_TYPE
#define LED_TYPE WS2812
#endif

#ifndef COLOR_ORDER
#define COLOR_ORDER GRB
#endif

#ifndef APP_MAX_EFFECT_NAME_LEN
#define APP_MAX_EFFECT_NAME_LEN 32
#endif

#ifndef APP_MAX_STATE_LEN
#define APP_MAX_STATE_LEN 16
#endif

#ifndef MQTT_TOPIC_MAX_LEN
#define MQTT_TOPIC_MAX_LEN 64
#endif

#ifndef CHIPSET_NAME_MAX_LEN
#define CHIPSET_NAME_MAX_LEN 32
#endif

#define LIGHT_STATE_OFF false
#define LIGHT_STATE_ON true

#define ARRAY_SIZE(A) (sizeof(A) / sizeof((A)[0]))

#define DEBUG_LIGHT_STATE(statePtr, name) \
		LOG_DEBUG("Light State (" name ")"); \
		LOG_PRINTF(DEBUG, "\tBrightness: %d", statePtr->brightness); \
		LOG_PRINTF(DEBUG, "\tStored Brightness: %d", statePtr->stored_brightness); \
		LOG_PRINTF(DEBUG, "\tR: %d", statePtr->color.r); \
		LOG_PRINTF(DEBUG, "\tG: %d", statePtr->color.g); \
		LOG_PRINTF(DEBUG, "\tB: %d", statePtr->color.b); \
		LOG_PRINTF(DEBUG, "\tEffect: %s", (strlen(statePtr->effect) > 0) ? statePtr->effect : "-"); \
		LOG_PRINTF(DEBUG, "\tState: %s", statePtr->state ? "on" : "off"); \
		LOG_PRINTF(DEBUG, "\tTransition: %d", statePtr->transition);

typedef struct app_config_t {
	coogleiot_config_base_t base;
	char set_topic[MQTT_TOPIC_MAX_LEN + 1];
	char state_topic[MQTT_TOPIC_MAX_LEN + 1];
	bool lights_on_at_boot;
	int num_leds;
	uint16_t brightness_max;
	uint16_t frames_per_sec;
	uint32_t color_correction = 0xFFB0F0;
};

app_config_t *app_config = NULL;

typedef struct app_light_state {
	uint16_t brightness = 255;
	uint16_t stored_brightness = 255;
	CRGB color = CRGB::White;
	CRGB stored_color = CRGB::White;
	char effect[APP_MAX_EFFECT_NAME_LEN + 1] = "";
	bool state;
	uint8_t transition = 0;

	bool has_brightness = false;
	bool has_color = false;
	bool has_effect = false;
	bool has_state = false;
	bool has_transition = false;
	bool state_changed = true;

};

app_light_state current_state;
app_light_state *new_state = NULL;

const size_t json_state_size = JSON_OBJECT_SIZE(3) + JSON_OBJECT_SIZE(5) + 70;

class CoogleIOT_Logger;
class CoogleIOT_Wifi;
class CoogleIOT_NTP;
class CoogleIOT_MQTT;
class CoogleIOT_OTA;
class CoogleIOT_Config;

CoogleIOT_Config *configManager = NULL;
CoogleIOT_Logger *_ciot_log = NULL;
CoogleIOT_Wifi *WiFiManager = NULL;
CoogleIOT_NTP *NTPManager = NULL;
CoogleIOT_MQTT *mqttManager = NULL;
CoogleIOT_OTA *otaManager = NULL;

PubSubClient *mqtt = NULL;

bool onParseConfig(DynamicJsonDocument&);

void onMQTTConnect();
void onMQTTCommand(const char *, byte *, unsigned int);
void processNewState();
void publishCurrentState();
void logSetupInfo();

void onNTPReady();
void onNewFirmware();

void setupConfig();
void setupSerial();
void setupMQTT();
void setupNTP();
void setupLogging();
void setupLeds();
void setupWiFi();
void setupOTA();

void setup();
void loop();

#endif
