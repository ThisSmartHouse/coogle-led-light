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
#include <rboot.h>
#include <rboot-api.h>
#include "CoogleIOT_Logger.h"
#include "CoogleIOT_Wifi.h"
#include "CoogleIOT_NTP.h"
#include "CoogleIOT_MQTT.h"
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

#ifndef NUM_LEDS
#define NUM_LEDS 83
#endif

#ifndef BRIGHTNESS
#define BRIGHTNESS 255
#endif

#ifndef FRAMES_PER_SECOND
#define FRAMES_PER_SECOND 120
#endif

#define ARRAY_SIZE(A) (sizeof(A) / sizeof((A)[0]))

#define STRINGIZE(x) #x
#define STRINGIZE_VALUE_OF(x) STRINGIZE(x)

#ifndef APP_MAX_EFFECT_NAME_LEN
#define APP_MAX_EFFECT_NAME_LEN 32
#endif

#ifndef APP_MAX_STATE_LEN
#define APP_MAX_STATE_LEN 16
#endif


#define LIGHT_STATE_OFF false
#define LIGHT_STATE_ON true

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

struct app_config {
	char ssid[33];
	char pass[64];
	char ota_endpoint[256];
	char ota_token[256];
};

typedef struct app_light_state {
	uint8_t brightness = 255;
	uint8_t stored_brightness = 255;
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

CoogleIOT_Logger *_ciot_log = NULL;
CoogleIOT_Wifi *WiFiManager = NULL;
CoogleIOT_NTP *NTPManager = NULL;
CoogleIOT_MQTT *mqttManager = NULL;

PubSubClient *mqtt = NULL;

void onMQTTConnect();
void onMQTTCommand(const char *, byte *, unsigned int);
void processNewState();
#endif
