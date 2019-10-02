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
#ifndef COOGLEIOT_LOGGER_H
#define COOGLEIOT_LOGGER_H

#ifndef COOGLEIOT_LOGGER_LOGFILE
#define COOGLEIOT_LOGGER_LOGFILE "/app.log"
#endif

#ifndef COOGLEIOT_LOGGER_MAXSIZE
#define COOGLEIOT_LOGGER_MAXSIZE 32768 // 32k
#endif

//#define COOGLEIOT_WITH_REMOTEDEBUG

#include <time.h>
#include <FS.h>
#include "CoogleIOT_NTP.h"
#include "CoogleIOT_MQTT.h"
#include "CoogleIOT_Logger_Severity.h"

extern HardwareSerial Serial;

class CoogleIOT_NTP;
class CoogleIOT_MQTT;

class CoogleIOT_Logger
{
	public:
		CoogleIOT_Logger(Stream *);
		CoogleIOT_Logger();
		~CoogleIOT_Logger();

		bool initialize();

		CoogleIOT_Logger& disableStream();
		CoogleIOT_Logger& setStream(Stream *);
		bool streamEnabled();

		CoogleIOT_Logger& setNTPManager(CoogleIOT_NTP *);
		CoogleIOT_Logger& setMQTTManager(CoogleIOT_MQTT *, const char *);

		CoogleIOT_Logger& warn(String &);
		CoogleIOT_Logger& error(String &);
		CoogleIOT_Logger& critical(String &);
		CoogleIOT_Logger& log(String &, CoogleIOT_Logger_Severity);
		CoogleIOT_Logger& debug(String &);
		CoogleIOT_Logger& info(String &);
		char *buildLogMsg(String &, CoogleIOT_Logger_Severity);

		CoogleIOT_Logger& warn(const char *);
		CoogleIOT_Logger& error(const char *);
		CoogleIOT_Logger& critical(const char *);
		CoogleIOT_Logger& log(const char *, CoogleIOT_Logger_Severity);
		CoogleIOT_Logger& debug(const char*);
		CoogleIOT_Logger& info(const char *);
		char *buildLogMsg(const char *, CoogleIOT_Logger_Severity);

		CoogleIOT_Logger& error(const __FlashStringHelper *);
		CoogleIOT_Logger& critical(const __FlashStringHelper *);
		CoogleIOT_Logger& warn(const __FlashStringHelper *);
		CoogleIOT_Logger& debug(const __FlashStringHelper *);
		CoogleIOT_Logger& info(const __FlashStringHelper *);
		CoogleIOT_Logger& log(const __FlashStringHelper *, CoogleIOT_Logger_Severity);

		CoogleIOT_Logger& logPrintf(CoogleIOT_Logger_Severity, const char *, ...);
		CoogleIOT_Logger& logPrintf(CoogleIOT_Logger_Severity, const __FlashStringHelper *, ...);

		char *getLogs();
		File& getLogFile();
		char *getTimestampAsString();

	private:
		File logFile;
		Stream *_stream;
		char *mqttLogTopic = NULL;
		CoogleIOT_MQTT *mqttManager = NULL;
		CoogleIOT_NTP *ntpManager = NULL;
};
#endif
