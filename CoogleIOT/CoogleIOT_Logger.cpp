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
#include "CoogleIOT_Logger.h"

#ifdef COOGLEIOT_WITH_REMOTEDEBUG
extern RemoteDebug COOGLEIOT_REMOTEDEBUG_INSTANCE_NAME;
#endif

CoogleIOT_Logger::CoogleIOT_Logger(Stream *stream)
{
	CoogleIOT_Logger();
	setStream(stream);
}

CoogleIOT_Logger::CoogleIOT_Logger()
{
	disableStream();
}

CoogleIOT_Logger::~CoogleIOT_Logger()
{
	if(logFile) {
		logFile.close();
	}

	SPIFFS.end();
}

bool CoogleIOT_Logger::streamEnabled() {
	return _stream != NULL;
}

CoogleIOT_Logger& CoogleIOT_Logger::disableStream()
{
	_stream = NULL;
	return *this;
}

CoogleIOT_Logger& CoogleIOT_Logger::setStream(Stream *stream)
{
	_stream = stream;
	return *this;
}

CoogleIOT_Logger& CoogleIOT_Logger::setMQTTManager(CoogleIOT_MQTT *_mqttManager, const char *topic)
{
	size_t topicLen = (strlen(topic) > COOGLEIOT_MQTT_MAX_LWT_TOPIC_LEN ? COOGLEIOT_MQTT_MAX_LWT_TOPIC_LEN : strlen(topic)) + 1;

	mqttManager = _mqttManager;

	mqttLogTopic = (char *)os_zalloc(topicLen);
	strncpy(mqttLogTopic, topic, topicLen);
	mqttLogTopic[topicLen] = NULL;

	return *this;
}

CoogleIOT_Logger& CoogleIOT_Logger::setNTPManager(CoogleIOT_NTP *_ntpManager)
{
	ntpManager = _ntpManager;
	return *this;
}

char * CoogleIOT_Logger::getTimestampAsString()
{
 	char *timestamp;
	struct tm* p_tm;
	time_t now;

	/**
	 * We have to malloc() and memcpy() here because
	 * downstream callers expect to be able to free() this
	 */
	if(!ntpManager) {
		timestamp = (char *)malloc(5);
		memcpy(timestamp, "UKWN", 5);
		return timestamp;
	}

	if(!ntpManager->active()) {
		timestamp = (char *)malloc(5);
		memcpy(timestamp, "UKWN", 5);
		return timestamp;
	}

	now = ntpManager->getNow();

	timestamp = (char *)malloc(21); // "YYYY-MM-DD HH:II:SS\0"
	memset(timestamp, NULL, 21);

	p_tm = localtime(&now);
	strftime(timestamp, 21, "%Y-%m-%d %H:%M:%S", p_tm);

	return timestamp;
}


char *CoogleIOT_Logger::buildLogMsg(const char *msg, CoogleIOT_Logger_Severity severity)
{
	char *retval;
	char *timestamp;
	size_t allocSize;

	timestamp = getTimestampAsString();
	allocSize = strlen(msg) + strlen(timestamp);

	allocSize++; // Account for the ultimate NULL char

	switch(severity) {
		case DEBUG:
			allocSize += 9;
			retval = (char *)malloc(allocSize);
			memset(retval, NULL, allocSize);
			strcat(retval, "[DEBUG ");
			strcat(retval, timestamp);
			strcat(retval, "] ");
			break;
		case INFO:
			allocSize += 8;
			retval = (char *)malloc(allocSize);
			memset(retval, NULL, allocSize);
			strcat(retval, "[INFO ");
			strcat(retval, timestamp);
			strcat(retval, "] ");
			break;
		case WARNING:
			allocSize += 11;
			retval = (char *)malloc(allocSize);
			memset(retval, NULL, allocSize);
			strcat(retval, "[WARNING ");
			strcat(retval, timestamp);
			strcat(retval, "] ");
			break;
		case ERROR:
			allocSize += 9;
			retval = (char *)malloc(allocSize);
			memset(retval, NULL, allocSize);
			strcat(retval, "[ERROR ");
			strcat(retval, timestamp);
			strcat(retval, "] ");
			break;
		case CRITICAL:
			allocSize += 11;
			retval = (char *)malloc(allocSize);
			memset(retval, NULL, allocSize);
			strcat(retval, "[CRITICAL ");
			strcat(retval, timestamp);
			strcat(retval, "] ");
			break;
		default:
			allocSize += 11;
			retval = (char *)malloc(allocSize);
			memset(retval, NULL, allocSize);
			strcat(retval, "[UNKNOWN ");
			strcat(retval, timestamp);
			strcat(retval, "] ");
			break;
	}

	strcat(retval, msg);

	free(timestamp); // getTimestampAsString doesn't free memory

	return retval;
}

CoogleIOT_Logger& CoogleIOT_Logger::logPrintf(CoogleIOT_Logger_Severity severity, const __FlashStringHelper *_format, ...)
{
	va_list arg;

	char temp[64];
	char* buffer = temp;
	char *format;
	size_t length, len;

	length = strlen_P((PGM_P)_format);
	format = (char *)malloc(length + 1) ;
	memcpy_P(format, (PGM_P)_format, length + 1);

	va_start(arg, format);

	len = vsnprintf(temp, sizeof(temp), format, arg);
	va_end(arg);

	if (len > sizeof(temp) - 1) {
		buffer = new char[len + 1];
		if (!buffer) {
			return *this;
		}
		va_start(arg, format);
		vsnprintf(buffer, len + 1, format, arg);
		va_end(arg);
	}

	log(buffer, severity);

	if (buffer != temp) {
		delete[] buffer;
	}

	free(format);

	return *this;

}

CoogleIOT_Logger& CoogleIOT_Logger::logPrintf(CoogleIOT_Logger_Severity severity, const char *format, ...)
{
    va_list arg;
    va_start(arg, format);
    char temp[64];
    char* buffer = temp;
    size_t len = vsnprintf(temp, sizeof(temp), format, arg);
    va_end(arg);

    if (len > sizeof(temp) - 1) {
        buffer = new char[len + 1];
        if (!buffer) {
            return *this;
        }
        va_start(arg, format);
        vsnprintf(buffer, len + 1, format, arg);
        va_end(arg);
    }

    log(buffer, severity);

    if (buffer != temp) {
        delete[] buffer;
    }

    return *this;
}

CoogleIOT_Logger& CoogleIOT_Logger::debug(String& msg)
{
	return log(msg.c_str(), DEBUG);
}

CoogleIOT_Logger& CoogleIOT_Logger::info(String& msg)
{
	return log(msg.c_str(), INFO);
}

CoogleIOT_Logger& CoogleIOT_Logger::warn(String& msg)
{
	return log(msg.c_str(), WARNING);
}

CoogleIOT_Logger& CoogleIOT_Logger::error(const __FlashStringHelper *msg)
{
	char *buffer;
	size_t length = strlen_P((PGM_P)msg);

	buffer = (char *)malloc(length + 1) ;
	memcpy_P(buffer, (PGM_P)msg, length + 1);

	log(buffer, ERROR);

	free(buffer);
	return *this;
}

CoogleIOT_Logger& CoogleIOT_Logger::critical(const __FlashStringHelper *msg)
{
	char *buffer;
	size_t length = strlen_P((PGM_P)msg);

	buffer = (char *)malloc(length + 1) ;
	memcpy_P(buffer, (PGM_P)msg, length + 1);

	log(buffer, CRITICAL);

	free(buffer);
	return *this;
}

CoogleIOT_Logger& CoogleIOT_Logger::debug(const __FlashStringHelper *msg)
{
	char *buffer;
	size_t length = strlen_P((PGM_P)msg);

	buffer = (char *)malloc(length + 1) ;
	memcpy_P(buffer, (PGM_P)msg, length + 1);

	log(buffer, DEBUG);

	free(buffer);
	return *this;
}

CoogleIOT_Logger& CoogleIOT_Logger::info(const __FlashStringHelper *msg)
{
	char *buffer;
	size_t length = strlen_P((PGM_P)msg);

	buffer = (char *)malloc(length + 1) ;
	memcpy_P(buffer, (PGM_P)msg, length + 1);

	log(buffer, INFO);

	free(buffer);
	return *this;

}

CoogleIOT_Logger& CoogleIOT_Logger::warn(const __FlashStringHelper *msg)
{
	char *buffer;
	size_t length = strlen_P((PGM_P)msg);

	buffer = (char *)malloc(length + 1) ;
	memcpy_P(buffer, (PGM_P)msg, length + 1);

	log(buffer, WARNING);

	free(buffer);
	return *this;
}

CoogleIOT_Logger& CoogleIOT_Logger::log(const __FlashStringHelper *msg, CoogleIOT_Logger_Severity severity)
{
	char *buffer;
	size_t length = strlen_P((PGM_P)msg);

	buffer = (char *)malloc(length + 1) ;
	memcpy_P(buffer, (PGM_P)msg, length + 1);

	log(buffer, severity);

	free(buffer);
	return *this;

}

CoogleIOT_Logger& CoogleIOT_Logger::error(String& msg)
{
	return log(msg.c_str(), ERROR);
}


CoogleIOT_Logger& CoogleIOT_Logger::critical(String& msg)
{
	return log(msg.c_str(), CRITICAL);
}


CoogleIOT_Logger& CoogleIOT_Logger::debug(const char *msg)
{
	return log(msg, DEBUG);
}

CoogleIOT_Logger& CoogleIOT_Logger::info(const char *msg)
{
	return log(msg, INFO);
}

CoogleIOT_Logger& CoogleIOT_Logger::warn(const char *msg)
{
	return log(msg, WARNING);
}

CoogleIOT_Logger& CoogleIOT_Logger::error(const char *msg)
{
	return log(msg, ERROR);
}

CoogleIOT_Logger& CoogleIOT_Logger::critical(const char *msg)
{
	return log(msg, CRITICAL);
}

File& CoogleIOT_Logger::getLogFile()
{
	return logFile;
}

char *CoogleIOT_Logger::getLogs()
{
	char *retval;

	if(!logFile || !logFile.size()) {
		return "";
	}

	retval = (char *)malloc(logFile.size() + 1);
	memset(retval, NULL, logFile.size() + 1);

	logFile.seek(0, SeekSet);

	while(logFile.available()) {
		char logChar;
		logChar = (char)logFile.read();
		strcat(retval, &logChar);
	}

	logFile.seek(0, SeekEnd);

	return retval;
}

bool CoogleIOT_Logger::initialize()
{

	if(!SPIFFS.begin()) {
		return false;
	}

	logFile = SPIFFS.open(COOGLEIOT_LOGGER_LOGFILE, "a+");

	if(!logFile) {
		error(PSTR("Could not open SPIFFS Log file!"));
		return false;
	} else {
		logPrintf(INFO, PSTR("Log file '%s' successfully opened"), COOGLEIOT_LOGGER_LOGFILE);
		return true;
	}
}

CoogleIOT_Logger& CoogleIOT_Logger::log(const char *msg, CoogleIOT_Logger_Severity severity)
{
	char *logMsg = buildLogMsg(msg, severity);

	if(_stream) {
		_stream->println(logMsg);
	}

	if(mqttManager) {
		if(mqttManager->connected()) {
			yield();
			mqttManager->getClient()->publish(mqttLogTopic, logMsg);
			yield();
		}
	}

	if(!logFile) {

		free(logMsg);
		return *this;
	}

	if((logFile.size() + strlen(msg)) > COOGLEIOT_LOGGER_MAXSIZE) {

		logFile.close();
		SPIFFS.remove(COOGLEIOT_LOGGER_LOGFILE);
		logFile = SPIFFS.open(COOGLEIOT_LOGGER_LOGFILE, "a+");

		if(!logFile) {
			if(_stream) {
				_stream->println(F("[CRITICAL] ERROR Could not open SPIFFS log file!"));
			}

			free(logMsg);

			return *this;
		}
	}


	logFile.println(logMsg);
	logFile.flush();

	free(logMsg);

	return *this;
}

