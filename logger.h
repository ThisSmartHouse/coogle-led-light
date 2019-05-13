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
#ifndef APP_LOGGER_H_
#define APP_LOGGER_H_

#ifndef LOG_INFO
#define LOG_INFO(msg) _ciot_log->info(msg);
#endif

#ifndef LOG_WARN
#define LOG_WARN(msg) _ciot_log->warn(msg);
#endif

#ifndef LOG_ERROR
#define LOG_ERROR(msg) _ciot_log->error(msg);
#endif

#ifndef LOG_CRITICAL
#define LOG_CRITICAL(msg) _ciot_log->critical(msg);
#endif

#ifndef LOG_PRINTF
#define LOG_PRINTF(severity, format, ...) _ciot_log->logPrintf(severity, format, __VA_ARGS__)
#endif

#ifndef LOG_DEBUG
#define LOG_DEBUG(msg) _ciot_log->debug(msg);
#endif

#endif
