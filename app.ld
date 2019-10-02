/*
  +----------------------------------------------------------------------+
  | Coogle IOT skeleton                                                  |
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

/* Memory Split Map for firmware, ota, and a 1.5 MB SPIFFS storage space */

/**
 * ROM 0: 0x2000 -> 0xF2000 (983,040 bytes)
 * ROM 1: 0x102000 -> 0x1F2000
 * SPIFFS: 0x202000 -> 0x3F7000 (2,150,400 bytes)
 * SDK Config: 0x3FB000 -> 0x400000
 */
 
MEMORY
{
  dport0_0_seg :                        org = 0x3FF00000, len = 0x10
  dram0_0_seg :                         org = 0x3FFE8000, len = 0x14000
  iram1_0_seg :                         org = 0x40100000, len = 0x8000
  irom0_0_seg :                         org = 0x40202010, len = 0xF0000
}

/**
 * For some silly reason you have to add 0x40200000 to the offset here,
 * even though it's basically just subtracted later in the Arudino library
 */
PROVIDE ( _SPIFFS_start = 0x40402000 );
PROVIDE ( _SPIFFS_end = 0x405F7000 );
PROVIDE ( _SPIFFS_page = 0x80 );
PROVIDE ( _SPIFFS_block = 0x1000 );

INCLUDE "eagle.app.v6.common.ld"
