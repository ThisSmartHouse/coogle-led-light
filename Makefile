
FLASH_DEF = 4M1M
BOARD = generic
UPLOAD_SPEED = 115200

# Path to the ESP8266 NONOS SDK
ESP_ROOT = $(HOME)/esp8266

# Path where we can find the esptool (note this isn't esptool.py)
ESPTOOL = $(ESP_ROOT)/tools/esptool/esptool

# Path where the rBoot firmware .bin is located
BOOT_LOADER = ../rboot/firmware/rboot.bin

# Path where the Arduino files are located
ARDUINO_LIBS = $(HOME)/Arduino/libraries

# A list of things we should end up having as defines within the code base
APP_DEFINES := MQTT_MAX_PACKET_SIZE=512 \
			   ESP8266 \
			   FASTLED_ESP8266_NODEMCU_PIN_ORDER \
			   BOOT_BIG_FLASH \
			   $(APP_DEFINES) 
			   #DEBUG_ESP_PORT=Serial \
			   #DEBUG_ESP_HTTP_CLIENT
			   #DEBUG_ESP_WIFI \
			   #COOGLEIOT_WITH_REMOTEDEBUG \
			   #COOGLEIOT_REMOTEDEBUG_INSTANCE_NAME=Debug 
			
CPP_EXTRA := $(addprefix -D, $(APP_DEFINES)) -ffunction-sections $(CPP_EXTRA)
C_EXTRA :=  $(addprefix -D, $(APP_DEFINES)) -ffunction-sections $(C_EXTRA)

include makeEspArduino.mk

