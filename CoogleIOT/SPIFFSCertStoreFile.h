#ifndef COOGLEIOT_SPIFFS_CERT_H_
#define COOGLEIOT_SPIFFS_CERT_H_

#include <FS.h>

class SPIFFSCertStoreFile : public BearSSL::CertStoreFile {

	public:

		SPIFFSCertStoreFile(const char *name) {
		  _name = name;
		};

		virtual ~SPIFFSCertStoreFile() override {};

		// The main API
		virtual bool open(bool write = false) override {
		  _file = SPIFFS.open(_name, write ? "w" : "r");
		  return _file;
		}

		virtual bool seek(size_t absolute_pos) override {
		  return _file.seek(absolute_pos, SeekSet);
		}

		virtual ssize_t read(void *dest, size_t bytes) override {
		  return _file.readBytes((char*)dest, bytes);
		}

		virtual ssize_t write(void *dest, size_t bytes) override {
		  return _file.write((uint8_t*)dest, bytes);
		}

		virtual void close() override {
		  _file.close();
		}

	private:
		File _file;
		const char *_name;
};

#endif