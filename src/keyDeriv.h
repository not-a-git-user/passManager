#ifndef KEYDERIV_H
#define KEYDERIV_H

#include <vector>
#include <string>
#include <sodium.h>
#include <iomanip>
#include <sstream>
#include "config.h"

class saltManagement{
public:
    static std::string firstTImeRun(){
        std::vector<unsigned char> random_bytes(32);
        std::ostringstream var;

        randombytes_buf(random_bytes.data(), 32);
        for (int i = 0; i < 32; ++i) {
            var << std::hex << std::setw(2) << std::setfill('0') << (int)random_bytes[i];
        }
        std::string hex_output = var.str();
        return hex_output;
    }
};

std::vector<uint8_t> deriveKeyFromPassword(const std::string& salt, const Config& config);

#endif // KEYDERIV_H