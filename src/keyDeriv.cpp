#include <iostream>
#include <vector> //array
#include <string> 

#include <sodium.h> 
#include <argon2.h>

#include <iomanip>  //salt
#include <sstream>  //salt

#include "utils.h"
#include "config.h"

class argon2idDeriv{
private:
    static const int saltSize = 16;
    static const int hashSize = 32;
    static const int parallel = 8;    

public:
    static std::vector<uint8_t> hashPass(std::string salt, const Config& config){
        echoDisable echoOff;
        SecureString pass;
        std::cout << "Enter your password: " << std::flush;
        
        char c;
        while (read(STDIN_FILENO, &c, 1) == 1 && c != '\n') {
            pass.push_back(c);
        }
        std::cout << std::endl;

        std::vector<uint8_t> key(hashSize);
        size_t memlimit_kib = config.memlimit / 1024;
        if (memlimit_kib < 8) {
            memlimit_kib = 8;
        }

        int worked = argon2id_hash_raw(
            config.opslimit,
            memlimit_kib,
            parallel,
            pass.c_str(),
            pass.size(),
            salt.data(),
            salt.length(),
            key.data(),
            key.size()
        );
        if (worked != ARGON2_OK) {
            throw std::runtime_error("Argon2 error" + std::string(argon2_error_message(worked)));
        }
        return key;
    } 
};

std::vector<uint8_t> deriveKeyFromPassword(const std::string& salt, const Config& config) {
    std::cout << "Salt is:" << toHex(salt) << std::endl;
    return argon2idDeriv::hashPass(salt, config);
}