#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <filesystem>
#include <termios.h>
#include <unistd.h>
#include <stdexcept>
#include <sodium.h>
#include <nlohmann/json.hpp>

std::filesystem::path getPassManagerDir();

std::string getCurrentTimestamp();
std::string toHex(const std::string& in);
bool isPasswordWeak(const std::string& password);

struct VaultData {
    std::string salt;
    std::vector<unsigned char> nonce;
    std::string aad;
    std::vector<unsigned char> ciphertext;
};

VaultData readVaultFile(const std::string& vaultName);
void writeVaultFile(const std::string& vaultName, const VaultData& vaultData);

class echoDisable{
public:
    echoDisable(){//STDIN_FILENO is raw input handler instead of stdin
        if(tcgetattr(STDIN_FILENO, &originalSettings) !=0){
            throw std::runtime_error("Failed to get terminal setting. Can't diable echo");
        }

        termios newSettings = originalSettings; //need not be priavet because it is local variable and dies here only
        newSettings.c_lflag &= ~ECHO; //c_lflag is local mode in tty

        if(tcsetattr(STDIN_FILENO, TCSANOW, &newSettings) !=0){ //TCSNOW = terminal control set attribute now
            throw std::runtime_error("Failed to set terminal setting. Can't diable echo");
        }
    }

    ~echoDisable(){ //when the distructor is called
        tcsetattr(STDIN_FILENO, TCSANOW, &originalSettings);
    }
private:
    termios originalSettings; //need to be global and private because it is needed to be called after everuthing has been done
};

class SecureString {
public:
    SecureString() = default;
    ~SecureString() { clear(); }

    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;

    void push_back(char c) { buffer.push_back(c); }
    void pop_back() { if (!buffer.empty()) buffer.pop_back(); }
    size_t size() const { return buffer.size(); }
    const char* c_str() const { return buffer.data(); }

    void clear() {
        if (!buffer.empty()) {
            sodium_memzero(buffer.data(), buffer.size());
            buffer.clear();
        }
    }

private:
    std::vector<char> buffer;
};

#endif // UTILS_H
