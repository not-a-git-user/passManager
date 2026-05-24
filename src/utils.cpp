#include "utils.h"
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>

std::filesystem::path getPassManagerDir() {
    const char* home = getenv("HOME");
    if (!home) {
        throw std::runtime_error("Could not get HOME directory");
    }
    return std::filesystem::path(home) / ".local/share/passManager";
}

std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X");
    return ss.str();
}

std::string toHex(const std::string& in) {
    std::stringstream ss;
    for (unsigned char c : in) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return ss.str();
}

bool isPasswordWeak(const std::string& password) {
    if (password.length() < 8) {
        return true;
    }

    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    bool hasSpecial = false;

    for (char c : password) {
        if (std::isupper(c)) {
            hasUpper = true;
        } else if (std::islower(c)) {
            hasLower = true;
        } else if (std::isdigit(c)) {
            hasDigit = true;
        } else {
            hasSpecial = true;
        }
    }

    return !(hasUpper && hasLower && hasDigit && hasSpecial);
}

VaultData readVaultFile(const std::string& vaultName) {
    std::filesystem::path vaultFile = getPassManagerDir() / (vaultName + ".vault");
    if (!std::filesystem::exists(vaultFile)) {
        throw std::runtime_error("Vault does not exist.");
    }

    std::ifstream inFile(vaultFile, std::ios::binary);
    if (!inFile.is_open()) {
        throw std::runtime_error("Could not open vault file for reading.");
    }

    VaultData vaultData;

    uint32_t saltLen;
    inFile.read(reinterpret_cast<char*>(&saltLen), sizeof(saltLen));
    vaultData.salt.resize(saltLen);
    inFile.read(vaultData.salt.data(), saltLen);

    uint32_t nonceLen;
    inFile.read(reinterpret_cast<char*>(&nonceLen), sizeof(nonceLen));
    vaultData.nonce.resize(nonceLen);
    inFile.read(reinterpret_cast<char*>(vaultData.nonce.data()), nonceLen);

    uint32_t aadLen;
    inFile.read(reinterpret_cast<char*>(&aadLen), sizeof(aadLen));
    vaultData.aad.resize(aadLen);
    inFile.read(vaultData.aad.data(), aadLen);

    uint64_t cipherLen;
    inFile.read(reinterpret_cast<char*>(&cipherLen), sizeof(cipherLen));
    vaultData.ciphertext.resize(cipherLen);
    inFile.read(reinterpret_cast<char*>(vaultData.ciphertext.data()), cipherLen);

    inFile.close();
    return vaultData;
}

void writeVaultFile(const std::string& vaultName, const VaultData& vaultData) {
    std::filesystem::path vaultFile = getPassManagerDir() / (vaultName + ".vault");
    std::ofstream outFile(vaultFile, std::ios::binary);
    if (!outFile.is_open()) {
        throw std::runtime_error("Could not open vault file for writing.");
    }

    uint32_t saltLen = vaultData.salt.size();
    outFile.write(reinterpret_cast<const char*>(&saltLen), sizeof(saltLen));
    outFile.write(vaultData.salt.data(), saltLen);

    uint32_t nonceLen = vaultData.nonce.size();
    outFile.write(reinterpret_cast<const char*>(&nonceLen), sizeof(nonceLen));
    outFile.write(reinterpret_cast<const char*>(vaultData.nonce.data()), nonceLen);

    uint32_t aadLen = vaultData.aad.size();
    outFile.write(reinterpret_cast<const char*>(&aadLen), sizeof(aadLen));
    outFile.write(vaultData.aad.data(), aadLen);

    uint64_t cipherLen = vaultData.ciphertext.size();
    outFile.write(reinterpret_cast<const char*>(&cipherLen), sizeof(cipherLen));
    outFile.write(reinterpret_cast<const char*>(vaultData.ciphertext.data()), cipherLen);

    outFile.close();
}