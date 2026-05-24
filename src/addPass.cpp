#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <limits>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include "utils.h"
#include "passwordStrength.h"

int addPass(const std::string& vaultName, std::vector<uint8_t>* key) {
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return -1;
    }

    VaultData vaultData;
    try {
        vaultData = readVaultFile(vaultName);
    } catch (const std::runtime_error& e) {
        std::cerr << e.what() << '\n';
        return -1;
    }

    std::vector<unsigned char> decrypted(vaultData.ciphertext.size());
    unsigned long long decryptedLen;

    if (crypto_aead_chacha20poly1305_decrypt(
            decrypted.data(), &decryptedLen,
            nullptr,
            vaultData.ciphertext.data(), vaultData.ciphertext.size(),
            reinterpret_cast<const unsigned char*>(vaultData.aad.data()), vaultData.aad.size(),
            vaultData.nonce.data(),
            key->data()) != 0) {
        std::cerr << "Vault decryption failed! Wrong key or corrupted.\n";
        return -1;
    }

    std::string plainStr(reinterpret_cast<char*>(decrypted.data()), decryptedLen);
    nlohmann::json vJson = nlohmann::json::parse(plainStr);

    SecureString entryName, entryPass;
    std::string nameStr;

    while (true) {
        std::cout << "Enter entry name: ";
        std::getline(std::cin, nameStr);
        if (!nameStr.empty()) {
            for (char ch : nameStr) {
                entryName.push_back(ch);
            }
            break;
        }
        std::cout << "Entry name cannot be empty.\n";
    }

    std::cout << "Enter password: " << std::flush;
    {
        echoDisable echoOff;
        char c;
        while (std::cin.get(c) && c != '\n') {
            entryPass.push_back(c);
        }
    }
    std::cout << "\n";

    int passwordStrength = calculatePasswordStrength(std::string(entryPass.c_str(), entryPass.size()));
    std::cout << "Password strength: " << passwordStrength << "/10\n";
    if (passwordStrength < 5) {
        std::cout << "Warning: The password you entered is weak. \nConsider using a stronger password with a mix of uppercase, lowercase, numbers, and special characters.\n";
    }


    std::string comments;
    std::cout << "Comments (max 64 chars): ";
    std::getline(std::cin, comments);
    if (comments.size() > 64) comments = comments.substr(0,64);


    nlohmann::json newEntry;
    newEntry["name"] = std::string(entryName.c_str(), entryName.size());
    newEntry["password"] = std::string(entryPass.c_str(), entryPass.size());
    newEntry["comments"] = comments;
    newEntry["createdAt"] = getCurrentTimestamp();
    newEntry["lastUsed"] = getCurrentTimestamp();
    newEntry["lastEdited"] = getCurrentTimestamp();

    vJson["entries"].push_back(newEntry);
    vJson["lastEdited"] = getCurrentTimestamp();


    std::string plaintext = vJson.dump();
    std::vector<unsigned char> newCiphertext(plaintext.size() + crypto_aead_chacha20poly1305_ABYTES);
    unsigned long long newCipherLen;

    std::vector<unsigned char> new_nonce(crypto_aead_chacha20poly1305_NPUBBYTES);
    randombytes_buf(new_nonce.data(), new_nonce.size());

    if (crypto_aead_chacha20poly1305_encrypt(
            newCiphertext.data(), &newCipherLen,
            reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
            reinterpret_cast<const unsigned char*>(vaultData.aad.data()), vaultData.aad.size(),
            nullptr,
            new_nonce.data(),
            key->data()) != 0) {
        std::cerr << "Encryption failed!\n";
        return -1;
    }

    vaultData.nonce = new_nonce;
    vaultData.ciphertext.assign(newCiphertext.begin(), newCiphertext.begin() + newCipherLen);

    try {
        writeVaultFile(vaultName, vaultData);
    } catch (const std::runtime_error& e) {
        std::cerr << e.what() << '\n';
        return -1;
    }

    //wipe sensitive memory
    entryName.clear();
    entryPass.clear();
    sodium_memzero(decrypted.data(), decrypted.size());
    sodium_memzero(newCiphertext.data(), newCiphertext.size());

    std::cout << "New entry added successfully.\n";
    return 0;
}