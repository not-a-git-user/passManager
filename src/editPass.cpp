#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <sodium.h>
#include "utils.h"
#include "passwordStrength.h"

int editPass(const std::string& vaultName, std::vector<uint8_t>* key) {
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

    // Decrypt vault
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

    // List all entry names
    const auto& entries = vJson["entries"];
    if (entries.empty()) {
        std::cout << "No entries in this vault.\n";
        sodium_memzero(decrypted.data(), decrypted.size());
        return 0;
    }

    std::cout << "\n=== Available Passwords ===\n";
    for (size_t i = 0; i < entries.size(); ++i) {
        std::cout << i + 1 << ". " << entries[i]["name"].get<std::string>() << "\n";
    }
    std::cout << "\n";

    sodium_memzero(decrypted.data(), decrypted.size());

    // Get user selection
    std::string choiceStr;
    std::cout << "Select entry to edit (name or number): ";
    std::getline(std::cin, choiceStr);

    int entryIndex = -1;
    try {
        int choiceNum = std::stoi(choiceStr);
        if (choiceNum > 0 && choiceNum <= static_cast<int>(entries.size())) {
            entryIndex = choiceNum - 1;
        }
    } catch (...) {
        // Not a number, try to match by name
        for (size_t i = 0; i < entries.size(); ++i) {
            if (entries[i]["name"].get<std::string>() == choiceStr) {
                entryIndex = i;
                break;
            }
        }
    }

    if (entryIndex == -1) {
        std::cerr << "Invalid selection.\n";
        return -1;
    }

    auto& entry = vJson["entries"][entryIndex];

    // Display current entry
    std::cout << "\n=== Current Entry ===\n";
    std::cout << "Name:     " << entry["name"].get<std::string>() << "\n";
    std::cout << "Password: " << entry["password"].get<std::string>() << "\n";
    std::cout << "Comments: " << entry["comments"].get<std::string>() << "\n\n";

    // Get new values
    SecureString newPass;
    std::string newComments;

    std::cout << "Enter new password (leave empty to keep): ";
    {
        echoDisable echoOff;
        char c;
        while (std::cin.get(c) && c != '\n') {
            newPass.push_back(c);
        }
    }
    std::cout << "\n";

    if (newPass.size() > 0) {
        int passwordStrength = calculatePasswordStrength(std::string(newPass.c_str(), newPass.size()));
        std::cout << "Password strength: " << passwordStrength << "/10\n";
        if (passwordStrength < 5) {
            std::cout << "Warning: The password you entered is weak. \nConsider using a stronger password with a mix of uppercase, lowercase, numbers, and special characters.\n";
        }
    }

    std::cout << "Enter new comments (max 64 chars, leave empty to keep): ";
    std::getline(std::cin, newComments);
    if (newComments.size() > 64) newComments = newComments.substr(0, 64);

    // Update entry only if new values provided
    if (newPass.size() > 0) {
        entry["password"] = std::string(newPass.c_str(), newPass.size());
    }
    if (!newComments.empty()) {
        entry["comments"] = newComments;
    }

    entry["lastUsed"] = getCurrentTimestamp();
    entry["lastEdited"] = getCurrentTimestamp();
    vJson["lastEdited"] = getCurrentTimestamp();

    // Re-encrypt and save
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

    // Wipe sensitive memory
    newPass.clear();
    sodium_memzero(newCiphertext.data(), newCiphertext.size());

    std::cout << "Entry updated successfully.\n";
    return 0;
}
