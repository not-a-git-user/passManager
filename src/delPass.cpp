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

int delPass(const std::string& vaultName, std::vector<uint8_t>* key) {
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
    std::cout << "Select entry to delete (name or number): ";
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

    // Confirm deletion
    std::string confirm;
    std::cout << "Are you sure? (yes/no): ";
    std::getline(std::cin, confirm);
    if (confirm != "yes") {
        std::cout << "Deletion cancelled.\n";
        return 0;
    }

    // Delete entry
    vJson["entries"].erase(entryIndex);
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
    sodium_memzero(newCiphertext.data(), newCiphertext.size());

    std::cout << "Entry deleted successfully.\n";
    return 0;
}
