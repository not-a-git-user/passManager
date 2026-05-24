#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sodium.h>
#include "keyDeriv.h"
#include "utils.h"
#include "config.h"

int delVault(const std::string& vaultName, const Config& config) {
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

    std::vector<uint8_t> key = deriveKeyFromPassword(vaultData.salt, config);

    std::vector<unsigned char> decrypted(vaultData.ciphertext.size());
    unsigned long long decryptedLen;

    if (crypto_aead_chacha20poly1305_decrypt(
            decrypted.data(), &decryptedLen,
            nullptr,
            vaultData.ciphertext.data(), vaultData.ciphertext.size(),
            reinterpret_cast<const unsigned char*>(vaultData.aad.data()), vaultData.aad.size(),
            vaultData.nonce.data(),
            key.data()) != 0) {
        std::cerr << "Wrong password or corrupted vault." << std::endl;
        sodium_memzero(key.data(), key.size());
        return 1;
    }

    try {
        std::string plainStr(reinterpret_cast<char*>(decrypted.data()), decryptedLen);
        nlohmann::json vJson = nlohmann::json::parse(plainStr);
        if (!vJson.contains("verification") || vJson["verification"] != "OK") {
            throw std::runtime_error("Verification failed");
        }
    } catch (...) {
        std::cerr << "Wrong password or corrupted vault." << std::endl;
        sodium_memzero(key.data(), key.size());
        return 1;
    }

    std::string confirm;
    std::cout << "Are you sure you want to delete the vault '" << vaultName << "'? (yes/no): ";
    std::getline(std::cin, confirm);

    if (confirm == "yes") {
        std::filesystem::path vaultFile = getPassManagerDir() / (vaultName + ".vault");
        if (std::filesystem::remove(vaultFile)) {
            std::cout << "Vault '" << vaultName << "' deleted successfully.\n";
        } else {
            std::cerr << "Failed to delete vault file.\n";
            return -1;
        }
    } else {
        std::cout << "Vault deletion cancelled.\n";
    }

    sodium_memzero(key.data(), key.size());
    return 0;
}
