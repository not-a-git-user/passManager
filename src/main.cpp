#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sodium.h>
#include <stdexcept>
#include "keyDeriv.h"
#include "vaultCreation.h"
#include "vaultManagement.h"
#include "addPass.h"
#include "delPass.h"
#include "editPass.h"
#include "getPass.h"
#include "delVault.h"
#include "config.h"
#include "utils.h"
#include "importVault.h"
#include "exportVault.h"

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium\n";
        return 1;
    }

    std::filesystem::path dirPath;
    try {
        dirPath = getPassManagerDir();
    } catch (const std::runtime_error& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }

    // Create directory if it doesn't exist
    if (!std::filesystem::exists(dirPath)) {
        if (!std::filesystem::create_directories(dirPath)) {
            std::cerr << "Failed to create directory: " << dirPath << "\n";
            return 1;
        }
    }

    Config config = readConfig();

    std::vector<uint8_t> key;
    std::chrono::steady_clock::time_point key_derivation_time;

    while (true) {
        // List all existing vaults
        std::vector<std::string> vaults;
        for (auto& file : std::filesystem::directory_iterator(dirPath)) {
            if (file.is_regular_file() && file.path().extension() == ".vault") {
                vaults.push_back(file.path().stem().string());
            }
        }

        std::string selectedVault;

        if (vaults.empty()) {
            std::cout << "No vaults found. Creating a new vault...\n\n";
            
            std::string salt = saltManagement::firstTImeRun();
            key = deriveKeyFromPassword(salt, config);

            if (vaultCreation(&key, salt) != 0) {
                std::cerr << "Vault creation failed\n";
                sodium_memzero(key.data(), key.size());
                continue; // Loop back to menu
            }

            sodium_memzero(key.data(), key.size());
            std::cout << "\nVault created successfully!\n";
            continue; // Loop back to menu
        }

        // Display available vaults
        std::cout << "=== Available Vaults ===\n";
        for (size_t i = 0; i < vaults.size(); ++i) {
            std::cout << i + 1 << ". " << vaults[i] << "\n";
        }
        std::cout << "\nOptions:\n";
        std::cout << "Enter vault number (1-" << vaults.size() << ") to open\n";
        std::cout << "Enter 'new' to create a new vault\n";
        std::cout << "Enter 'del' to delete a vault\n";
        std::cout << "Enter 'import' to import a vault\n";
        std::cout << "Enter 'export' to export a vault\n";
        std::cout << "Enter 'exit' to quit\n";

        std::string choice;
        std::cout << "\nYour choice: ";
        std::getline(std::cin, choice);

        if (choice == "new") {
            std::cout << "\nCreating a new vault...\n\n";

            std::string salt = saltManagement::firstTImeRun();
            key = deriveKeyFromPassword(salt, config);

            if (vaultCreation(&key, salt) != 0) {
                std::cerr << "Vault creation failed\n";
                sodium_memzero(key.data(), key.size());
                continue;
            }

            sodium_memzero(key.data(), key.size());
            std::cout << "\nVault created successfully!\n";
            continue;
        } else if (choice == "del") {
            if (vaults.empty()) {
                std::cout << "No vaults to delete.\n";
                continue;
            }
            std::cout << "\nSelect a vault to delete:\n";
            for (size_t i = 0; i < vaults.size(); ++i) {
                std::cout << i + 1 << ". " << vaults[i] << "\n";
            }
            std::cout << "\nYour choice: ";
            std::string delChoice;
            std::getline(std::cin, delChoice);

            bool vaultToDeleteFound = false;
            std::string vaultToDelete;
            try {
                int vaultIndex = std::stoi(delChoice) - 1;
                if (vaultIndex >= 0 && vaultIndex < static_cast<int>(vaults.size())) {
                    vaultToDelete = vaults[vaultIndex];
                    vaultToDeleteFound = true;
                }
            } catch (...) {
                // Not a number, try to match by name
                for (const auto& vault : vaults) {
                    if (vault == delChoice) {
                        vaultToDelete = vault;
                        vaultToDeleteFound = true;
                        break;
                    }
                }
            }

            if (vaultToDeleteFound) {
                delVault(vaultToDelete, config);
            } else {
                std::cerr << "Invalid choice.\n";
            }
            continue;
        } else if (choice == "import") {
            importVault();
            continue;
        } else if (choice == "export") {
            if (vaults.empty()) {
                std::cout << "No vaults to export.\n";
                continue;
            }
            std::cout << "\nSelect a vault to export:\n";
            for (size_t i = 0; i < vaults.size(); ++i) {
                std::cout << i + 1 << ". " << vaults[i] << "\n";
            }
            std::cout << "\nYour choice: ";
            std::string exportChoice;
            std::getline(std::cin, exportChoice);

            bool vaultToExportFound = false;
            std::string vaultToExport;
            try {
                int vaultIndex = std::stoi(exportChoice) - 1;
                if (vaultIndex >= 0 && vaultIndex < static_cast<int>(vaults.size())) {
                    vaultToExport = vaults[vaultIndex];
                    vaultToExportFound = true;
                }
            } catch (...) {
                // Not a number, try to match by name
                for (const auto& vault : vaults) {
                    if (vault == exportChoice) {
                        vaultToExport = vault;
                        vaultToExportFound = true;
                        break;
                    }
                }
            }

            if (vaultToExportFound) {
                exportVault(vaultToExport);
            } else {
                std::cerr << "Invalid choice.\n";
            }
            continue;
        } else if (choice == "exit") {
            break; // Exit the main loop
        }

        bool vaultFound = false;
        try {
            int vaultIndex = std::stoi(choice) - 1;
            if (vaultIndex >= 0 && vaultIndex < static_cast<int>(vaults.size())) {
                selectedVault = vaults[vaultIndex];
                vaultFound = true;
            }
        } catch (...) {
            // Not a number, try to match by name
            for (const auto& vault : vaults) {
                if (vault == choice) {
                    selectedVault = vault;
                    vaultFound = true;
                    break;
                }
            }
        }

        if (vaultFound) {
            // Derive key from password and verify it
            std::cout << "\n";
            
            VaultData vaultData;
            try {
                vaultData = readVaultFile(selectedVault);
            } catch (const std::runtime_error& e) {
                std::cerr << e.what() << '\n';
                continue;
            }

            if (key.empty() || std::chrono::steady_clock::now() - key_derivation_time > std::chrono::minutes(5)) {
                key = deriveKeyFromPassword(vaultData.salt, config);
                key_derivation_time = std::chrono::steady_clock::now();
            }

            std::vector<unsigned char> decrypted(vaultData.ciphertext.size());
            unsigned long long decryptedLen;

            if (crypto_aead_chacha20poly1305_decrypt(
                    decrypted.data(), &decryptedLen,
                    nullptr,
                    vaultData.ciphertext.data(), vaultData.ciphertext.size(),
                    reinterpret_cast<const unsigned char*>(vaultData.aad.data()), vaultData.aad.size(),
                    vaultData.nonce.data(),
                    key.data()) != 0) {
                std::cerr << "\nWrong password or corrupted vault.\n" << std::endl;
                sodium_memzero(key.data(), key.size());
                key.clear();
                continue;
            }

            try {
                std::string plainStr(reinterpret_cast<char*>(decrypted.data()), decryptedLen);
                nlohmann::json vJson = nlohmann::json::parse(plainStr);
                if (!vJson.contains("verification") || vJson["verification"] != "OK") {
                    throw std::runtime_error("Verification failed");
                }
            } catch (...) {
                std::cerr << "\nWrong password or corrupted vault.\n" << std::endl;
                sodium_memzero(key.data(), key.size());
                key.clear();
                continue;
            }

            std::cout << "Opening vault: \n" << selectedVault << "\n\n";

            // Pass control to vault management
            vaultManagement(selectedVault, &key, &key_derivation_time);

            sodium_memzero(key.data(), key.size());
        } else {
            std::cerr << "Invalid vault selection.\n";
            continue;
        }
    }

    return 0;
}
