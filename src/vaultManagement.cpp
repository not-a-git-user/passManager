#include <iostream>
#include <vector>
#include <string>
#include <cctype>
#include <sodium.h>
#include <chrono>

// Forward declarations for vault operations
int getPass(const std::string& vaultName, std::vector<uint8_t>* key);
int addPass(const std::string& vaultName, std::vector<uint8_t>* key);
int editPass(const std::string& vaultName, std::vector<uint8_t>* key);
int delPass(const std::string& vaultName, std::vector<uint8_t>* key);

void displayMenu() {
    std::cout << "\n=== Vault Management ===\n";
    std::cout << "1. Get Password (getPass)\n";
    std::cout << "2. Add Password (addPass)\n";
    std::cout << "3. Edit Password (editPass)\n";
    std::cout << "4. Delete Password (delPass)\n";
    std::cout << "5. Exit\n";
}

int vaultManagement(const std::string& vaultName, std::vector<uint8_t>* key, std::chrono::steady_clock::time_point* key_derivation_time) {
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return -1;
    }

    int running = 1;

    while (running) {
        if (std::chrono::steady_clock::now() - *key_derivation_time > std::chrono::minutes(5)) {
            std::cout << "\nSession timed out. Please re-enter your password.\n";
            sodium_memzero(key->data(), key->size());
            key->clear();
            return 0;
        }

        displayMenu();

        std::string choice;
        std::cout << "\nEnter your choice (1-5): ";
        std::getline(std::cin, choice);

        // Remove leading/trailing whitespace
        choice.erase(0, choice.find_first_not_of(" \t"));
        choice.erase(choice.find_last_not_of(" \t") + 1);

        if (choice.length() != 1 || !std::isdigit(choice[0])) {
            std::cerr << "Invalid input. Please enter a number between 1 and 5.\n";
            continue;
        }

        int option = std::stoi(choice);

        switch (option) {
            case 1: {
                std::cout << "\n--- Get Password ---\n";
                int result = getPass(vaultName, key);
                if (result != 0) {
                    std::cerr << "Failed to retrieve password.\n";
                }
                break;
            }

            case 2: {
                std::cout << "\n--- Add Password ---\n";
                int result = addPass(vaultName, key);
                if (result != 0) {
                    std::cerr << "Failed to add password.\n";
                }
                break;
            }

            case 3: {
                std::cout << "\n--- Edit Password ---\n";
                int result = editPass(vaultName, key);
                if (result != 0) {
                    std::cerr << "Failed to edit password.\n";
                }
                break;
            }

            case 4: {
                std::cout << "\n--- Delete Password ---\n";
                int result = delPass(vaultName, key);
                if (result != 0) {
                    std::cerr << "Failed to delete password.\n";
                }
                break;
            }

            case 5: {
                std::cout << "\nExiting vault management. Goodbye!\n";
                running = 0;
                break;
            }

            default: {
                std::cerr << "Invalid option. Please enter a number between 1 and 5.\n";
                break;
            }
        }
    }

    return 0;
}