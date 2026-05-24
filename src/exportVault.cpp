
#include "exportVault.h"
#include "utils.h"
#include <iostream>
#include <filesystem>
#include <fstream>

void exportVault(const std::string& vaultName) {
    std::filesystem::path srcPath = getPassManagerDir() / (vaultName + ".vault");

    if (!std::filesystem::exists(srcPath)) {
        std::cerr << "Vault not found: " << vaultName << std::endl;
        return;
    }

    std::cout << "Enter the full path to export the vault (e.g., /path/to/my-vault.exported): ";
    std::string destPathStr;
    std::getline(std::cin, destPathStr);

    std::filesystem::path destPath(destPathStr);

    if (std::filesystem::exists(destPath)) {
        std::cout << "File already exists. Overwrite? (y/n): ";
        std::string answer;
        std::getline(std::cin, answer);
        if (answer != "y") {
            std::cout << "Export cancelled." << std::endl;
            return;
        }
    }

    try {
        std::filesystem::copy_file(srcPath, destPath, std::filesystem::copy_options::overwrite_existing);
        std::cout << "Vault exported successfully to " << destPath << std::endl;
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error exporting vault: " << e.what() << std::endl;
    }
}
