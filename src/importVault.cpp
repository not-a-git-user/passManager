
#include "importVault.h"
#include "utils.h"
#include <iostream>
#include <filesystem>
#include <fstream>

void importVault() {
    std::cout << "Enter the full path to the exported vault file: ";
    std::string srcPathStr;
    std::getline(std::cin, srcPathStr);

    std::filesystem::path srcPath(srcPathStr);

    if (!std::filesystem::exists(srcPath)) {
        std::cerr << "File not found: " << srcPathStr << std::endl;
        return;
    }

    std::cout << "Enter a new name for the imported vault: ";
    std::string vaultName;
    std::getline(std::cin, vaultName);

    std::filesystem::path destPath = getPassManagerDir() / (vaultName + ".vault");

    if (std::filesystem::exists(destPath)) {
        std::cout << "A vault with that name already exists. Overwrite? (y/n): ";
        std::string answer;
        std::getline(std::cin, answer);
        if (answer != "y") {
            std::cout << "Import cancelled." << std::endl;
            return;
        }
    }

    try {
        std::filesystem::copy_file(srcPath, destPath, std::filesystem::copy_options::overwrite_existing);
        std::cout << "Vault imported successfully as " << vaultName << std::endl;
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error importing vault: " << e.what() << std::endl;
    }
}
