#include "config.h"
#include "utils.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <limits>

nlohmann::json getSecurityLevels() {
    nlohmann::json levels;
    levels["interactive"] = {
        {"opslimit", crypto_pwhash_OPSLIMIT_INTERACTIVE},
        {"memlimit", crypto_pwhash_MEMLIMIT_INTERACTIVE / 4}
    };
    levels["moderate"] = {
        {"opslimit", crypto_pwhash_OPSLIMIT_MODERATE},
        {"memlimit", crypto_pwhash_MEMLIMIT_MODERATE / 4}
    };
    levels["sensitive"] = {
        {"opslimit", crypto_pwhash_OPSLIMIT_SENSITIVE},
        {"memlimit", crypto_pwhash_MEMLIMIT_SENSITIVE / 4}
    };
    return levels;
}

Config readConfig() {
    std::filesystem::path configPath = getPassManagerDir() / "config.json";
    if (!std::filesystem::exists(configPath)) {
        promptAndSaveConfig();
    }

    std::ifstream configFile(configPath);
    nlohmann::json configJson;
    configFile >> configJson;

    Config config;
    config.opslimit = configJson["opslimit"];
    config.memlimit = configJson["memlimit"];
    return config;
}

void writeConfig(const Config& config) {
    std::filesystem::path configPath = getPassManagerDir() / "config.json";
    nlohmann::json configJson;
    configJson["opslimit"] = config.opslimit;
    configJson["memlimit"] = config.memlimit;

    std::ofstream configFile(configPath);
    configFile << configJson.dump(4);
}

void promptAndSaveConfig() {
    std::cout << "No config file found. Please select a security level:\n";
    std::cout << "1. Interactive (fastest, for interactive logins)\n";
    std::cout << "2. Moderate (for less sensitive data)\n";
    std::cout << "3. Sensitive (slowest, for most sensitive data)\n";
    std::cout << "Your choice: ";

    int choice;
    std::cin >> choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    nlohmann::json levels = getSecurityLevels();
    nlohmann::json selectedLevel;

    switch (choice) {
        case 1:
            selectedLevel = levels["interactive"];
            break;
        case 2:
            selectedLevel = levels["moderate"];
            break;
        case 3:
            selectedLevel = levels["sensitive"];
            break;
        default:
            std::cout << "Invalid choice, defaulting to interactive.\n";
            selectedLevel = levels["interactive"];
            break;
    }

    Config config;
    config.opslimit = selectedLevel["opslimit"];
    config.memlimit = selectedLevel["memlimit"];
    writeConfig(config);
}
