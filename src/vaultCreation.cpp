#include <iostream>
#include <sodium.h>
#include <error.h>
#include <filesystem>
#include <string>
#include <cctype>
#include <cstdlib>

#include <chrono>   //json
#include <ctime>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>

#include "utils.h"

std::string bytesToHex(const unsigned char* bytes, size_t len) {
    std::ostringstream ret;
    for (size_t i = 0; i < len; ++i) {
        ret << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i];
    }
    return ret.str();
}

int vaultCreation(std::vector<uint8_t>* key, const std::string& salt){

    if(sodium_init() < 0){
        std::cerr << "Libsodium error: " << strerror(errno) << std::endl;
        return -1;
    }

    std::vector<std::string> vaults;
    std::filesystem::path dirPath = getPassManagerDir();

    if (!std::filesystem::exists(dirPath)) {//if the path not exists
        if (std::filesystem::create_directories(dirPath)) {
            std::cout << "Directory created successfully: " << dirPath << std::endl;
        } else {
            std::cerr << "Directory not created: " << dirPath << std::endl;
            return -1;
        }
    }

    for(auto& file: std::filesystem::directory_iterator(dirPath)){
        if(file.is_regular_file()){            //check if its a file
            vaults.push_back(file.path().string());
        }
    }
    
    std::string vault;
    while(1){
        std::cout << "\n\nEnter Vault Name:" << std::endl;
        std::getline(std::cin, vault);
        int valid = 1;

        for (char ch: vault){
            if(!std::isalnum(ch)){
                std::cout << "Alphanumeric with no space only" << std::endl;
                valid = 0;
                break;
            }
        }
        for(std::string filepath : vaults){
            std::string filename = std::filesystem::path(filepath).stem().string();
            if (filename == vault){
                std::cout << "Vault with same name already exists" << std::endl;
                valid = 0;
                break;
            }
        }

        if(valid == 1){
            break;
        }
    }

    nlohmann::json vJson;
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));//randombytes is libsodium inbuilt


    vJson["vaultVersion"] = "1.0";
    vJson["encryptionType"] = "ChaCha20-Poly1305";
    vJson["createdAt"] = getCurrentTimestamp();
    vJson["lastUsed"] = getCurrentTimestamp();
    vJson["lastEdited"] = getCurrentTimestamp();
    vJson["verification"] = "OK";

    nlohmann::json encryption;
    encryption["nonce"] = bytesToHex(nonce, crypto_aead_chacha20poly1305_NPUBBYTES);
    encryption["salt"] = salt;
    encryption["tag"] = "";  // Will be populated after encryption
    encryption["nonceLength"] = crypto_aead_chacha20poly1305_NPUBBYTES;
    encryption["tagLength"] = crypto_aead_chacha20poly1305_ABYTES;
    encryption["keyLength"] = crypto_aead_chacha20poly1305_KEYBYTES;
    
    vJson["encryption"] = encryption;

    vJson["entries"] = nlohmann::json::array();//empty for now

    std::string plaintext = vJson.dump();
    std::vector<unsigned char> ciphertext(plaintext.size() + crypto_aead_chacha20poly1305_ABYTES);
    unsigned long long ciphertext_len;

    std::string aad = "vault:" + vault + "|version:1.0";
    int result = crypto_aead_chacha20poly1305_encrypt(
        ciphertext.data(),           //output buffer
        &ciphertext_len,             //resulting length
        reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
        reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
        nullptr,                     //no secret nonce reuse
        nonce,                       
        key->data()    
    );              

    if (result != 0) {
        std::cerr << "Encryption failed!" << std::endl;
        return -1;
    }
    
    


    std::filesystem::path filePath = dirPath / (vault + ".vault");
    std::ofstream outFile(filePath, std::ios::binary);


    if (!outFile.is_open()) {
        std::cerr << "Error: Failed to open file for writing: " << filePath << std::endl;
        return -1;
    }
    //salt
    uint32_t saltLen = salt.size();
    outFile.write(reinterpret_cast<const char*>(&saltLen), sizeof(saltLen));
    outFile.write(salt.data(), saltLen);

    //nonce
    uint32_t nonceLen = sizeof(nonce);
    outFile.write(reinterpret_cast<const char*>(&nonceLen), sizeof(nonceLen));
    outFile.write(reinterpret_cast<const char*>(nonce), nonceLen);

    //AAD
    uint32_t aadLen = aad.size();
    outFile.write(reinterpret_cast<const char*>(&aadLen), sizeof(aadLen));
    outFile.write(aad.data(), aadLen);

    //ciphertext
    uint64_t cipherLen = ciphertext_len;
    outFile.write(reinterpret_cast<const char*>(&cipherLen), sizeof(cipherLen));
    outFile.write(reinterpret_cast<const char*>(ciphertext.data()), cipherLen);

    outFile.close();

    //cleanup
    //sodium_memzero(key->data(), key->size()); MAYBE NOT?
    sodium_memzero(ciphertext.data(), ciphertext.size());

    return 0;
}

/*
int main() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium\n";
        return 1;
    }

    // fixed dummy key (DO NOT USE IN REAL APP)
    std::vector<uint8_t> key(crypto_aead_chacha20poly1305_KEYBYTES);
    for (size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<uint8_t>(i);  // predictable content for testing

    int result = vaultCreation(&key);
    if (result == 0)
        std::cout << "Vault creation test successful.\n";
    else
        std::cout << "Vault creation failed.\n";

    return 0;
}*/