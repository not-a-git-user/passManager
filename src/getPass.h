#ifndef GETPASS_H
#define GETPASS_H

#include <vector>
#include <cstdint>

#include <string>

int getPass(const std::string& vaultName, std::vector<uint8_t>* key);

#endif // GETPASS_H
