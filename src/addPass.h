#ifndef ADDPASS_H
#define ADDPASS_H

#include <vector>
#include <cstdint>

#include <string>

int addPass(const std::string& vaultName, std::vector<uint8_t>* key);

#endif // ADDPASS_H
