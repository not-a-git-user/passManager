#ifndef VAULTMANAGEMENT_H
#define VAULTMANAGEMENT_H

#include <vector>
#include <cstdint>
#include <string>
#include <chrono>

int vaultManagement(const std::string& vaultName, std::vector<uint8_t>* key, std::chrono::steady_clock::time_point* key_derivation_time);

#endif // VAULTMANAGEMENT_H
