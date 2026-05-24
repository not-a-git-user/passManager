#ifndef VAULTCREATION_H
#define VAULTCREATION_H

#include <vector>
#include <cstdint>

#include <string>

int vaultCreation(std::vector<uint8_t>* key, const std::string& salt);

#endif // VAULTCREATION_H
