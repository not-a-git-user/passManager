#ifndef DELPASS_H
#define DELPASS_H

#include <vector>
#include <cstdint>

#include <string>

int delPass(const std::string& vaultName, std::vector<uint8_t>* key);

#endif // DELPASS_H
