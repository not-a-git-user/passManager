#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <nlohmann/json.hpp>

struct Config {
    unsigned long long opslimit;
    size_t memlimit;
};

Config readConfig();
void writeConfig(const Config& config);
void promptAndSaveConfig();

#endif // CONFIG_H
