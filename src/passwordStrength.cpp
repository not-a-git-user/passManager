
#include "passwordStrength.h"
#include <string>
#include <cctype>

int calculatePasswordStrength(const std::string& password) {
    int score = 0;
    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    bool hasSpecial = false;

    // Length check
    if (password.length() >= 8) {
        score += 2;
    }
    if (password.length() >= 12) {
        score += 2;
    }

    // Character type check
    for (char c : password) {
        if (isupper(c)) {
            hasUpper = true;
        }
        if (islower(c)) {
            hasLower = true;
        }
        if (isdigit(c)) {
            hasDigit = true;
        }
        if (!isalnum(c)) {
            hasSpecial = true;
        }
    }

    if (hasUpper) {
        score += 2;
    }
    if (hasLower) {
        score += 2;
    }
    if (hasDigit) {
        score += 1;
    }
    if (hasSpecial) {
        score += 1;
    }

    return std::min(score, 10);
}
