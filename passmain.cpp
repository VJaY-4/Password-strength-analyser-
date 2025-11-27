#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <unordered_set>
#include <algorithm>
#include <regex>
#include <map>
#include <cmath>

class AdvancedPasswordAnalyzer {
private:
    std::string password;
    int strengthScore;
    std::vector<std::string> suggestions;
    std::vector<std::string> warnings;
    std::map<std::string, int> detailedScores;

    // Expanded common weak passwords database
    std::unordered_set<std::string> commonPasswords = {
        // Top most common passwords
        "password", "123456", "12345678", "1234", "12345", "123456789",
        "qwerty", "abc123", "password1", "admin", "welcome", "monkey",
        "letmein", "dragon", "master", "hello", "freedom", "whatever",
        "qazwsx", "trustno1", "baseball", "football", "superman",
        
        // Common simple patterns
        "111111", "222222", "333333", "444444", "555555", "666666",
        "777777", "888888", "999999", "000000", "123123", "112233",
        
        // Keyboard walks
        "1qaz2wsx", "1q2w3e4r", "zaq12wsx", "qwer1234", "asdf1234",
        "zxcv1234", "!qaz2wsx", "1qaz@wsx",
        
        // Season/year based
        "spring", "summer", "winter", "autumn", "fall2024", "summer2024",
        "winter2023", "spring2024",
        
        // Common names and words
        "michael", "jordan", "charlie", "andrew", "matthew", "jennifer",
        "michelle", "amanda", "ashley", "shadow", "sunshine", "princess",
        "computer", "internet", "access", "coffee", "chocolate",
        
        // Simple sequences
        "abcd", "abcde", "abcdef", "zyxwv", "qwe", "asd", "zxc"
    };

    // Expanded keyboard patterns
    std::vector<std::string> keyboardPatterns = {
        // QWERTY rows
        "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
        
        // Number sequences
        "123456", "12345678", "123456789", "987654", "98765432",
        
        // Special character sequences
        "!@#$%", "!@#$%^", "!@#$%^&", "!@#$%^&*",
        
        // Common keyboard walks
        "qazwsx", "edcrfv", "tgbnhy", "yhnujm", "ikm", "olp",
        "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm", "8ik", "9ol", "0p",
        
        // Diagonal patterns
        "qsc", "wdv", "efc", "rdx", "tfv", "ygb", "uhn", "ijm", "ok", "pl",
        
        // Reverse patterns
        "poiuyt", "lkjhgf", "mnbvcx", "zaq", "xsw", "cde", "vfr", "bgt", "nhy",
        
        // Short repeated patterns
        "qqqq", "wwww", "eeee", "rrrr", "tttt", "yyyy"
    };

public:
    AdvancedPasswordAnalyzer(std::string pwd) : password(pwd), strengthScore(0) {}
    
    void analyze() {
        strengthScore = 0;
        suggestions.clear();
        warnings.clear();
        detailedScores.clear();
        
        // Comprehensive analysis
        int lengthScore = checkLength();
        int varietyScore = checkCharacterVariety();
        int entropyScore = calculateEntropy();
        int patternScore = checkPatternsAndSequences();
        int dictionaryScore = checkDictionaryAttacks();
        int personalInfoScore = checkPersonalInfoPatterns();
        
        // Calculate final score with weights
        strengthScore = (lengthScore * 3 + varietyScore * 2 + entropyScore * 2 + 
                        patternScore * 1 + dictionaryScore * 1 + personalInfoScore * 1) / 10;
        
        strengthScore = std::min(10, std::max(0, strengthScore)); // Clamp between 0-10
        
        provideDetailedReport();
    }
    
private:
    int checkLength() {
        int len = password.length();
        int score = 0;
        
        if (len < 8) {
            suggestions.push_back("🚫 Password should be at least 8 characters long");
            score = 0;
        } else if (len >= 8 && len <= 11) {
            score = 4;
        } else if (len >= 12 && len <= 15) {
            score = 6;
            suggestions.push_back("✅ Good length! Consider going even longer");
        } else if (len >= 16 && len <= 19) {
            score = 8;
        } else {
            score = 10;
        }
        
        detailedScores["Length"] = score;
        return score;
    }
    
    int checkCharacterVariety() {
        bool hasUpper = false, hasLower = false, hasDigit = false;
        bool hasSpecial = false, hasExtended = false;
        int charTypes = 0;
        
        std::unordered_set<char> uniqueChars;
        
        for (char c : password) {
            uniqueChars.insert(c);
            
            if (std::isupper(c)) hasUpper = true;
            else if (std::islower(c)) hasLower = true;
            else if (std::isdigit(c)) hasDigit = true;
            else if (std::ispunct(c)) hasSpecial = true;
            else if (c > 127) hasExtended = true; // Extended ASCII/Unicode
        }
        
        // Count character types
        if (hasUpper) charTypes++;
        if (hasLower) charTypes++;
        if (hasDigit) charTypes++;
        if (hasSpecial) charTypes++;
        if (hasExtended) charTypes++;
        
        // Calculate variety score
        int score = 0;
        switch(charTypes) {
            case 1: score = 1; break;
            case 2: score = 3; break;
            case 3: score = 6; break;
            case 4: score = 8; break;
            case 5: score = 10; break;
        }
        
        // Suggestions
        if (!hasUpper) suggestions.push_back("🔤 Add uppercase letters (A-Z)");
        if (!hasLower) suggestions.push_back("🔤 Add lowercase letters (a-z)");
        if (!hasDigit) suggestions.push_back("🔢 Add numbers (0-9)");
        if (!hasSpecial) suggestions.push_back("🔣 Add special characters (!@#$%^&*)");
        if (hasExtended) suggestions.push_back("🌟 Bonus: Extended characters detected!");
        
        // Character uniqueness bonus
        double uniqueness = static_cast<double>(uniqueChars.size()) / password.length();
        if (uniqueness > 0.8) {
            score += 2;
            suggestions.push_back("🎯 Excellent character variety!");
        } else if (uniqueness < 0.5) {
            warnings.push_back("⚠  Many repeated characters - reduces security");
        }
        
        detailedScores["Character Variety"] = score;
        return score;
    }
    
    int calculateEntropy() {
        // Calculate password entropy (bits of entropy)
        std::map<char, int> charCount;
        for (char c : password) {
            charCount[c]++;
        }
        
        double entropy = 0.0;
        for (const auto& pair : charCount) {
            double probability = static_cast<double>(pair.second) / password.length();
            entropy -= probability * std::log2(probability);
        }
        
        // Estimate character set size
        int charsetSize = 0;
        bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
        
        for (char c : password) {
            if (std::isupper(c)) hasUpper = true;
            else if (std::islower(c)) hasLower = true;
            else if (std::isdigit(c)) hasDigit = true;
            else if (std::ispunct(c)) hasSpecial = true;
        }
        
        if (hasLower) charsetSize += 26;
        if (hasUpper) charsetSize += 26;
        if (hasDigit) charsetSize += 10;
        if (hasSpecial) charsetSize += 32; // Common special characters
        
        // Theoretical maximum entropy
        double maxEntropy = password.length() * std::log2(charsetSize);
        double entropyRatio = entropy / maxEntropy;
        
        int score = static_cast<int>((entropy / 4.0) * 10); // Normalize to 0-10 scale
        score = std::min(10, std::max(0, score));
        
        detailedScores["Entropy"] = score;
        
        if (entropy < 2.0) {
            warnings.push_back("⚠  Very low entropy - easily guessable");
        } else if (entropy > 3.5) {
            suggestions.push_back("🎲 Good randomness in password");
        }
        
        return score;
    }
    
    int checkPatternsAndSequences() {
        int penalty = 0;
        std::string lowerPwd = password;
        std::transform(lowerPwd.begin(), lowerPwd.end(), lowerPwd.begin(), ::tolower);
        
        // Check for common keyboard patterns
        for (const auto& pattern : keyboardPatterns) {
            if (lowerPwd.find(pattern) != std::string::npos) {
                penalty += 3;
                suggestions.push_back("⌨  Avoid keyboard patterns like '" + pattern + "'");
            }
        }
        
        // Check for sequences
        penalty += checkSequentialCharacters();
        
        // Check for repeated characters
        penalty += checkRepeatedCharacters();
        
        // Check for common substitutions (l33t speak)
        if (hasLeetSpeak()) {
            penalty += 1;
            warnings.push_back("⚠  Simple character substitutions (l33t speak) are predictable");
        }
        
        // Check for repeated patterns
        penalty += checkRepeatedPatterns();
        
        int score = std::max(0, 10 - penalty);
        detailedScores["Pattern Safety"] = score;
        return score;
    }
    
    int checkSequentialCharacters() {
        int sequentialCount = 0;
        int maxSequence = 0;
        
        for (size_t i = 1; i < password.length(); i++) {
            if (std::abs(password[i] - password[i-1]) == 1) {
                sequentialCount++;
                maxSequence = std::max(maxSequence, sequentialCount);
            } else {
                sequentialCount = 0;
            }
        }
        
        if (maxSequence >= 3) {
            suggestions.push_back("🔢 Avoid sequential characters (like '123' or 'abc')");
            return 2;
        }
        return 0;
    }
    
    int checkRepeatedCharacters() {
        int repeatCount = 0;
        for (size_t i = 1; i < password.length(); i++) {
            if (password[i] == password[i-1]) {
                repeatCount++;
            }
        }
        
        if (repeatCount >= 3) {
            suggestions.push_back("🔄 Too many repeated characters");
            return 2;
        }
        return 0;
    }
    
    int checkRepeatedPatterns() {
        // Check for repeated short patterns (like "ababab")
        for (size_t patternLen = 2; patternLen <= password.length() / 2; patternLen++) {
            bool isRepeating = true;
            for (size_t i = patternLen; i < password.length(); i++) {
                if (password[i] != password[i % patternLen]) {
                    isRepeating = false;
                    break;
                }
            }
            if (isRepeating && patternLen < password.length() / 2) {
                suggestions.push_back("🔁 Avoid repeating patterns in password");
                return 2;
            }
        }
        return 0;
    }
    
    bool hasLeetSpeak() {
        // Common leet speak patterns
        std::vector<std::pair<std::string, std::string>> leetPatterns = {
            {"a", "4"}, {"e", "3"}, {"i", "1"}, {"o", "0"}, {"s", "5"}, {"t", "7"},
            {"l", "1"}, {"z", "2"}, {"g", "9"}, {"b", "8"}, {"q", "9"}
        };
        
        std::string lowerPwd = password;
        std::transform(lowerPwd.begin(), lowerPwd.end(), lowerPwd.begin(), ::tolower);
        
        for (const auto& pattern : leetPatterns) {
            if (lowerPwd.find(pattern.second) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
    
    int checkDictionaryAttacks() {
        std::string lowerPwd = password;
        std::transform(lowerPwd.begin(), lowerPwd.end(), lowerPwd.begin(), ::tolower);
        
        // Check against common passwords
        if (commonPasswords.find(lowerPwd) != commonPasswords.end()) {
            suggestions.push_back("🚫 This is a very common password - choose something unique");
            return 0;
        }
        
        // Check if password contains common words
        for (const auto& commonPwd : commonPasswords) {
            if (lowerPwd.find(commonPwd) != std::string::npos && commonPwd.length() >= 4) {
                suggestions.push_back("📖 Avoid using common words like '" + commonPwd + "'");
                return 3;
            }
        }
        
        // Check for date patterns
        if (std::regex_search(password, std::regex(R"(\d{1,2}[-/]\d{1,2}[-/]\d{2,4})"))) {
            warnings.push_back("📅 Avoid using dates in passwords");
            return 2;
        }
        
        // Check for simple number suffixes
        if (std::regex_search(password, std::regex(R"([a-zA-Z]+\d{1,4}$)"))) {
            if (password.length() < 10) {
                warnings.push_back("🔢 Simple number suffixes are predictable");
                return 1;
            }
        }
        
        return 10;
    }
    
    int checkPersonalInfoPatterns() {
        // Simple check for potential personal info patterns
        int penalty = 0;
        
        // Check for all same character type
        if (std::all_of(password.begin(), password.end(), ::islower) ||
            std::all_of(password.begin(), password.end(), ::isupper) ||
            std::all_of(password.begin(), password.end(), ::isdigit)) {
            penalty += 3;
            suggestions.push_back("🎯 Mix different character types");
        }
        
        // Check for common username patterns
        if (password.length() <= 3) {
            penalty += 2;
        }
        
        // Check for only letters or only numbers
        if (std::all_of(password.begin(), password.end(), ::isalpha) ||
            std::all_of(password.begin(), password.end(), ::isdigit)) {
            penalty += 2;
            suggestions.push_back("🔀 Combine letters, numbers, and special characters");
        }
        
        return std::max(0, 10 - penalty);
    }
    
    void provideDetailedReport() {
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "🔐 ADVANCED PASSWORD SECURITY ANALYSIS" << std::endl;
        std::cout << std::string(60, '=') << std::endl;
        
        std::cout << "Password: " << std::string(password.length(), '*') << " (" << password.length() << " characters)" << std::endl;
        std::cout << "\n📊 DETAILED SCORING BREAKDOWN:" << std::endl;
        
        for (const auto& score : detailedScores) {
            std::cout << "  " << score.first << ": " << score.second << "/10" << std::endl;
        }
        
        std::cout << "\n🏆 FINAL STRENGTH SCORE: " << strengthScore << "/10" << std::endl;
        
        // Final rating with emojis
        if (strengthScore >= 9) {
            std::cout << "Status: 💪 EXCELLENT - Very strong password!" << std::endl;
        } else if (strengthScore >= 7) {
            std::cout << "Status: 👍 STRONG - Good security level" << std::endl;
        } else if (strengthScore >= 5) {
            std::cout << "Status: ⚠  MODERATE - Could be stronger" << std::endl;
        } else if (strengthScore >= 3) {
            std::cout << "Status: 🔴 WEAK - Easy to compromise" << std::endl;
        } else {
            std::cout << "Status: 🚫 VERY WEAK - Change immediately!" << std::endl;
        }
        
        // Show time to crack estimation
        estimateCrackTime();
        
        // Show suggestions
        if (!suggestions.empty()) {
            std::cout << "\n🔧 SECURITY IMPROVEMENTS:" << std::endl;
            for (const auto& suggestion : suggestions) {
                std::cout << "  • " << suggestion << std::endl;
            }
        }
        
        if (!warnings.empty()) {
            std::cout << "\n⚠  SECURITY WARNINGS:" << std::endl;
            for (const auto& warning : warnings) {
                std::cout << "  • " << warning << std::endl;
            }
        }
        
        // Generate strong password suggestions
        if (strengthScore < 8) {
            suggestStrongPasswords();
        }
    }
    
    void estimateCrackTime() {
        double combinations = 1.0;
        int charsetSize = 0;
        
        // Estimate character set size
        bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
        
        for (char c : password) {
            if (std::isupper(c)) hasUpper = true;
            else if (std::islower(c)) hasLower = true;
            else if (std::isdigit(c)) hasDigit = true;
            else if (std::ispunct(c)) hasSpecial = true;
        }
        
        if (hasLower) charsetSize += 26;
        if (hasUpper) charsetSize += 26;
        if (hasDigit) charsetSize += 10;
        if (hasSpecial) charsetSize += 32;
        
        combinations = std::pow(charsetSize, password.length());
        
        double guessesPerSecond = 1e9; // 1 billion guesses/sec (modern cracking)
        double seconds = combinations / guessesPerSecond;
        
        std::cout << "\n⏰ CRACK TIME ESTIMATION:" << std::endl;
        
        if (seconds < 1) {
            std::cout << "  Instant to a few seconds" << std::endl;
        } else if (seconds < 60) {
            std::cout << "  " << static_cast<int>(seconds) << " seconds" << std::endl;
        } else if (seconds < 3600) {
            std::cout << "  " << static_cast<int>(seconds/60) << " minutes" << std::endl;
        } else if (seconds < 86400) {
            std::cout << "  " << static_cast<int>(seconds/3600) << " hours" << std::endl;
        } else if (seconds < 31536000) {
            std::cout << "  " << static_cast<int>(seconds/86400) << " days" << std::endl;
        } else {
            std::cout << "  " << static_cast<int>(seconds/31536000) << " years" << std::endl;
        }
    }
    
    void suggestStrongPasswords() {
        std::cout << "\n💡 STRONG PASSWORD EXAMPLES:" << std::endl;
        std::cout << "  • Mountain@Sunset#46Peak!" << std::endl;
        std::cout << "  • Ocean$Wave*2024!Beach" << std::endl;
        std::cout << "  • Forest^Trail&Autumn89!" << std::endl;
        std::cout << "  • Galaxy@Star#Nebula$42!" << std::endl;
        
        std::cout << "\n🎯 TIPS FOR STRONG PASSWORDS:" << std::endl;
        std::cout << "  • Use 12+ characters with mixed types" << std::endl;
        std::cout << "  • Avoid dictionary words and patterns" << std::endl;
        std::cout << "  • Use unique passwords for each account" << std::endl;
        std::cout << "  • Consider using a password manager" << std::endl;
    }
};

int main() {
    std::cout << "🔐 ADVANCED PASSWORD STRENGTH ANALYZER" << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << "This tool analyzes your password security using multiple factors:" << std::endl;
    std::cout << "• Length & Character Variety • Entropy & Randomness" << std::endl;
    std::cout << "• Pattern Detection • Dictionary Attack Resistance" << std::endl;
    std::cout << "• Crack Time Estimation" << std::endl;
    
    char tryAnother = 'y';
    
    while (tryAnother == 'y' || tryAnother == 'Y') {
        std::string userPassword;
        std::cout << "\nEnter your password to analyze: ";
        std::cin >> userPassword;
        
        if (userPassword.empty()) {
            std::cout << "Please enter a valid password." << std::endl;
            continue;
        }
        
        AdvancedPasswordAnalyzer analyzer(userPassword);
        analyzer.analyze();
        
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "Try another password? (y/n): ";
        std::cin >> tryAnother;
    }
    
    std::cout << "\nThank you for using Advanced Password Strength Analyzer!" << std::endl;
    std::cout << "🔒 Stay Secure Online! 🔒" << std::endl;
    
    return 0;
}
