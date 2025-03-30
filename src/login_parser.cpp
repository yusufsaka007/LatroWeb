#include "login_parser.hpp"

namespace js {
    std::ifstream get_file() {
        std::ifstream file(JSON_FILE);
        if (!file.is_open()) {
            std::cerr << RED << "[login_parser] Error opening " << JSON_FILE << RESET << std::endl;
            return std::ifstream();
        }
        return file;
    }
    

    int get_value(std::string& buffer, const std::string search) {
        std::ifstream file = get_file();
        if ((!file.is_open()) || (file.bad())) {
            std::cerr << RED << "[login_parser] Error opening " << JSON_FILE << RESET << std::endl;
            return 0;
        }
        nlohmann::json json;
        try {
            file >> json;
        } catch (const nlohmann::json::parse_error& e) {
            std::cerr << RED << "[login_parser] Error parsing JSON file: " << e.what() << RESET << std::endl;
            return 0;
        }

        if (json.find(search) == json.end()) {
            std::cerr << RED << "[login_parser] " << search << " not found in JSON file" << RESET << std::endl;
            return 0;
        }
        if (json[search].is_string()) {
            buffer = json[search].get<std::string>();
        } else {
            std::cerr << RED << "[login_parser] " << search << " is not a string" << RESET << std::endl;
            return 0;
        }
        if (buffer.empty()) {
            std::cerr << RED << "[login_parser] " << search << " is empty" << RESET << std::endl;
            return 0;
        }
        
        return 1;
    }
}