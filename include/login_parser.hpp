#ifndef LOGIN_PARSER_HPP
#define LOGIN_PARSER_HPP

#include <nlohmann/json.hpp>
#include <iostream>
#include <string>
#include "color_codes.hpp"
#include <fstream>

#define MAX_USERNAME_SIZE 32
#define MAX_PASSWORD_SIZE 32

namespace js{
    std::ifstream get_file();
    int get_value(std::string& username, const std::string search);
    int get_value(int& buffer, const std::string search);
}

#endif // LOGIN_PARSER_HPP