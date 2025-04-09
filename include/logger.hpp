#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <iostream>
#include <fstream>
#include <color_codes.hpp>
#include <string>
#include <ctime>
#include <nlohmann/json.hpp>
#include <filesystem>

#define DATE_FORMAT 0b00000001
#define TIME_FORMAT 0b00000010

#define YYYY_MM_DD  0b00000001
#define DD_MM_YYYY  0b00000010
#define DD_MM       0b00000100
#define MM_DD       0b00001000
#define USE_SLASH   0b00010000
#define USE_DASH    0b00100000

#define HH_MM_SS    0b00000001

#define LOG_LIMIT 3

class Logger{
public:
    Logger(const char*);
    int log_command(const char*);
    void get_date();
    void set_opt(int, int);
    int flush_logs();
     
private:
    int current_date_format_;
    std::string target_file_name_;
    char* p_ip_;
    // pointer to a date object
    char date_format_[16];
    char time_format_[16];
    std::string combined_format_;
    char time_buffer_[16];
    int total_logs_;
    std::string logs[LOG_LIMIT];
};


#endif // LOGGER_HPP