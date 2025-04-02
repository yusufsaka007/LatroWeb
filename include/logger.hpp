#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <iostream>
#include <fstream>
#include <color_codes.hpp>
#include <string>
#include <ctime>
#include <nlohmann/json.hpp>

 // Open the target file
 target_file_.open(target_file_name_, std::ios::out | std::ios::app);
 if (!target_file_.is_open()) {
     std::cerr << RED << "[Logger::Logger] Error opening target file" << RESET << std::endl;
     return;
 } else {
     std::cout << GREEN << "[Logger::Logger] Target file opened successfully" << RESET << std::endl;
 }
#define DATE_FORMAT 0b00000001
#define TIME_FORMAT 0b00000010

#define YYYY_MM_DD  0b00000001
#define DD_MM_YYYY  0b00000010
#define DD_MM       0b00000100
#define MM_DD       0b00001000
#define USE_SLASH   0b00010000
#define USE_DASH    0b00100000

#define HH_MM_SS    0b00000001

#define LOG_LIMIT 10

class Logger{
public:
    Logger(const char*);
    int log_command(const char*);
    void get_date();
    void set_opt(int, int)
    int flush_logs();
    ~Logger();
     
private:
    std::fstream target_file_;
    std::string target_file_name_;
    char* p_ip_;
    // pointer to a date object
    char* date_format_;
    char* time_format_;
    std::string combined_format_;
    char time_buffer_[16];
    int total_logs_;
    std::string logs[LOG_LIMIT];
};


#endif // LOGGER_HPP