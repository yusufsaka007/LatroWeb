// logger.cpp

#include "logger.hpp"

std::mutex Logger::meta_mutex_;

void replace_delimeter(char* __target, size_t __size) {
    char* p = __target;
    char* p_end = __target + __size - 1;
    while (*p && p < p_end) {
        if (*p == '/') {
            *p = '-';
        }
        if (*p == '-') {
            *p = '/';
        }
        p++;
    }
    *p = '\0';
}

Logger::Logger(const char* __p_ip) {
    // Default options
    strncpy(date_format_, "%Y/%m/%d", sizeof(date_format_));
    strncpy(time_format_, "%H:%M:%S", sizeof(time_format_));

    // Initialize logs
    for (int i = 0; i < LOG_LIMIT; i++) {
        logs[i] = "";
    }

    total_logs_ = 0;
    bzero(time_buffer_, sizeof(time_buffer_));
    target_file_name_ = "";

    // Check LOG_DIR
    if (!std::filesystem::exists(LOG_DIR)) {
        std::filesystem::create_directory(LOG_DIR);
        std::cerr << GREEN << "[Logger::Logger] Created log directory" << RESET << std::endl;
    }

    // Read the JSON_FILE which has targets with (ip:target_file_name). If not create
    nlohmann::json json_obj;
    json_obj = nlohmann::json::parse(std::ifstream(JSON_FILE));

    std::ifstream meta_file_in(JSON_FILE);
    if (!meta_file_in.is_open()) {
        std::cerr << RED << "[Logger::Logger] Error opening JSON file" << RESET << std::endl;
        return;
    } else {
        meta_file_in >> json_obj;
        meta_file_in.close();
    }
    meta_file_in.close();

    // Check if the targets block exists. If not create it
    if (json_obj.find("targets") == json_obj.end()) {
        json_obj["targets"] = nlohmann::json::object();
    }

    // Check if the given IP exists in the targets block
    std::string ip(__p_ip);
    if (json_obj["targets"].find(ip) != json_obj["targets"].end()) {
        std::cerr << GREEN << "[Logger::Logger] Target found in JSON file" << RESET << std::endl;
        target_file_name_ = json_obj["targets"][ip];
    } else {
        std::lock_guard<std::mutex> lock(meta_mutex_);
        std::cerr << YELLOW << "[Logger::Logger] Adding new target" << RESET << std::endl;
        target_file_name_ = LOG_DIR + std::to_string(json_obj["targets"].size() + 1) + ".log";
        json_obj["targets"][ip] = target_file_name_;

        // Modify the JSON file if the target is new
        std::ofstream meta_file_out(JSON_FILE);
        if (!meta_file_out.is_open()) {
            std::cerr << RED << "[Logger::Logger] Error opening JSON file for writing" << RESET << std::endl;
            return;
        } else {
            meta_file_out << json_obj.dump(4);
            meta_file_out.close();
        }

        // Create the actual file since the target is new
        std::ofstream log_file(target_file_name_);
        if (!log_file.is_open()) {
            std::cerr << RED << "[Logger::Logger] Error creating log file" << RESET << std::endl;
            return;
        }
        log_file << "LOGS FOR " << ip << std::endl;
        log_file << "----------------------------------------" << std::endl;
        log_file.close();
    }
}

void Logger::set_opt(int __target_opt, int __opt) {
    if (__target_opt == DATE_FORMAT) {
        if (__opt & YYYY_MM_DD) {
            strncpy(date_format_, "%Y/%m/%d", sizeof(date_format_));
        } else if (__opt & DD_MM_YYYY) {
            strncpy(date_format_, "%d/%m/%Y", sizeof(date_format_));
        } else if (__opt & DD_MM) {
            strncpy(date_format_, "%d/%m", sizeof(date_format_));
        } else if (__opt & MM_DD) {
            strncpy(date_format_, "%m/%d", sizeof(date_format_));
        } else {
            std::cerr << RED << "[Logger::set_opt] Invalid date format option" << RESET << std::endl;
            return;
        }

        if (__opt & USE_SLASH) {
            if (current_date_format_ == USE_SLASH) {
                std::cerr << RED << "[Logger::set_opt] Date format already set to slash" << RESET << std::endl;
                return;
            } else {
                replace_delimeter(date_format_, sizeof(date_format_));
                current_date_format_ = USE_SLASH;
            }

        } else if (__opt & USE_DASH) {
            if (current_date_format_ == USE_DASH) {
                std::cerr << RED << "[Logger::set_opt] Date format already set to dash" << RESET << std::endl;
                return;
            } else {
                replace_delimeter(date_format_, sizeof(date_format_));
                current_date_format_ = USE_DASH;
            }
        } else {
            std::cerr << RED << "[Logger::set_opt] Invalid date format option" << RESET << std::endl;
            return;
        }
    } else if (__target_opt == TIME_FORMAT) {
        if (__opt & HH_MM_SS) {
            strncpy(time_format_, "%H:%M:%S", sizeof(time_format_));
        } else {
            std::cerr << RED << "[Logger::set_opt] Invalid time format option" << RESET << std::endl;
            return;
        }
    } else {
        std::cerr << RED << "[Logger::set_opt] Invalid target option" << RESET << std::endl;
        return;
    }
}

int Logger::flush_logs() {
    int rc = 0;
    std::cout << GREEN << "[Logger::flush_logs] Flushing logs on" << target_file_name_ << RESET << std::endl;
    std::ofstream target_file_(target_file_name_, std::ios::app);
    if (!target_file_.is_open()) {
        return -1;
    }
    for (int i = 0; i < total_logs_; i++) {
        if (logs[i].empty()) {
            continue;
        }
        target_file_ << logs[i] << std::endl;
    }
    target_file_.close();
    total_logs_ = 0;
    return 0;
}

int Logger::log_command(const char* command) {
    int rc = 0;
    get_date();
    std::string log_entry = "[" + std::string(time_buffer_) + "] " + command;
    log_entry.erase(log_entry.find_last_not_of("\n\r\t") + 1);
    if (total_logs_ < LOG_LIMIT) {
        logs[total_logs_] = log_entry;
    } else {
        rc = flush_logs();
        if (rc != 0) {
            std::cerr << RED << "[Logger::log_command] Error opening file" << RESET << std::endl;
            return rc;
        }
        std::cout << GREEN << "[Logger::log_command] Flushing logs" << RESET << std::endl;
        logs[0] = log_entry;
    }
    total_logs_++;
    return rc;

}
void Logger::get_date() {
    time_t current_time = time(NULL);
    localtime_r(&current_time, &timeinfo_);

    combined_format_ = (std::string) date_format_ + " " + (std::string) time_format_;
    strftime(time_buffer_, sizeof(time_buffer_), combined_format_.c_str(), &timeinfo_);
}