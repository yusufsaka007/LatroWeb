// logger.cpp

#include "logger.hpp"

Logger::Logger(const char* __p_ip, int) {
    // Default options
    date_format_ = "%Y/%m/%d";
    time_format_ = "%H:%M:%S";

    // Read the JSON_FILE which has targets with (ip:target_file_name). If not create
    nlohmann::json json_obj;
    json_obj = nlohmann::json::parse(std::ifstream("JSON_FILE"));

    std::ifstream meta_file(JSON_FILE);
    if (!meta_file.is_open()) {
        std::cerr << RED << "[Logger::Logger] Error opening JSON file" << RESET << std::endl;
        return;
    } else {
        meta_file >> json_obj;
        meta_file.close();
    }

    // Check if the targets block exists. If not create it
    if (json_obj.find("targets") == json_obj.end()) {
        std::cerr << RED << "[Logger::Logger] No targets found in JSON file" << RESET << std::endl;
        
        json_obj["targets"] = nlohmann::json::array();
    }

    // Check if the given IP exists in the targets block (target is not new)
    std::string ip(__p_ip);
    if (json_obj["targets"].find(ip) != json_obj["targets"].end()) {
        std::cerr << GREEN << "[Logger::Logger] Target found in JSON file" << RESET << std::endl;
        target_file_name_ = json_obj["targets"][ip];
    } else {
        std::cerr << RED << "[Logger::Logger] Target not found in JSON file" << RESET << std::endl;
        target_file_name_ = (json_obj["targets"].size() + 1) + ".log";
        json_obj["targets"][ip] = target_file_name_;
    }

    // Modify the JSON file
    std::ofstream out_file(JSON_FILE);
    if (!out_file.is_open()) {
        std::cerr << RED << "[Logger::Logger] Error opening JSON file for writing" << RESET << std::endl;
        return;
    } else {
        out_file << json_obj.dump(4);
        out_file.close();
    }
    meta_file.close();
   
}

void Logger::set_opt(int __target_opt, int __opt) {
    if (__target_opt == DATE_FORMAT) {
        if (__opt & YYYY_MM_DD) {
            date_format_ = "%Y/%m/%d";
        } else if (__opt & DD_MM_YYYY) {
            date_format_ = "%d/%m/%Y";
        } else if (__opt & DD_MM) {
            date_format_ = "%d/%m";
        } else if (__opt & MM_DD) {
            date_format_ = "%m/%d";
        } else {
            std::cerr << RED << "[Logger::set_opt] Invalid date format option" << RESET << std::endl;
            return;
        }

        if (__opt & USE_SLASH) {
            date_format_ = date_format_.replace(date_format_.find("/"), 1, "/");
        } else if (__opt & USE_DASH) {
            date_format_ = date_format_.replace(date_format_.find("/"), 1, "-");
        } else {
            std::cerr << RED << "[Logger::set_opt] Invalid date format option" << RESET << std::endl;
            return;
        }
    } else if (__target_opt == TIME_FORMAT) {
        if (__opt & HH_MM_SS) {
            time_format_ = "%H:%M:%S";
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
    target_file_.open(target_file_name_, std::ios::out | std::ios::app);
    if (!target_file_.is_open()) {
        std::cerr << RED << "[Logger::flush_logs] Error opening file" << RESET << std::endl;
        return -1;
    }
    for (int i = 0; i < total_logs_; i++) {
        target_file_ << logs[i] << std::endl;
    }
    target_file_.close();
    total_logs_ = 0;
}

int Logger::log_command(const char*) {
    int rc = 0;
    get_date();
    std::string log_entry = "[" + std::string(time_buffer_) + "]" + command;
    if (total_logs_ < LOG_LIMIT) {
        logs[total_logs_] = log_entry;
    } else {
        rc = flush_logs();
        if (rc != 0) {
            std::cerr << RED << "[Logger::log_command] Error flushing logs" << RESET << std::endl;
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
    struct tm* time_info = localtime(&current_time);

    combined_format_ = date_format_ + " " + time_format_;

    strftime(time_buffer_, sizeof(time_buffer_), combined_format_.c_str(), time_info);
}

Logger::~Logger() {
    target_file.close();
}