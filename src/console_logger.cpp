#include "console_logger.hpp"

std::mutex console_mutex;
std::condition_variable console_cv;
std::queue<std::string> log_queue;

void log_console(TCPClient* clients, std::atomic<bool>& shutdown_flag) {
    while (!shutdown_flag) {
        std::unique_lock<std::mutex> lock(console_mutex);
        // Wait until there is data in the queue or shutdown flag is set
        console_cv.wait(lock, [] {return !log_queue.empty() || shutdown_flag;});
        if (shutdown_flag) {
            break;
        }

        while (!log_queue.empty()) {
            std::string log_message = log_queue.front();
            log_queue.pop();
            std::cout << log_message << std::endl;
        }
    }
}