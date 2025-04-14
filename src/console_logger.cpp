#include "console_logger.hpp"

std::mutex console_mutex;
std::condition_variable console_cv;
std::queue<std::string> log_queue;

void log_console(const std::atomic<bool>& shutdown_flag) {
    try{
        while (!shutdown_flag) {
            std::unique_lock<std::mutex> lock(console_mutex);
            // Wait until there is data in the queue or shutdown flag is set
            console_cv.wait(lock, [&shutdown_flag] {return !log_queue.empty() || shutdown_flag;});

            while (!log_queue.empty()) {
                std::string log_message = std::move(log_queue.front());
                log_queue.pop();
                std::cout << log_message << std::endl;
            }

            if (shutdown_flag) {
                std::cout << YELLOW << "[log_console] Shutting down console logger" << RESET << std::endl;
                break;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << RED << "[log_console] Error: " << e.what() << RESET << std::endl;
    } catch (...) {
        std::cerr << RED << "[log_console] Unknown error" << RESET << std::endl;
    }
}