#ifndef CONSOLE_LOGGER_HPP
#define CONSOLE_LOGGER_HPP

#include <iostream>
#include <string>
#include <atomic>
#include <common_macros.hpp>
#include <mutex>
#include <condition_variable>
#include <queue>
#include "color_codes.hpp"

extern std::mutex console_mutex;
extern std::condition_variable console_cv;
extern std::queue<std::string> log_queue;

/*
Will be called in a seperate thread
If the buffer is not empty it will print it to the console
Works together with the log_client function
*/
void log_console(const std::atomic<bool>& shutdown_flag);

#endif // CONSOLE_LOGGER_HPP