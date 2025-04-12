#ifndef CONSOLE_LOGGER_HPP
#define CONSOLE_LOGGER_HPP

#include <iostream>
#include <string>
#include <atomic>
#include <common_macros.hpp>
#include <mutex>
#include <condition_variable>
#include <queue>
#include "tcp_client.hpp"

/*
Will be called in a seperate thread
If the buffer is not empty it will print it to the console
Works together with the log_client function
*/
void log_console(TCPClient* client, std::atomic<bool>& shutdown_flag);

#endif // CONSOLE_LOGGER_HPP