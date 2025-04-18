#ifndef TCP_CLIENT_HPP
#define TCP_CLIENT_HPP

#include <string>
#include <queue>
#include <mutex>
#include <sstream>
#include <sys/socket.h>
#include <condition_variable>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "logger.hpp"
#include "common_macros.hpp"
#include "color_codes.hpp"

extern std::mutex console_mutex;
extern std::condition_variable console_cv;
extern std::queue<std::string> log_queue;

struct TCPClient {
    pid_t pid;
    int client_socket;
    int stdin_pipe[2];
    int stdout_pipe[2];
    int stderr_pipe[2];
    socklen_t addr_len;
    std::string ip;
    int index;
    int authenticated;
    char command_request[MAX_BUFFER_SIZE + 1];
    uint8_t command_request_len;
    Logger* logger;
    std::string current_dir;
    std::stringstream event_log;
};

/*
Modify the client then notify the console logger
*/
void log_client(TCPClient* client);

void cleanup_client(TCPClient* client);


#endif // TCP_CLIENT_HPP