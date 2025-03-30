/*
TCP Server
*/

#ifndef TCP_SERVER_HPP
#define TCP_SERVER_HPP

#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <memory>
#include <string>
#include <atomic>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <thread>
#include <signal.h>
#include <vector>
#include <condition_variable>
#include <random>
#include <sys/select.h>
#include <fcntl.h>
#include <pty.h>
#include <utmp.h>
#include <sys/wait.h>
#include "login_parser.hpp"
#include "color_codes.hpp"

#define DEFAULT_PORT 2222
#define DEFAULT_IP "0.0.0.0"
#define DEFAULT_MAX_CONNECTIONS 5
#define WITH_THREADS 1
#define MAX_BUFFER_SIZE 65536


struct TCPClient {
    pid_t pid;
    int client_socket;
    int pty_master;
    int pty_slave;
    int stdin_fd;
    int stdout_fd;
    int stderr_fd;
    socklen_t addr_len;
    std::string ip;
    int index;
    int authenticated;
};

class TCPServer {
public:
    TCPServer();
    TCPServer(const int __port, const std::string& __ip, const std::string& __username, const std::string& __password, const uint8_t __max_connections);
    ~TCPServer();
    int init();
    void tcp_recv(int fd, char* buffer, const int size, ssize_t* bytes_read);
    void tcp_send(int fd, const char* buffer, const int size);
    int server_auth(TCPClient* client);
    int tcp_accept();
    int cleanup();
    void stop();
    void start();
    void handle_client(TCPClient* client);
    void set_brute_force(bool allow, int min, int max);
    int client_cleanup(TCPClient* client);
    void cleanup_client(TCPClient* client);
    void shell_handler(TCPClient* client);
private:    
    uint32_t port_; 
    std::string ip_;
    std::string username_;
    std::string password_;
    std::string hostname_;
    int server_fd_;
    struct sockaddr_in server_addr_;
    std::atomic<bool> shutdown_flag_ = true;
    uint8_t max_connections_;
    TCPClient* clients_ = nullptr;
    std::vector<std::thread> threads_;
    int client_count_ = 0;
    std::mutex client_mutex_;
    std::condition_variable client_cv_;
    std::atomic<bool> allow_brute_force_ = false;
    int success_at_ = 0;
};


#endif // TCP_SERVER_HPP