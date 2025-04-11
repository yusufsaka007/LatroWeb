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
#include <limits.h>
#include "login_parser.hpp"
#include "color_codes.hpp"
#include "logger.hpp"

#define DEFAULT_PORT 2222
#define DEFAULT_IP "0.0.0.0"
#define DEFAULT_MAX_CONNECTIONS 5
#define WITH_THREADS 1
#define MAX_BUFFER_SIZE 16384
#define PIPE_READ 0
#define PIPE_WRITE 1

#define SHELL_BIN "/bin/bash" // Replace with the path to the shell in the virtual environment
#define SHELL_ARG "-c"

struct BufferChain {
    char bytes[MAX_BUFFER_SIZE];
    size_t len;
    struct BufferChain* next;
};

struct TCPClient {
    pid_t pid;
    int client_socket;
    int pty_master;
    int pty_slave;
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
};

class TCPServer {
public:
    TCPServer();
    TCPServer(const int __port, const std::string& __ip, const std::string& __username, const std::string& __password, const uint8_t __max_connections);
    ~TCPServer();
    int init();
    void tcp_recv(int client_socket, char* buffer, const int size, ssize_t* bytes_read);
    void tcp_send(int client_socket, const char* buffer, const int size);
    void tcp_send(int client_socket, struct BufferChain* buffers, size_t& total_bytes);
    int server_auth(TCPClient* client);
    int tcp_accept();
    int cleanup();
    void stop();
    void start();
    void handle_client(TCPClient* client);
    void set_brute_force(bool allow, int min, int max);
    int client_cleanup(TCPClient* client);
    void cleanup_client(TCPClient* client);
    void handle_shell(TCPClient* client);
    int exec_request(TCPClient* client);
    struct BufferChain* read_pipe(int fd);
    void free_buffer_chain(struct BufferChain* buffers);
    size_t get_total_bytes(struct BufferChain* buffers);
    void trim_newline(char* str, ssize_t& len);
private:    
    uint32_t port_; 
    std::string ip_;
    std::string username_;
    std::string password_;
    std::string hostname_;
    std::string shell_prompt_;
    int uid_;
    int gid_;
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