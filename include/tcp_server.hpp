/*
TCP Server
*/

#ifndef TCP_SERVER_HPP
#define TCP_SERVER_HPP

#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <memory>
#include <atomic>
#include <errno.h>
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
#include "tcp_client.hpp"
#include "common_macros.hpp"

struct BufferChain {
    char bytes[MAX_BUFFER_SIZE];
    size_t len;
    struct BufferChain* next;
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