/* This is the base of the LatroWeb Honeypot */
/*
    * It uses libssh SSH as communication protocol
    * It simulates a realistic environment for the attacker
    * Works together with the audit Logger
    * Will enable the attacker to enter the system with random amount of tries making the brute force attack seem successful
*/

/*

Copyright 2025 Yusuf Saka

This file is part of the LatroWeb HoneyPot Project.
Feel free to copy this file, modify it in any way.
Used for educational purposes and research only.

*/

#ifndef SSH_SERVER_H
#define SSH_SERVER_H

#include "callbacks.h"

#define DEFAULT_PORT 2222
#define DEFAULT_IP "0.0.0.0"
#define DEFAULT_USERNAME "username"
#define DEFAULT_PASSWORD "password"
#define SESSION_END (SSH_CLOSED | SSH_CLOSED_ERROR)

class SSHServer {
public:
    SSHServer();
    SSHServer(const char* ip, uint32_t port, const char* username, const char* password);
    ~SSHServer();
    void set_options();
    void start();
    void cleanup();
    void handle_session(ssh_event event, ssh_session session);
    static void* session_thread_helper(void* arg);
    void session_thread(ssh_session __s);
    static void sigterm_handler(int signum);
    static void sigchld_handler(int signum);
    void register_signal_handler();
private:
    std::string ip_;
    uint32_t port_;
    std::string username_;
    std::string password_;
    ssh_bind sshbind_;
    ssh_session session_;
    std::atomic<bool> shutdown_flag_;
    static SSHServer* instance_;
    std::vector<pthread_t> threads_;
};

#endif // SSH_SERVER_H