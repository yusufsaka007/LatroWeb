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

#include <libssh/callbacks.h>
#include <libssh/server.h>
#include <string>
#include <iostream>
#include <atomic>
#include <vector>
#include <thread>
#include <mutex>
#include <pty.h>
#include <sys/ioctl.h>
#include "color_codes.h"

#define DEFAULT_PORT 2222
#define DEFAULT_IP "0.0.0.0"
#define DEFAULT_USERNAME "username"
#define DEFAULT_PASSWORD "password"
const std::string SSH_BANNER = "SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1.1";

// for libssh callbacks
namespace cb {
    static int auth_password(ssh_session session, const char* user, const char* password, void* userdata);
    static ssh_channel channel_open(ssh_session, void* userdata);
    static int pty_request(ssh_session session, ssh_channel channel, const char *term, int cols, int rows, int py, int px, void *userdata);
    static int pty_resize(ssh_session session, ssh_channel channel, int cols, int rows, int py, int px, void *userdata);
    static int shell_request(ssh_session session, ssh_channel channel, void *userdata);
    static int exec_request(ssh_session session, ssh_channel channel,const char *command, void *userdata);
    static int data_function(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata);
}
/*
struct winsize {
    unsigned short int ws_row;
    unsigned short int ws_col;
    unsigned short int ws_xpixel;
    unsigned short int ws_ypixel;
};
*/

struct ChannelData {
    // For PTY allocation 
    int pty_master; 
    int pty_slave;  

    // For communication with the client 
    int child_stdin;  
    int child_stdout; 
    int child_stderr; 
    // Event used to monitor descriptors 
    ssh_event event;
    struct winsize* winsize;
};
struct ClientData {
    char* username;
    char* password;
    int auth;
    ssh_channel channel;
};

class SSHServer {
public:
    SSHServer(const std::string& address, const unsigned int port, const std::string& username, const std::string& password);
    SSHServer();
    ~SSHServer();
    void set_options();
    void start();
    void stop();
    void cleanup();
private:
    void handle_client(ssh_event event, ssh_session session);

    // Server variables
    std::atomic<bool> runServer_ = false; // If false all sessions will be closed
    std::vector<std::thread> threads_; // Container for all the threads handling the clients
    std::string address_;
    unsigned int port_;
    std::string username_;
    std::string password_;
    ssh_bind ssh_bind_;
    int sessionVerbosity = SSH_LOG_PROTOCOL;
    int bindVerbosity = SSH_LOG_PROTOCOL;
};

#endif // SSH_SERVER_H