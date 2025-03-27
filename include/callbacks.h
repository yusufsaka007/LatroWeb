/*
This file has the appropriate callbacks for the libssh server.
*/

#ifndef CALLBACKS_H
#define CALLBACKS_H

#include <iostream>
#include <pty.h>
#include <libssh/server.h> 
#include <libssh/callbacks.h>
#include <string>
#include <poll.h>
#include <utmp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <memory>
#include <signal.h>
#include <vector>
#include <pthread.h>
#include <atomic> // if multi threaded in future
#include "color_codes.h"

struct session_data_struct {
    ssh_channel channel;
    int auth_attempts;
    int authenticated;
    std::string* username;
    std::string* password;
};

struct channel_data_struct {
    pid_t pid; // PID of the child process the channel will spawn
    socket_t pty_master;
    socket_t pty_slave; 
    /* For communicating with the child process */
    socket_t child_stdin; 
    socket_t child_stdout; 
    socket_t child_stderr;
    ssh_event event; // Event to poll the descriptors
    struct winsize* winsize; // Terminal size struct
};

namespace cb{
    int auth_password(ssh_session session, const char* user, const char* password, void* userdata);
    ssh_channel channel_open(ssh_session session, void* userdata);
    int pty_request(ssh_session session, ssh_channel channel, const char *term, int cols, int rows, int py, int px, void *userdata);
    int pty_resize(ssh_session session, ssh_channel channel, int cols, int rows, int py, int px, void *userdata);
    int shell_request(ssh_session session, ssh_channel channel, void *userdata);
    int exec_request(ssh_session session, ssh_channel channel,const char *command, void *userdata);
    int data_function(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata);
}

#endif // CALLBACKS_H