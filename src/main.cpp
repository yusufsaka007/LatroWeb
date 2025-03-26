// main.cpp
/*
#include "ssh_server.h"
#include <csignal>

SSHServer* server = nullptr;

void handle_signal(int signal) {
    if (signal == SIGINT) {
        std::cout << "\n" << YELLOW << "CTRL^C received." << RESET << std::endl;
        ssh_finalize();
        if (server) {
            server->stop();
            delete server;
        }

        exit(0);
    }
}

int main(int argc, char** argv) {
    signal(SIGINT, handle_signal);
    if (ssh_init() != SSH_OK) {
        std::cerr << RED << "Failed to initialize libssh" << RESET << std::endl;
        return -1;
    }

    if (argc == 5) {
        server = new SSHServer(argv[1], std::stoi(argv[2]), argv[3], argv[4]);
    } else {
        server = new SSHServer();
    }

    server->set_options();
    server->start();
    server->stop();

    delete server;

    return 0;
}
*/

#include <iostream>
#include <pty.h>
#include <libssh/libssh.h>
#include <libssh/server.h> 
#include <libssh/callbacks.h>
#include <signal.h>
#include <thread>
#include <vector>
#include <string>

#define RESET  "\033[0m"
#define RED "\033[31m[-] "
#define GREEN "\033[32m[+] "
#define YELLOW "\033[33m[!] "
#define BLUE "\033[34m"
#define MAGENTA "\033[35m" 
#define CYAN "\033[36m"



#define USER "username"
#define PASS "password"


bool runProgram = true;

void sigterm_handler(int signal) {
    if (signal == SIGINT) {
        std::cout << "\n" << YELLOW << "CTRL^C received." << RESET << std::endl;
        ssh_finalize();
        runProgram = false;
        exit(0);
    }
}

struct channel_data_struct {
    int pty_master;
    int pty_slave;
    ssh_event event;
    struct winsize *winsize;
};

struct session_data_struct {
    ssh_channel channel;
    int auth_attempts;
    int authenticated;
};

static int auth_password(ssh_session session, const char* user, const char* pass, void* userdata) {
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;

    if (strcmp(user, USER) == 0 && strcmp(pass, PASS) == 0) {
        std::cout << GREEN << "Login successful" << RESET << std::endl;
        sdata->authenticated = 1;
        return SSH_AUTH_SUCCESS;
    }
    std::cout << RED << "Failed login attempt: " << user << ":" << pass << RESET << std::endl;
    sdata->auth_attempts++;
    return SSH_AUTH_DENIED;
}

static ssh_channel channel_open(ssh_session session, void* userdata) {
    std::cout << GREEN << "Channel request has been made" << RESET << std::endl;
    
    struct session_data_struct* sdata = static_cast<struct session_data_struct*>(userdata);
    sdata->channel = ssh_channel_new(session);
    return sdata->channel;
}

static int pty_request(ssh_session session, ssh_channel channel, const char* term, int cols, int rows, int py, int px, void* userdata) {
    struct channel_data_struct* cdata = static_cast<struct channel_data_struct*>(userdata);
    (void) session;
    (void) channel;
    (void) term;

    cdata->winsize->ws_row = rows;
    cdata->winsize->ws_col = cols;
    cdata->winsize->ws_xpixel = px;
    cdata->winsize->ws_ypixel = py;

    if (openpty(&cdata->pty_master, &cdata->pty_slave, NULL, NULL, cdata->winsize) != 0) {
        std::cerr << RED << "Failed to open pty" << RESET << std::endl;
        return SSH_ERROR;
    }
    return SSH_OK;
}


static int shell_request(ssh_session session, ssh_channel channel, void* userdata) {
    struct channel_data_struct* cdata = static_cast<struct channel_data_struct*>(userdata);

    (void) session;
    (void) channel;

    if (cdata->pty_master == -1 && cdata->pty_slave == -1) {
        std::cerr << RED << "PTY not allocated" << RESET << std::endl;
        return SSH_ERROR;
    }

    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << RED << "Failed to fork" << RESET << std::endl;
        return SSH_ERROR;
    }

    if (pid == 0) {
        // child process: setup the shell
        close(cdata->pty_master); // close the master side in the child process
        if(setsid() < 0) {
            std::cerr << RED << "Failed to create new session" << RESET << std::endl;
            exit(1);
        }
        if(ioctl(cdata->pty_slave, TIOCSCTTY, NULL) < 0) {
            std::cerr << RED << "Failed to set the controlling terminal" << RESET << std::endl;
            exit(1);
        }

        dup2(cdata->pty_slave, STDIN_FILENO);
        dup2(cdata->pty_slave, STDOUT_FILENO);
        dup2(cdata->pty_slave, STDERR_FILENO);

        close(cdata->pty_slave);

        execl("/bin/bash", "/bin/bash", NULL);
        exit(1);
    }

    close(cdata->pty_slave);

    char buffer[1024];
    while (ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)) {
        // Read from the SSH channel and write to the PTY
        int nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        if (nbytes > 0) {
            write(cdata->pty_master, buffer, nbytes);
        }

        // Read from the PTY and write to the SSH channel
        nbytes = read(cdata->pty_master, buffer, sizeof(buffer));
        if (nbytes > 0) {
            ssh_channel_write(channel, buffer, nbytes);
        }
    }

    close(cdata->pty_master);
    ssh_channel_close(channel);
    return SSH_OK;
}

static void handle_session(ssh_event event, ssh_session session) {
    struct winsize wsize = {
        .ws_row = 0,
        .ws_col = 0,
        .ws_xpixel = 0,
        .ws_ypixel = 0
    };

    struct channel_data_struct cdata = {
        .pty_master = -1,
        .pty_slave = -1,
        .event = NULL,
        .winsize = &wsize
    };

    struct session_data_struct sdata = {
        .channel = NULL,
        .auth_attempts = 0,
        .authenticated = 0
    };

    struct ssh_channel_callbacks_struct channel_cb = {
        .userdata = &cdata,
        .channel_pty_request_function = pty_request,
        .channel_shell_request_function = shell_request
    };

    struct ssh_server_callbacks_struct server_cb = {
        .userdata =&sdata,
        .auth_password_function = auth_password,
        .channel_open_request_session_function = channel_open
    };

    ssh_callbacks_init(&server_cb);
    ssh_callbacks_init(&channel_cb);

    ssh_set_server_callbacks(session, &server_cb);

    if (ssh_handle_key_exchange(session) != SSH_OK) {
        std::cerr << RED << "Key exchange failed: " << ssh_get_error(session) << RESET << std::endl;
        return;
    }
    std::cout << GREEN << "Successful key exchange" << RESET << std::endl;
    ssh_event_add_session(event, session);

    while (sdata.authenticated == 0 || sdata.channel == NULL) {
        if (runProgram == false) {
            return;
        }
        if (sdata.auth_attempts >=3) {
            return;
        }

        if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
            std::cerr << RED << ssh_get_error(session) << RESET << std::endl;
            return;
        }
    }
    std::cout << GREEN << "Authenticated user" << RESET << std::endl;
    ssh_set_channel_callbacks(sdata.channel, &channel_cb);

    do {
        if (ssh_event_dopoll(event, -1) == SSH_ERROR) {
            std::cerr << RED << "Error during polling" << RESET << std::endl;
            ssh_channel_closer(sdata.channel);
        }
        if (cdata.event != NULL) {
            continue; 
        }
        cdata.event = event;
        if (cdata) // change the cdata add stdout and shit
    }

    ssh_channel_close(sdata.channel);
    ssh_channel_free(sdata.channel);

    return;
}

int main() {
    signal(SIGINT, sigterm_handler);
    ssh_bind sshbind;
    ssh_session session;
    ssh_event event;
    int rc;
    int port = 2222;
    std::string address = "0.0.0.0";
    int bindVerbosity = SSH_LOG_PACKET;
    rc = ssh_init();
    if (rc < 0) {
        std::cout << RED << "ssh_init failed" << RESET << std::endl;
        return -1;
    }

    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        std::cout << RED << "ssh_bind_new failed" << RESET << std::endl;
        return -1;
    }
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, SSH_KEY);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &bindVerbosity);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, address.c_str());
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    if (ssh_bind_listen(sshbind) < 0) {
        std::cout << RED << ssh_get_error(sshbind) << RESET << std::endl;
        return -1;
    }

    while (runProgram) {
        session = ssh_new();
        if (session == NULL) {
            std::cout << RED << "Failed to allocate session" << RESET << std::endl;
            continue;
        }
        std::cout << BLUE << "Waiting for incoming connection" << RESET << std::endl;
        if (ssh_bind_accept(sshbind, session) != SSH_ERROR) {
            std::cout << GREEN << "Accepted incoming connection" << RESET << std::endl;
            event = ssh_event_new();
            if (event == NULL) {
                std::cout << RED << "Failed to allocate event" << RESET << std::endl;
                return -1;
            }
            handle_session(event, session);
            ssh_event_free(event);
            runProgram = false;

        } else {
            std::cout << RED << "Failed to accept incoming connection" << ssh_get_error(sshbind) << RESET << std::endl;
        }
        ssh_disconnect(session);
        ssh_free(session);
    }

    std::cout << YELLOW << "Cleaning up" << RESET << std::endl;
    ssh_bind_free(sshbind);
    ssh_finalize();

    return 0;
}