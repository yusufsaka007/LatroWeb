// ssh_server.cpp

#include "ssh_server.h"

SSHServer* SSHServer::instance_ = nullptr;

SSHServer::SSHServer() {
    ip_ = DEFAULT_IP;
    port_ = DEFAULT_PORT;
    username_ = DEFAULT_USERNAME;
    password_ = DEFAULT_PASSWORD;
    shutdown_flag_ = false;
    instance_ = this;
}

SSHServer::SSHServer(const char* ip, uint32_t port, const char* username, const char* password) {
    ip_ = ip;
    port_ = port;
    username_ = username;
    password_ = password;
    shutdown_flag_ = false;
    instance_ = this;
}

SSHServer::~SSHServer() {
    cleanup();
}

void SSHServer::sigterm_handler(int signum) {
    if (signum == SIGINT) {
        instance_->shutdown_flag_ = true;
    }
}

void SSHServer::sigchld_handler(int signum) {
    (void) signum;
    while (waitpid(-1, NULL, WNOHANG) > 0) {
        // Reap all the zombie processes
    }
}

void SSHServer::register_signal_handler() {
    struct sigaction sa;

    // SIGINT handler
    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    // SIGCHLD handler
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
}

void SSHServer::set_options() {
    std::cout << MAGENTA << "[SSHServer::set_options]: Setting the SSH server options" << RESET << std::endl;
    sshbind_ = ssh_bind_new();
    if (sshbind_ == NULL) {
        std::cerr << RED << "[SSHServer::set_options]: ssh_bind_new failed" << RESET << std::endl;
        return;
    }
    ssh_bind_options_set(sshbind_, SSH_BIND_OPTIONS_BINDADDR, ip_.c_str());
    ssh_bind_options_set(sshbind_, SSH_BIND_OPTIONS_BINDPORT, &port_);
    ssh_bind_options_set(sshbind_, SSH_BIND_OPTIONS_HOSTKEY, KEY_FILE);
}

void SSHServer::start() {
    int rc;
    std::cout << MAGENTA << "[SSHServer::start]: Starting the SSH server" << RESET << std::endl;

    rc = ssh_init();
    if (rc < 0) {
        std::cerr << RED << "[SSHServer::start]: ssh_init failed" << RESET << std::endl;
        return;
    }

    rc = ssh_bind_listen(sshbind_);
    if (rc < 0) {
        std::cerr << RED << "[SSHServer::start]: " << ssh_get_error(sshbind_) << RESET << std::endl;
        return;
    }

    while (shutdown_flag_ == false) {
        session_ = ssh_new();
        if (session_ == NULL) {
            std::cerr << RED << "[SSHServer::start]: Failed to allocate session" << RESET << std::endl;
            continue;
        }

        // Block until new connection arises
        rc = ssh_bind_accept(sshbind_, session_);
        if (rc != SSH_ERROR) {
            pthread_t t;
            rc = pthread_create(&t, NULL, &SSHServer::session_thread_helper, this);
            if (rc == 0) {
                pthread_detach(t);
                threads_.push_back(std::move(t)); 
                continue;
            }
            
        } else{
            std::cerr << RED << "[SSHServer::start]: " << ssh_get_error(sshbind_) << RESET << std::endl;
        }
    }

    return;
}

void* SSHServer::session_thread_helper(void* arg) {
    SSHServer* server = static_cast<SSHServer*>(arg);
    server->session_thread(server->session_);
    return nullptr;
}

void SSHServer::session_thread(ssh_session __s) {
    ssh_session session = __s;
    ssh_event event;

    std::cout << MAGENTA << "[SSHServer::session_thread]: Starting a new session thread" << RESET << std::endl;
    event = ssh_event_new();
    if (event != NULL) {
        handle_session(event, session);
    } else {
        std::cerr << RED << "[SSHServer::session_thread]: Failed to create event" << RESET << std::endl;
    }
    if (session != nullptr) ssh_free(session);
    if (ssh_is_connected(session)) ssh_disconnect(session);
}

void SSHServer::handle_session(ssh_event event, ssh_session session) {
    int n; // Used to give the client 5 seconds before terminating the session
    int rc = 0;    

    std::cout << BLUE << "[SSHServer::handle_session]: Handling a new session: " << session << RESET << std::endl;

    struct winsize wsize = {
        .ws_row = 0,
        .ws_col = 0,
        .ws_xpixel = 0,
        .ws_ypixel = 0
    };

    struct session_data_struct sdata = {
        .channel = NULL,
        .auth_attempts = 0,
        .authenticated = 0,
        .username = &username_,
        .password = &password_
    };

    struct channel_data_struct cdata = {
        .pid = 0,
        .pty_master = -1,
        .pty_slave = -1,
        .child_stdin = -1,
        .child_stdout = -1,
        .child_stderr = -1,
        .event = NULL,
        .winsize = &wsize
    };

    struct ssh_server_callbacks_struct server_cb;
    server_cb.userdata = &sdata;
    server_cb.auth_password_function = cb::auth_password;
    server_cb.channel_open_request_session_function = cb::channel_open;

    struct ssh_channel_callbacks_struct channel_cb;
    channel_cb.userdata = &cdata,
    channel_cb.channel_pty_request_function = cb::pty_request;
    channel_cb.channel_pty_window_change_function = cb::pty_resize;
    channel_cb.channel_shell_request_function = cb::shell_request;
    channel_cb.channel_exec_request_function = cb::exec_request; // wont be allowed later
    channel_cb.channel_data_function = cb::data_function;

    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);

    ssh_callbacks_init(&server_cb);
    ssh_callbacks_init(&channel_cb);

    ssh_set_server_callbacks(session, &server_cb);

    // Key exchange
    if (ssh_handle_key_exchange(session) != SSH_OK) {
        std::cerr << RED << "[SSHServer::handle_session]: Key exchange failed: " << ssh_get_error(session) << RESET << std::endl;
        goto cleanup;
    }
    std::cout << GREEN << "[SSHServer::handle_session]: Successful key exchange" << RESET << std::endl;
    
    rc = ssh_event_add_session(event, session);
    if (rc != SSH_OK) {
        std::cerr << RED << "[SSHServer::handle_session]: Failed to add session to event" << RESET << std::endl;
        goto cleanup;
    }

    // Authentica and open a channel
    while (sdata.authenticated == 0 || sdata.channel == NULL) {
        /* To Do! Simulate a successful brute force attempt at random X attempts to make the attacker get inside*/
        if (sdata.auth_attempts >= 3) {
            std::cout << YELLOW << "[SSHServer::handle_session]: Auth attempts exceeded" << RESET << std::endl;
            goto cleanup;
        }
        if (ssh_event_dopoll(event, -1) == SSH_ERROR) {
            std::cerr << RED << "[SSHServer::handle_session]: " << ssh_get_error(session) << RESET << std::endl;
            goto cleanup;
        }
    }

    std::cout << GREEN << "[SSHServer::handle_session]: Authenticated user" << RESET << std::endl;

cleanup:
    std::cout << YELLOW << "[SSHServer::handle_session]: Cleaning up the session" << RESET << std::endl;
    if(ssh_is_connected(session)) ssh_disconnect(session); std::cout << YELLOW << "[SSHServer::handle_session]: Disconnected the session" << RESET << std::endl;
    if(session != nullptr) ssh_free(session); std::cout << YELLOW << "[SSHServer::handle_session]: Freed the session" << RESET << std::endl;
    if(event != nullptr) ssh_event_free(event); std::cout << YELLOW << "[SSHServer::handle_session]: Freed the event" << RESET << std::endl;
    if(cdata.event != nullptr) ssh_event_free(cdata.event); std::cout << YELLOW << "[SSHServer::handle_session]: Freed the sdata event" << RESET << std::endl;
    if(ssh_channel_is_open(sdata.channel)) ssh_channel_free(sdata.channel); std::cout << YELLOW << "[SSHServer::handle_session]: Freed the channel" << RESET << std::endl;
}

void SSHServer::cleanup() {
    std::cout << MAGENTA << "[SSHServer::cleanup]: Stopping the SSH server" << RESET << std::endl;
    if (sshbind_ != nullptr) ssh_bind_free(sshbind_); 
    if (ssh_is_connected) ssh_disconnect(session_);
    if (session_ != nullptr) ssh_free(session_);
    ssh_finalize();

    for (auto& t : threads_) {
        pthread_join(t, NULL);
    }

    return;
}