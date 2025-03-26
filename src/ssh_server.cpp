// ssh_server.cpp

#include "ssh_server.h"


static int cb::auth_password(ssh_session session, const char* user, const char* password, void* userdata){
    ClientData* pClient = static_cast<ClientData*>(userdata);
    if (strcmp(pClient->username, user) == 0 && strcmp(pClient->password, password) == 0){
        std::cout << GREEN << "Login successful"<< RESET << std::endl;
        pClient->auth = SSH_AUTH_SUCCESS;
        return SSH_AUTH_SUCCESS;
    }
    else{
        std::cerr << RED << "Failed login attempt: " << user << ":" << password << RED << std::endl;
        pClient->auth = SSH_AUTH_DENIED;
        return SSH_AUTH_DENIED;
    }
}

static ssh_channel cb::channel_open(ssh_session session, void* userdata) {
    ClientData* pClient = static_cast<ClientData*>(userdata);
    std::cout << GREEN << "Channel open request" << RESET << std::endl;
    pClient->channel = ssh_channel_new(session);
    return pClient->channel;
}

static int cb::pty_request(ssh_session session, ssh_channel channel, const char *term, int cols, int rows, int py, int px, void *userdata) {
    struct ChannelData* pChannel = static_cast<ChannelData*>(userdata);
    std::cout << GREEN << "PTY request" << RESET << std::endl;
    (void) session;
    (void) channel;
    (void) term;

    pChannel->winsize->ws_row = rows;
    pChannel->winsize->ws_col = cols;
    pChannel->winsize->ws_xpixel = px;
    pChannel->winsize->ws_ypixel = py;

    if (openpty(&pChannel->pty_master, &pChannel->pty_slave, NULL, NULL, pChannel->winsize) != 0) {
        std::cerr << RED << "Failed to open pty" << RESET << std::endl;
        return SSH_ERROR;
    }
    return SSH_OK;
}

static int cb::pty_resize(ssh_session session, ssh_channel channel, int cols, int rows, int py, int px, void *userdata){
    struct ChannelData* pChannel = static_cast<ChannelData*>(userdata);
    (void) session;
    (void) channel;

    pChannel->winsize->ws_row = rows;
    pChannel->winsize->ws_col = cols;
    pChannel->winsize->ws_xpixel = px;
    pChannel->winsize->ws_ypixel = py;

    if (pChannel->pty_master != -1) {
        return ioctl(pChannel->pty_master, TIOCSWINSZ, pChannel->winsize);
    }

    return SSH_ERROR;
}

static int cb::data_function(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata) {
    struct ChannelData* pChannel = static_cast<ChannelData*>(userdata);
    (void) session;
    (void) channel;
    (void) is_stderr;

    if (len == 0) {
        std::cerr << RED << "No data received" << RESET << std::endl;
        return 0;
    }

    std::cout << GREEN << "Data received: " << std::string(static_cast<char*>(data), len) << RESET << std::endl;
    return write(pChannel->child_stdin, static_cast<char*>(data), len);
}
static int cb::exec_request(ssh_session session, ssh_channel channel,const char *command, void *userdata) {
    struct ChannelData* pChannel = static_cast<ChannelData*>(userdata);

    (void) session;
    (void) channel;

    if (pChannel->pty_master == -1 && pChannel->pty_slave == -1) {
        std::cerr << RED << "PTY not allocated (from exec_request)" << RESET << std::endl;
        return SSH_ERROR;
    }

    std::cout << GREEN << "Exec request" << RESET << std::endl;
    return SSH_OK;
}

static int cb::shell_request(ssh_session session, ssh_channel channel, void *userdata) {
    struct ChannelData* pChannel = static_cast<ChannelData*>(userdata);

    (void) session;
    (void) channel;

    if (pChannel->pty_master == -1 || pChannel->pty_slave == -1) {
        std::cerr << RED << "PTY not allocated (from shell request)" << RESET << std::endl;
        return SSH_ERROR;
    }    

    // Test purpose
    std::cout << GREEN << "Shell request" << RESET << std::endl;
    return SSH_OK;
}


SSHServer::SSHServer(const std::string& address, const unsigned int port, const std::string& username, const std::string& password) {
    address_ = address;
    port_ = port;
    username_ = username;
    password_ = password;
}

SSHServer::SSHServer() {
    address_ = DEFAULT_IP;
    port_ = DEFAULT_PORT;
    username_ = DEFAULT_USERNAME;
    password_ = DEFAULT_PASSWORD;
}

SSHServer::~SSHServer() {
    cleanup();
}

void SSHServer::cleanup() {
    std::cout << "\n" << YELLOW << "Performing cleanup" << RESET << std::endl;
    ssh_bind_free(ssh_bind_);
    ssh_finalize();
}

void SSHServer::set_options() {
    ssh_bind_ = ssh_bind_new();
    ssh_bind_options_set(ssh_bind_, SSH_BIND_OPTIONS_LOG_VERBOSITY, &bindVerbosity);
    ssh_bind_options_set(ssh_bind_, SSH_BIND_OPTIONS_BINDADDR, address_.c_str());
    ssh_bind_options_set(ssh_bind_, SSH_BIND_OPTIONS_BINDPORT, &port_);
    ssh_bind_options_set(ssh_bind_, SSH_BIND_OPTIONS_RSAKEY, KEY_FILE);
    ssh_bind_options_set(ssh_bind_, SSH_BIND_OPTIONS_BANNER, SSH_BANNER.c_str());
}


void SSHServer::handle_client(ssh_event event, ssh_session session){
    int n=0;
    ssh_message message = nullptr;
    ssh_channel channel = nullptr;
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &sessionVerbosity);

    
    struct winsize wSize = {
        .ws_row= 0,
        .ws_col = 0,
        .ws_xpixel = 0,
        .ws_ypixel = 0
    };

    struct ChannelData channelData{
        .pty_master = -1,
        .pty_slave = -1,
        .child_stdin = -1,
        .child_stdout = -1,
        .child_stderr = -1,
        .event = nullptr,
        .winsize = &wSize
    };

    struct ClientData clientData{
        .username = const_cast<char*>(username_.c_str()),
        .password = const_cast<char*>(password_.c_str()),
        .auth = SSH_AUTH_DENIED,
        .channel = nullptr
    };

    struct ssh_server_callbacks_struct server_cb = {
        .userdata = &clientData,
        .auth_password_function = cb::auth_password,
        .channel_open_request_session_function = cb::channel_open
    };
    
    struct ssh_channel_callbacks_struct channel_cb = {
        .userdata = &channelData,
        .channel_pty_request_function = cb::pty_request,
        .channel_pty_window_change_function = cb::pty_resize,
        //.channel_shell_request_function = cb::shell_request,
        //.channel_exec_request_function = cb::exec_request,
        //.channel_data_function = cb::data_function,
    };

    ssh_callbacks_init(&server_cb);
    ssh_set_server_callbacks(session, &server_cb);
    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);
    
    if (ssh_handle_key_exchange(session) != SSH_OK) {
        std::cerr << RED << "Key exchange failed: " << ssh_get_error(session) << RESET << std::endl;
        goto cleanup;
    }
    std::cout << GREEN << "Key exchange successful" << RESET << std::endl;
    
    message = ssh_message_get(session);
    
    std::cout << GREEN << "Client authenticated successfully" << RESET << std::endl;

    

    /*if (clientData.auth != SSH_AUTH_SUCCESS) {
        std::cerr << RED << "Failed to authenticate user" << RESET << std::endl;
        goto cleanup;
    }
    std::cout << GREEN << "Client authenticated successfully" << RESET << std::endl;

    if (!ssh_channel_is_open(clientData.channel)) {
        std::cerr << RED << "Channel is not open" << RESET << std::endl;
        goto cleanup;
    }
    std::cout << GREEN << "Channel is open" << RESET << std::endl;
    */
    // Handle channel requests    

    cleanup:
        if (channel != nullptr) {
            ssh_channel_send_eof(channel);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
        }
        if (session != nullptr && ssh_is_connected(session)) {
            ssh_disconnect(session);
            ssh_free(session);
        }
        if (message != nullptr){
            ssh_message_free(message);  
        }
        if (event != nullptr){
            ssh_event_free(event);
        }
}

// Bind to the server and start listening for incoming connections
// New session will be created for each incoming connection
// Each session will have thread to function

void SSHServer::start() {
    ssh_session session;
    if (ssh_bind_listen(ssh_bind_) < 0) {
        std::cerr << RED << "Error: " << ssh_get_error(ssh_bind_) << std::endl;
        return;
    } 
    runServer_ = true;
    std::cout << BLUE << "\nListening on " << address_ << ":" << port_ << std::endl;
    std::cout << BLUE << "Credentials: " << username_ << ":" << password_ << std::endl;
    std::cout << GREEN << "SSH Server started successfully." << RESET << std::endl;
    session = ssh_new();
    while (runServer_) {
        
        if (session == NULL) {
            std::cerr << RED << "Failed to allocate session" << RESET << std::endl;
            continue;
        }

        if (ssh_bind_accept(ssh_bind_, session) == SSH_ERROR) {
            std::cerr << RED << "Error accepting connection: " << ssh_get_error(ssh_bind_) << RESET << std::endl;
            ssh_free(session);
            continue;
        }
        
        ssh_event event = ssh_event_new();
        if (event == NULL) {
            std::cerr << RED << "Failed to create polling context" << RESET << std::endl;
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }
      
        threads_.emplace_back(&SSHServer::handle_client, this, event, session);
        
        //ssh_event_free(event);
        //ssh_disconnect(session);
        //ssh_free(session);
    }
}

// Stop the server
// Handle threads (avoid memory leaks)
void SSHServer::stop() {
    runServer_ = false;
    for (std::thread& t : threads_) {
        if (t.joinable()) {
            t.join(); // Wait for threads to terminate
        }
    }
}