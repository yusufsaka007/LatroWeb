// Implementing a fake SSH server for my honeypot project
// Does not have to be too complex, just enough to fool the attacker
// Will be using POSIX sockets

#include "tcp_server.hpp"

TCPServer::~TCPServer() {
    this->cleanup();
}

TCPServer::TCPServer(const int __port, const std::string& __ip, const std::string& __username, const std::string& __password, const uint8_t __max_connections)
{
    port_ = __port;
    ip_ = __ip;
    username_ = __username;
    password_ = __password;
    max_connections_ = __max_connections;
    server_fd_ = -1;
    bzero(&server_addr_, sizeof(server_addr_));
}

TCPServer::TCPServer() {
    int rc;

    port_ = DEFAULT_PORT;
    ip_ = DEFAULT_IP;
    rc = js::get_value(username_, "username");
    rc = js::get_value(password_, "password");
    rc = js::get_value(hostname_, "hostname");

    if (rc == 0) {
        std::cerr << RED << "[TCPServer::TCPServer] Error getting values from JSON file" << RESET << std::endl;
        return;
    }

    max_connections_ = DEFAULT_MAX_CONNECTIONS;
    server_fd_ = -1;
    bzero(&server_addr_, sizeof(server_addr_));
}

int TCPServer::init() {
    int rc;
    
    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        std::cerr << "[TCPServer::init] Error creating socket" << std::endl;
        return 0;
    }
    server_addr_.sin_family = AF_INET;
    server_addr_.sin_port = htons(port_);
    rc = inet_pton(AF_INET, ip_.c_str(), &server_addr_.sin_addr);
    if (rc == 0) {
        std::cerr << RED << "[TCPServer::init] IP address is not valid" << RESET << std::endl;
        return 0;
    }
    else if (rc < 0) {
        std::cerr << RED << "[TCPServer::init] Error converting IP address: " << strerror(errno) << RESET << std::endl; // Use strerror_r for thread safety in the clients
        return 0;
    }

    rc = bind(server_fd_, (const struct sockaddr*) &server_addr_, sizeof(server_addr_));
    if (rc < 0) {
        std::cerr << RED << "[TCPServer::init] Error binding socket: " << strerror(errno) << RESET << std::endl;
        return 0;
    }
    rc = listen(server_fd_, 1);
    if (rc < 0) {
        std::cerr << RED << "[TCPServer::init] Error listening on socket: " << strerror(errno) << RESET << std::endl;
        return 0;
    }
    
    shutdown_flag_ = false;
    
    return 1;
}

void TCPServer::tcp_recv(int client_socket, char* buffer, const int size, ssize_t* bytes_read=nullptr) { // Non blocking
    int rc;
    
    while (!shutdown_flag_) {
        fd_set read_fds;
        struct timeval timeout;
        FD_ZERO(&read_fds);
        FD_SET(client_socket, &read_fds);

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        rc = select(client_socket + 1, &read_fds, NULL, NULL, &timeout);
        if (rc < 0) {
            throw std::runtime_error(std::string("[TCPServer::tcp_recv] Error selecting the socket: ") + strerror(errno));
        }
        else if (rc == 0) {
            continue; // Timeout, check if shutdown_flag_ is set
        }

        // Data is available to read

        rc = recv(client_socket, buffer, size, 0);
        if (rc < 0) {
            throw std::runtime_error(std::string("[TCPServer::tcp_recv] Error receiving the data: ") + strerror(errno));
        }
        else if (rc == 0) {
            throw std::runtime_error(std::string("[TCPServer::tcp_recv] Client disconnected: "));
        }
        if (bytes_read != nullptr) {
            *bytes_read = rc;
        }
        break;
    }

    buffer[rc] = '\0';
}

void TCPServer::tcp_send(int client_socket, const char* buffer, int size=-1) {
    int rc;
    int total_bytes = 0;
    if (size == -1) {
        size = strlen(buffer);
    }
    while (!shutdown_flag_ && total_bytes < size) {
        rc = send(client_socket, buffer + total_bytes, size - total_bytes, 0);
        if (rc < 0) { 
            throw std::runtime_error(std::string("[TCPServer::tcp_send] Error sending data: ") + strerror(errno));
        }
        else if (rc == 0) {
            throw std::runtime_error(std::string("[TCPServer::tcp_recv] Client disconnected"));
        }
        total_bytes += rc;
    }
}

void TCPServer::set_brute_force(bool allow, int min, int max) {
    // Create a random number between 50 and 100
    if (min < 0) {
        std::cerr << RED << "[TCPServer::set_brute_force] Minimum value must be greater or equal than 0" << RESET << std::endl;
        return;
    }
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(min, max);
    success_at_ = dis(gen);
    allow_brute_force_ = allow; 
}

int TCPServer::server_auth(TCPClient* client) {
    char login[MAX_USERNAME_SIZE + MAX_PASSWORD_SIZE + 2];
    int rc;
    try {
        do {
            tcp_send(client->client_socket, "Login (username:password): ");
            
            tcp_recv(client->client_socket, login, MAX_USERNAME_SIZE + MAX_PASSWORD_SIZE + 2);
            login[rc] = '\0';
            std::cout << GREEN << "[TCPServer::server_auth] Received credentials from client " << client->ip << ": " << login << RESET << std::endl;
    
            char* delimeter = strchr(login, ':');
            if (delimeter == NULL) {
                tcp_send(client->client_socket, "Expected format: (username:password)\n");
                continue;
            }
            *delimeter = '\0'; // replace ':' with null byte
    
            char* username = login;
            char* password = delimeter + 1;
            password[strlen(password) - 1] = '\0'; // remove newline character

            if (strcmp(username, username_.c_str()) == 0 && strcmp(password, password_.c_str()) == 0) {
                std::cout << GREEN << "[TCPServer::server_auth] Client " << client->ip << " authenticated" << RESET << std::endl;
                tcp_send(client->client_socket, "Login successful\n");
                client->authenticated = 1;
                return 1;
            } else{
                tcp_send(client->client_socket, "Login failed\n");
                continue;
            }
    
        } while (!shutdown_flag_);
    }
    catch(const std::exception& e) {
        std::cerr << RED << e.what() << RESET << std::endl;
        return 0;
    }

    return 0;
}

void TCPServer::shell_handler(TCPClient* client) {
    char buffer[MAX_BUFFER_SIZE];
    ssize_t bytes_read;

    client->pty_master = posix_openpt(O_RDWR | O_NOCTTY);
    if (client->pty_master < 0 || grantpt(client->pty_master) < 0 || unlockpt(client->pty_master) < 0) {
        std::cerr << RED << "[TCPServer::shell_handler] Error creating pty: " << strerror(errno) << RESET << std::endl;
        return;
    }
    client->pid = fork();
    if (client->pid < 0) {
        std::cerr << RED << "[TCPServer::shell_handler] Fork failed: " << strerror(errno) << RESET << std::endl;
        close(client->pty_master);
        return;
    }

    if (client->pid == 0) {
        // Child process
        setsid(); // Detach from the parent terminal
        client->pty_slave = open(ptsname(client->pty_master), O_RDWR);
        if (client->pty_slave < 0) {
            std::cerr << RED << "[TCPServer::shell_handler] Error opening pty slave: " << strerror(errno) << RESET << std::endl;
            exit(1);
        }

        close(client->pty_master);

        // Set the pty slave as the controlling terminal
        if (ioctl(client->pty_slave, TIOCSCTTY, 0) < 0) {
            std::cerr << RED << "[TCPServer::shell_handler] Error setting pty as controlling terminal: " << strerror(errno) << RESET << std::endl;
            exit(1);
        }

        // Redirect input and output to the pty slave
        dup2(client->pty_slave, STDIN_FILENO);
        dup2(client->pty_slave, STDOUT_FILENO);
        dup2(client->pty_slave, STDERR_FILENO);
        close(client->pty_slave);

        // Launch a shell
        execl("/bin/bash", "bash", NULL);
        std::cerr << RED << "[TCPServer::shell_handler] Error launching shell: " << strerror(errno) << RESET << std::endl;
        exit(1);
    }

    // Parent process. Handle communication
    
    client->stdin_fd = client->pty_master;
    client->stdout_fd = client->pty_master;
    client->stderr_fd = client->pty_master;
    
    try {
        while (!shutdown_flag_) {
            bytes_read = read(client->stdout_fd, buffer, sizeof(buffer) - 1);
            if (bytes_read < 0) {
                if (errno == EINTR) {
                    // Interrupted by signal, check if shutdown_flag_ is set
                    continue;
                }
                std::cerr << RED << "[TCPServer::shell_handler] Error reading from pty: " << strerror(errno) << RESET << std::endl;
                break;
            }
            else if (bytes_read == 0) {
                std::cout << YELLOW << "[TCPServer::shell_handler] Shell closed" << RESET << std::endl;
                break;
            }
            buffer[bytes_read] = '\0';
            
            // Log the command/output
            std::cout << GREEN << "[TCPServer::shell_handler] Output: " << buffer << RESET << std::endl;
        
            tcp_send(client->client_socket, buffer, bytes_read);
    
            tcp_recv(client->client_socket, buffer, sizeof(buffer) - 1, &bytes_read);
            buffer[bytes_read] = '\0';
            std::cout << GREEN << "[TCPServer::shell_handler] Received command: " << buffer << RESET << std::endl;
            write(client->stdin_fd, buffer, bytes_read);
        }
    }
    catch(const std::exception& e) { // Catch the exception from tcp_recv and tcp_send
        std::cerr << RED << e.what() << RESET << std::endl;
    }

    if (client->pid > 0) {
        kill(client->pid, SIGKILL);
        waitpid(client->pid, NULL, 0);
        close(client->pty_master);
    }
}

void TCPServer::handle_client(TCPClient* client) {
    int rc;
    int bytes_received;

    std::cout << GREEN << "[TCPServer::handle_client] Handling client " << client->ip << RESET << std::endl;
    
    try {
        // Authentication phase
        tcp_send(client->client_socket, "Welcome to the Server\n");
        rc = server_auth(client);
        if (rc <= 0) goto cleanup;

        // Shell phase
        shell_handler(client);
    }
    catch(const std::exception& e) {
        std::cerr << RED << e.what() << RESET << std::endl;
    }   

cleanup:
    std::cout << YELLOW << "[TCPServer::handle_client] Cleaning up the client " << client->ip << RESET << std::endl;
    if (client->pid > 0) {
        kill(client->pid, SIGKILL);
        waitpid(client->pid, NULL, 0);
    }
    cleanup_client(client);

    {
        std::lock_guard<std::mutex> lock(client_mutex_);
        client_count_--;
        client_cv_.notify_one();
    }
    
    delete client;
    return;
}

int TCPServer::tcp_accept() {
    int rc;
    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    bool slot_found = false;

    client_fd = accept(server_fd_, (struct sockaddr*) &client_addr, &client_addr_len);
    
    if (client_fd < 0) {
        std::cerr << RED << "[TCPServer::tcp_accept] Error accepting connection: " << strerror(errno) << RESET << std::endl;
        return 0;
    }

    int flags = fcntl(client_fd, F_GETFL, 0);
    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

    TCPClient* client = nullptr;

    {
        std::lock_guard<std::mutex> lock(client_mutex_);
        for (int i=0; i<max_connections_; i++) {
            if (clients_[i].client_socket == -1){
                client = new TCPClient();
                client->client_socket = client_fd;
                client->addr_len = client_addr_len;
                client->ip = inet_ntoa(client_addr.sin_addr);
                client->index = i;
                clients_[i] = *client;
                slot_found = true;
                std::cout << GREEN << "[TCPServer::tcp_accept] Accepted connection from " << inet_ntoa(client_addr.sin_addr) << RESET << std::endl;
                client_count_++;
                client_cv_.notify_one();
                break;
            }
        }

        if (!slot_found) {
            std::cerr << RED << "[TCPServer::tcp_accept] No available slots for new client" << RESET << std::endl;
            close(client_fd);
            return 0;
        }
    }

    if (client == nullptr) {
        std::cerr << RED << "[TCPServer::tcp_accept] Error allocating memory for client" << RESET << std::endl;
        close(client_fd);
        return 0;
    }
    
    threads_.emplace_back(&TCPServer::handle_client, this, client);
    
    return 1;
}

void TCPServer::cleanup_client(TCPClient* client) {
    if (client->client_socket >= 0) {
        close(client->client_socket);
    }
    if (client->pty_master >= 0) {
        close(client->pty_master);
    }
    if (client->pty_slave >=0) {
        close(client->pty_slave);
    }
    if (client->stdin_fd >= 0) {
        close(client->stdin_fd);
    }
    if (client->stdout_fd >= 0) {
        close(client->stdout_fd);
    }
    if (client->stderr_fd >= 0) {
        close(client->stderr_fd);
    }
    client->pid = -1;
    client->client_socket = -1;
    client->pty_master = -1;
    client->pty_slave = -1;
    client->stdin_fd = -1;
    client->stdout_fd = -1;
    client->stderr_fd = -1;
    client->authenticated = 0;
    client->ip = "";
    client->addr_len = 0;
    client->index = -1; 
}

void TCPServer::start() {
    int rc;
    clients_ = new TCPClient[max_connections_]; 
    for (int i=0; i<max_connections_; i++) {
        cleanup_client(&clients_[i]); 
    }
    while (!shutdown_flag_) {
        std::cout << GREEN << "[TCPServer::start] Waiting for client connection" << RESET << std::endl;

        #ifdef WITH_THREADS
        std::unique_lock<std::mutex> lock(client_mutex_);
        client_cv_.wait(lock, [this] {return client_count_ < max_connections_ || shutdown_flag_; });
        if (shutdown_flag_) {
            break;
        }
        lock.unlock();
        rc = tcp_accept();
        if (rc < 0) continue;
        #else 
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        rc = accept(server_fd_, (struct sockaddr*) &client_addr, &client_addr_len);
        if (rc < 0) {
            std::cerr << RED << "[TCPServer::start] Error accepting connection: " << strerror(errno) << RESET << std::endl;
            continue;
        }
        #endif
    }
}

void TCPServer::stop() {
    shutdown_flag_ = true;
    client_cv_.notify_all();
    #ifdef WITH_THREADS
    for (auto& thread : threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    #endif
}

int TCPServer::cleanup() {
    std::cout << YELLOW << "[TCPServer::stop] Stopping the server" << RESET << std::endl;
    if (server_fd_ > 0) {
        close(server_fd_);
    }
    if (clients_) {
        delete[] clients_;
        clients_ = nullptr;
    }

    return 1;
}

