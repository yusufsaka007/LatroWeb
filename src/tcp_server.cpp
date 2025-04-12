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
    rc = js::get_value(uid_, "uid");
    rc = js::get_value(gid_, "gid");

    shell_prompt_ = BLUE + username_ + "@" + hostname_ + ":~$ " + RESET;

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
    int opt=1;
    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        std::cerr << "[TCPServer::init] Error creating socket" << std::endl;
        return 0;
    }

    rc = setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (rc < 0) {
        std::cerr << RED << "[TCPServer::init] Error setting SO_REUSEADDR: " << strerror(errno) << RESET << std::endl;
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

void TCPServer::tcp_send(int client_socket, struct BufferChain* buffers, size_t& total_bytes) {
    int rc;
    int bytes_send = 0;
    struct BufferChain* current = buffers;
    while (!shutdown_flag_ && bytes_send < total_bytes) {
        rc = send(client_socket, current->bytes, current->len, 0);
        if (rc < 0) {
            throw std::runtime_error(std::string("[TCPServer::tcp_send] Error sending data: ") + strerror(errno));
        }
        else if (rc == 0) {
            throw std::runtime_error(std::string("[TCPServer::tcp_recv] Client disconnected"));
        }
        bytes_send += rc;
        current = current->next;
        total_bytes -= rc;
    }

    if (total_bytes > 0) {
        std::cerr << RED << "[TCPServer::tcp_send] Not all data was sent, remaining bytes: " << total_bytes << RESET << std::endl;
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

size_t TCPServer::get_total_bytes(struct BufferChain* buffers) {
    struct BufferChain* current = buffers;
    size_t count = 0;

    while (current) {
        count += current->len;
        current = current->next;
    }

    return count;
}

void TCPServer::free_buffer_chain(struct BufferChain* buffers) {
    struct BufferChain* current;
    struct BufferChain* next;
    current = buffers;

    while (current != nullptr) {
        next = current->next;
        delete current;
        current = next;
    }
}

// *ToDo* make this function non blocking
struct BufferChain* TCPServer::read_pipe(int fd) {
    struct BufferChain* buffers;
    struct BufferChain* current;
    struct BufferChain* next;

    ssize_t count;
    ssize_t n, space;
    char* p;

    buffers = new BufferChain();
    if (!buffers) {
        std::cerr << RED << "[TCPServer::read_pipe] Buffer allocation error" << RESET << std::endl;
        return nullptr;
    }
    memset(buffers, 0, sizeof(struct BufferChain));
    current = buffers;
    count = 0;
    space = MAX_BUFFER_SIZE;
    p = current->bytes;
    while ((n = read(fd, p, space)) > 0 && !shutdown_flag_) {
        p += n; count += n; space -= n;
        if (space == 0) {
            // New allocation is required
            next = new BufferChain();
            if (!next) {
                std::cerr << RED << "[TCPServer::read_pipe] Buffer allocation error" << RESET << std::endl;
                return nullptr;
            }
            memset(next, 0, sizeof(struct BufferChain));
            current->len = count;
            current->next = next;
            current = next;
            count = 0;
            space = MAX_BUFFER_SIZE;
            p = current->bytes;
        }
    }
    current->len = count;
    if (n < 0) {
        std::cerr << RED << "[TCPServer::read_pipe] Error reading from pipe: " << strerror(errno) << RESET << std::endl;
        free_buffer_chain(buffers);
        return nullptr;
    }
    return buffers;
}

int TCPServer::exec_request(TCPClient* client) {
    int* stdin_pipe = client->stdin_pipe;
    int* stdout_pipe = client->stdout_pipe;
    int* stderr_pipe = client->stderr_pipe;
    int dir_update_pipe[2];

    struct BufferChain* out_buffer = nullptr;
    struct BufferChain* err_buffer = nullptr;
    struct BufferChain* current = nullptr;

    int rc;
    int exec_result;

    rc = pipe(stdin_pipe);
    if (rc < 0) {
        std::cerr << RED << "[TCPServer::exec_request] Error creating stdin pipe: " << strerror(errno) << RESET << std::endl;
        goto fail_pipe_stdin;
    }
    rc = pipe(stdout_pipe);
    if (rc < 0) {
        std::cerr << RED << "[TCPServer::exec_request] Error creating stdout pipe: " << strerror(errno) << RESET << std::endl;
        goto fail_pipe_stdout;
    }
    rc = pipe(stderr_pipe);
    if (rc < 0) {
        std::cerr << RED << "[TCPServer::exec_request] Error creating stderr pipe: " << strerror(errno) << RESET << std::endl;
        goto fail_pipe_stderr;
    }

    rc = pipe(dir_update_pipe);
    if (rc < 0) {
        std::cerr << RED << "[TCPServer::exec_request] Error creating dir update pipe: " << strerror(errno) << RESET << std::endl;
        goto fail_pipe_dir_update;
    }

    client->pid = fork();
    if (client->pid < 0) {
        std::cerr << RED << "[TCPServer::exec_request] Fork failed: " << strerror(errno) << RESET << std::endl;
        goto cleanup;
    }
    if (client->pid == 0) {
        // Child process
        client->logger = nullptr; // Prevent access
        close(client->client_socket); // Unused duplicate of socket fd
        close(stdin_pipe[PIPE_WRITE]);
        close(stdout_pipe[PIPE_READ]);
        close(stderr_pipe[PIPE_READ]);
        close(dir_update_pipe[PIPE_READ]);

        auto clean_exit = [&](int code) {
            close(dir_update_pipe[PIPE_WRITE]);
            if (stdin_pipe[PIPE_READ] != -1) {
                close(stdin_pipe[PIPE_READ]);
            }
            if (stdout_pipe[PIPE_WRITE] != -1) {
                close(stdout_pipe[PIPE_WRITE]);
            }
            if (stderr_pipe[PIPE_WRITE] != -1) {
                close(stderr_pipe[PIPE_WRITE]);
            }
            _exit(code);
        };
        
        // Where the virtualization happens and permissions are set
        if (chroot(VIRTUAL_HONEYPOT_DIR) != 0) clean_exit(EXIT_FAILURE);
        if (chdir(client->current_dir.c_str()) != 0) clean_exit(EXIT_FAILURE);
        if (setgid(gid_) != 0) clean_exit(EXIT_FAILURE);
        if (setuid(uid_) != 0) clean_exit(EXIT_FAILURE);

        if (dup2(stdin_pipe[PIPE_READ], STDIN_FILENO) < 0) clean_exit(EXIT_FAILURE);
        if (dup2(stdout_pipe[PIPE_WRITE], STDOUT_FILENO) < 0) clean_exit(EXIT_FAILURE);
        if (dup2(stderr_pipe[PIPE_WRITE], STDERR_FILENO) < 0) clean_exit(EXIT_FAILURE);

        close(stdin_pipe[PIPE_READ]);
        close(stdout_pipe[PIPE_WRITE]);
        close(stderr_pipe[PIPE_WRITE]);

        if (client->command_request_len > MAX_BUFFER_SIZE) {
            std::cerr << "Command limit passed" << std::endl;
            clean_exit(EXIT_FAILURE);
        }

        if (strncmp(client->command_request, "cd", 2) == 0) {
            if (client->command_request[2] == '\0' || strncmp(client->command_request, "cd ~", 4) == 0) {
                chdir("/");
                char cwd[PATH_MAX];
                if (getcwd(cwd, sizeof(cwd)) != nullptr) {
                    write(dir_update_pipe[PIPE_WRITE], cwd, strlen(cwd));
                }
                clean_exit(EXIT_SUCCESS);
            } else if (client->command_request[2] == ' ' && client->command_request[3] != '\0') {
                char target_dir[PATH_MAX];
                strncpy(target_dir, client->command_request + 3, client->command_request_len - 3);
                if (chdir(target_dir) != 0) {
                    std::cerr << strerror(errno) << std::endl;
                    clean_exit(EXIT_FAILURE);
                }

                char cwd[PATH_MAX];
                if (getcwd(cwd, sizeof(cwd)) != nullptr) {
                    write(dir_update_pipe[PIPE_WRITE], cwd, strlen(cwd));
                }
                
                clean_exit(EXIT_SUCCESS);
                
            } else {
                std::cerr << "Invalid cd command" << std::endl;
                clean_exit(EXIT_FAILURE);
            }
        }

        // Command is something else. Sanitize and prepare the command        
        close(dir_update_pipe[PIPE_WRITE]);
        const char* args[] = {SHELL_BIN, SHELL_ARG, client->command_request, nullptr};
        exec_result = execve(SHELL_BIN, const_cast<char* const*>(args), nullptr);

        // If we reach here, execve failed
        _exit(EXIT_FAILURE);
    } else {
        // Parent process
        close(stdin_pipe[PIPE_READ]);
        close(stdout_pipe[PIPE_WRITE]);
        close(stderr_pipe[PIPE_WRITE]);
        close(dir_update_pipe[PIPE_WRITE]);

        char updated_dir[PATH_MAX + 1];
        ssize_t n = read(dir_update_pipe[PIPE_READ], updated_dir, PATH_MAX);
        if (n > 0) {
            updated_dir[n] = '\0';
            client->current_dir = updated_dir;
            std::cout << BLUE << "[TCPServer::exec_request] Changed directory to " << client->current_dir << RESET << std::endl;
        } else if (n < 0) {
            std::cerr << RED << "[TCPServer::exec_request] Error reading from dir update pipe: " << strerror(errno) << RESET << std::endl;
        }
        close(dir_update_pipe[PIPE_READ]);

        // Write the command to the stdin pipe
        if (strncmp(client->command_request, "cd", 2) != 0) {
            write(stdin_pipe[PIPE_WRITE], client->command_request, client->command_request_len);
        }
        
        // Read output
        out_buffer = read_pipe(stdout_pipe[PIPE_READ]);

        // Read error
        err_buffer = read_pipe(stderr_pipe[PIPE_READ]);
    
        // Send output to the attacker
        if (out_buffer) {
            size_t total_bytes_out = get_total_bytes(out_buffer);            
            tcp_send(client->client_socket, out_buffer, total_bytes_out);
            free_buffer_chain(out_buffer);
        }

        // Send error to the attacker
        if (err_buffer) {
            size_t total_bytes_err = get_total_bytes(err_buffer);
            tcp_send(client->client_socket, err_buffer, total_bytes_err);
            free_buffer_chain(err_buffer);
        }

        int status;
        pid_t result = waitpid(client->pid, &status, 0);
        if (result < 0) {
            std::cerr << RED << "[TCPServer::exec_request] Error waiting for child process: " << strerror(errno) << RESET << std::endl;
        } else if (WIFEXITED(status)) {
            std::cout << GREEN << "[TCPServer::exec_request] Child process exited with status " << WEXITSTATUS(status) << RESET << std::endl;
        } else if (WIFSIGNALED(status)) {
            std::cout << RED << "[TCPServer::exec_request] Child process killed by signal " << WTERMSIG(status) << RESET << std::endl;
        }
    }

cleanup:
    close(dir_update_pipe[PIPE_READ]);
    close(dir_update_pipe[PIPE_WRITE]);
    fail_pipe_dir_update:    
    close(stderr_pipe[PIPE_READ]);
    close(stderr_pipe[PIPE_WRITE]);
fail_pipe_stderr:
    close(stdout_pipe[PIPE_READ]);
    close(stdout_pipe[PIPE_WRITE]);
fail_pipe_stdout:
    close(stdin_pipe[PIPE_READ]);
    close(stdin_pipe[PIPE_WRITE]);
fail_pipe_stdin:
    return 0;
}

void TCPServer::handle_shell(TCPClient* client) {
    ssize_t bytes_read;
    int rc;
    char* buffer = client->command_request;
    
    client->current_dir = "/home/" + username_; // Will be changed later on

    try{
        while (!shutdown_flag_) {
            tcp_send(client->client_socket, shell_prompt_.c_str(), shell_prompt_.size());
            tcp_recv(client->client_socket, buffer, MAX_BUFFER_SIZE, &bytes_read);
            if (bytes_read > 0) {
                buffer[bytes_read] = '\0';
                trim_newline(buffer, bytes_read);
                std::cout << BLUE << "[TCPServer::handle_shell] Command from client " << client->ip << ": " << buffer << RESET << std::endl;
                client->command_request_len = bytes_read;                
                client->logger->log_command(buffer);

                // Execute the command
                exec_request(client);

                if (strncmp(buffer, "exit", 4) == 0) {
                    std::cout << GREEN << "[TCPServer::handle_shell] Client " << client->ip << " exited" << RESET << std::endl;
                    break;
                }
            }
        }
    }
    catch(const std::exception& e) { // Catch the exception from tcp_recv and tcp_send
        std::cerr << RED << e.what() << RESET << std::endl;
    }

    if (client->pid > 0) {
        int status;
        pid_t result = waitpid(client->pid, &status, 0);
        if (result == 0) {
            // Child is still running, send SIGKILL
            kill(client->pid, SIGKILL);
            waitpid(client->pid, NULL, 0);
        } else if (result > 0) {
            // Child has already terminated, no need to send SIGKILL
            std::cout << GREEN << "[TCPServer::handle_shell] Child process terminated normally" << RESET << std::endl;
        } else {
            std::cerr << RED << "[TCPServer::handle_shell] Error waiting for child process: " << strerror(errno) << RESET << std::endl;
        }
    }
}

void TCPServer::trim_newline(char* str, ssize_t& len) {
    while (len>0 && (str[len-1] == '\n' || str[len-1] == '\r')) {
        str[--len] = '\0';
    }
}

void TCPServer::handle_client(TCPClient* client) {
    int rc;
    int bytes_received;

    client->event_log << GREEN << "[TCPServer::handle_client] Handling client " << client->ip << RESET << std::endl;
    log_client(client);

    try {
        // Authentication phase
        tcp_send(client->client_socket, "Welcome to the Server\n");
        rc = server_auth(client);
        if (rc <= 0) goto cleanup;

        // Shell phase
        handle_shell(client);
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
                client->logger = new Logger(client->ip.c_str());
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

    for (int i=0; i<max_connections_; i++) {
        cleanup_client(&clients_[i]);
    }

    if (clients_) {
        delete[] clients_;
        clients_ = nullptr;
    }

    return 1;
}