// main.cpp
// Executable will be automatically built and run by start_honeypot.py

#include "tcp_server.hpp"

std::unique_ptr<TCPServer> server;

static void sigterm_handler(int signum) {
    if (server) {
        server->stop();
    }
}

bool runProgram = true;

static void temp_sigterm_handler(int signum) {
    std::cerr << YELLOW << "[main] Received signal " << signum << ", stopping server" << RESET << std::endl;
    runProgram = false;
}

int main(int argc, char* argv[]) {   
    signal(SIGPIPE, SIG_IGN);

    std::ifstream file = js::get_file();
    if(!file.is_open()) {
        std::cerr << RED << "[main] File not found or bad file: " << JSON_FILE << RESET << std::endl;
        std::cerr << RED << "[main] Please use start_honeypot.py --help to see available options" << RESET << std::endl;
        return 0;
    }
    file.close();

    int rc = 0;
    struct sigaction sa;
    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (argc == 5) {
        server = std::make_unique<TCPServer>(atoi(argv[1]), argv[2], argv[3], argv[4], atoi(argv[5]));
    } else if (argc == 1) {
        server = std::make_unique<TCPServer>();
    } else {
        std::cerr << YELLOW << "Usage: " << argv[0] << " <port> <ip> <username> <password> <max_connections>" << RESET << std::endl;
        return 0;
    }

    rc = server->init();
    if (rc == 0) {
        std::cerr << RED << "[main] Error initializing server" << RESET << std::endl;
        return 0;
    }
    std::cout << GREEN << "[main] Server initialized" << RESET << std::endl;
    server->start();

    
    return 0;
}
