// main.cpp

#include "ssh_server.h"

int main(int argc, char** argv) {
    std::unique_ptr<SSHServer> server;

    if (argc == 1) {
        server = std::make_unique<SSHServer>();
    }
    else if (argc == 5) {
        server = std::make_unique<SSHServer>(argv[1], atoi(argv[2]), argv[3], argv[4]);
    }
    else {
        std::cout << RED << "Usage: " << argv[0] << " [ip port username password]" << RESET << std::endl;
        return 1;
    }

    server->register_signal_handler();
    server->set_options();
    server->start();

    return 0;
}