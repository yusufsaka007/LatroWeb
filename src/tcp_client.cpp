#include "tcp_client.hpp"

extern std::mutex console_mutex;
extern std::condition_variable console_cv;
extern std::queue<std::string> log_queue;

void log_client(TCPClient* client) {
    {
        std::lock_guard<std::mutex> lock(console_mutex);
        log_queue.push(client->event_log.str());
        client->event_log.str("");
    }

    console_cv.notify_one();
}

void cleanup_client(TCPClient* client) {
    if (client->client_socket >= 0) {
        close(client->client_socket);
    }
    if (client->pty_master >= 0) {
        close(client->pty_master);
    }
    if (client->pty_slave >=0) {
        close(client->pty_slave);
    }
    
    int* pipe = client->stdin_pipe;
    for (int i=0; i<3; i++) {
        for (int j=0; j<2; j++) {
            if (pipe[j] >= 0) {
                close(pipe[j]);
            }
            pipe[j] = -1;
        }
        pipe += 2;
    }

    client->pid = -1;
    client->client_socket = -1;
    client->pty_master = -1;
    client->pty_slave = -1;
    client->stdin_pipe[PIPE_READ] = client->stdin_pipe[PIPE_WRITE] = -1; 
    client->stdout_pipe[PIPE_READ] = client->stdout_pipe[PIPE_WRITE] = -1;
    client->stderr_pipe[PIPE_READ] = client->stderr_pipe[PIPE_WRITE] = -1;
    client->authenticated = 0;
    client->ip = "";
    client->addr_len = 0;
    client->index = -1; 
    client->current_dir = "";
    client->command_request_len = 0;
    client->command_request[0] = '\0';
    client->event_log.clear();
    if (client->logger) delete client->logger; client->logger = nullptr;
}