#include "callbacks.h"

namespace cb {
    int auth_password(ssh_session session, const char* user, const char* password, void* userdata) {
        struct session_data_struct* sdata = static_cast<struct session_data_struct*>(userdata);

        if (strcmp(user, sdata->username->c_str()) == 0 && strcmp(password, sdata->password->c_str()) == 0) {
            std::cout << GREEN << "[auth_password]: Login successful" << RESET << std::endl;
            sdata->authenticated = 1;
            return SSH_AUTH_SUCCESS;
        }
        std::cout << RED << "[auth_password]: Failed login attempt: " << user << ":" << password << RESET << std::endl;
        sdata->auth_attempts++;
        return SSH_AUTH_DENIED;
    }
    ssh_channel channel_open(ssh_session session, void* userdata) {
        struct session_data_struct* sdata = static_cast<struct session_data_struct*>(userdata);

        std::cout << GREEN << "[channel_open]: Channel request has been made" << RESET << std::endl;
        sdata->channel = ssh_channel_new(session);
        return sdata->channel;
    }
    int pty_request(ssh_session session, ssh_channel channel, const char *term, int cols, int rows, int py, int px, void *userdata) {
        return 0;
    }
    int pty_resize(ssh_session session, ssh_channel channel, int cols, int rows, int py, int px, void *userdata) {
        return 0;
    }
    int shell_request(ssh_session session, ssh_channel channel, void *userdata) {
        return 0;
    }
    int exec_request(ssh_session session, ssh_channel channel,const char *command, void *userdata) {
        return 0;
    }
    int data_function(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata) {
        return 0;
    }
}