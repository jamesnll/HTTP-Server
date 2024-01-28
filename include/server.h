#ifndef HTTP_SERVER_SERVER_H
#define HTTP_SERVER_SERVER_H
#include <inttypes.h>
// Data Types and Limits
#include <netinet/in.h>
#include <stdint.h>

struct arguments
{
    char     *ip_address;
    char     *port_str;
    char     *directory;
    in_port_t port;
};

struct http_request_arguments
{
    char *type;
    char *endpoint;
    char *http_version;
};

struct client_info
{
    int                     sockfd;
    struct sockaddr_storage addr;
    socklen_t               addr_len;
};

enum status_codes
{
    OK        = 200,
    NOT_FOUND = 404
};

void run_server(const struct arguments *args);

#endif    // HTTP_SERVER_SERVER_H
