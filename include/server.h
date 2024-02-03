#ifndef HTTP_SERVER_SERVER_H
#define HTTP_SERVER_SERVER_H
#include <inttypes.h>
// Data Types and Limits
#include <netinet/in.h>
#include <stdint.h>

#define LINE_LENGTH_SHORT 128

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
    int   content_length;
};

struct client_info
{
    int                     sockfd;
    struct sockaddr_storage addr;
    socklen_t               addr_len;
};

struct server_info
{
    int                     sockfd;
    struct sockaddr_storage addr;
};

struct kv_pair
{
    char key[LINE_LENGTH_SHORT];
    char value[LINE_LENGTH_SHORT];
};

enum status_codes
{
    OK        = 200,
    NOT_FOUND = 404
};

void run_server(const struct arguments *args);

#endif    // HTTP_SERVER_SERVER_H
