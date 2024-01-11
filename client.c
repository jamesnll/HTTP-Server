#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define BUFFER_SIZE 1024
#define BASE_TEN 10

#ifndef SOCK_CLOEXEC
    #define SOCK_CLOEXEC 0
#endif

// Function declarations
void read_server_response(int sock);
static void parse_arguments(int argc, char *argv[], char **ip_address, char **port, char **http_method, char **url_path, char **data);
static in_port_t parse_in_port_t(const char *port_str);
static void convert_address(const char *address, struct sockaddr_storage *addr);
static int socket_create(int domain);
static void socket_connect(int sockfd, struct sockaddr_storage *addr, in_port_t port);
static void socket_close(int sockfd);
void create_get_head_request(char *request, const char *method, const char *url);
void create_post_request(char *request, const char *url, const char *data);


// Main function
int main(int argc, char *argv[])
{
    char                   *ip;
    char                   *port_str;
    char                   *command;
    in_port_t               port;
    int                     sockfd;
    struct sockaddr_storage addr;
    char *http_method;
    char *request_data;
    char request[BUFFER_SIZE]; // To hold the constructed HTTP request

    parse_arguments(argc, argv, &ip, &port_str, &http_method, &request_data);
    port = parse_in_port_t(port_str);
    convert_address(ip, &addr);
    sockfd = socket_create(addr.ss_family);
    socket_connect(sockfd, &addr, port);

    if(strcmp(http_method, "GET") == 0 || strcmp(http_method, "HEAD") == 0) {
        create_get_head_request(request, http_method, request_data);
    } else if(strcmp(http_method, "POST") == 0) {
        create_post_request(request, request_data, argv[5]); // argv[5] for POST data
    } else {
        fprintf(stderr, "Invalid HTTP method.\n");
        exit(EXIT_FAILURE);
    }

    write(sockfd, request, strlen(request));
    read_server_response(sockfd);
    socket_close(sockfd);
    return 0;
}

// Read the server's response
void read_server_response(int sock)
{
    char    buffer[BUFFER_SIZE];
    ssize_t read_size;

    while((read_size = read(sock, buffer, BUFFER_SIZE - 1)) > 0)
    {
        buffer[read_size] = '\0';
        printf("%s", buffer);
    }

    if(read_size < 0)
    {
        perror("read");
    }
}

// Parses/handle HTTP method and request data
static void parse_arguments(int argc, char *argv[], char **ip_address, char **port, char **http_method, char **url_path, char **data) {
    // Check if the number of args is not within the expected range (5 or 6)
    if (argc < 5 || argc > 6) {
        // Prints usage info and exit if the arg count is incorrect
        fprintf(stderr, "Usage: %s <ip address> <port> <http method> <url path> [data]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    *ip_address  = argv[1]; // IP address
    *port        = argv[2]; // Port number
    *http_method = argv[3]; // HTTP method (GET, POST, HEAD)
    *url_path    = argv[4]; // URL path for HTTP request
    *data        = argc == 6 ? argv[5] : NULL; // Optional data for POST request; NULL if not provided
}

// HTTP Request Functions
// Function to create a GET or HEAD request
void create_get_head_request(char *request, const char *method, const char *url) {
    // Format the request string into the "request" buffer
    snprintf(request, BUFFER_SIZE, "%s %s HTTP/1.0\r\n\r\n", method, url);
    // %s for method (GET/HEAD), %s for URL, followed by HTTP/1.0 standard and \r\n\r\n
}

// Function to construct a POST request
void create_post_request(char *request, const char *url, const char *data) {
    // Check if data is provided for the POST request
    if (data != NULL) {
        // If data is provided, format the POST request with content length header and the data
        snprintf(request, BUFFER_SIZE, "POST %s HTTP/1.0\r\nContent-Length: %ld\r\n\r\n%s", url, strlen(data), data);
        // %s for URL, %ld for the length of the data, %s for the actual data
    } else {
        // If no data is provided, set content length to 0
        snprintf(request, BUFFER_SIZE, "POST %s HTTP/1.0\r\nContent-Length: 0\r\n\r\n", url);
        // POST request with content length header set to 0 (basically no data)
    }
}

// Parses string to get the port number, checking for errors and range
static in_port_t parse_in_port_t(const char *str)
{
    char         *endptr;
    unsigned long parsed_value;

    errno        = 0;
    parsed_value = strtoul(str, &endptr, BASE_TEN);

    if(errno != 0 || *endptr != '\0' || parsed_value > UINT16_MAX)
    {
        fprintf(stderr, "Invalid port number.\n");
        exit(EXIT_FAILURE);
    }

    return (in_port_t)parsed_value;
}

// Helps convert IP address string to network address structure
static void convert_address(const char *address, struct sockaddr_storage *addr)
{
    memset(addr, 0, sizeof(*addr));

    if(inet_pton(AF_INET, address, &(((struct sockaddr_in *)addr)->sin_addr)) == 1)
    {
        addr->ss_family = AF_INET;
    }
    else if(inet_pton(AF_INET6, address, &(((struct sockaddr_in6 *)addr)->sin6_addr)) == 1)
    {
        addr->ss_family = AF_INET6;
    }
    else
    {
        fprintf(stderr, "%s is not a valid IPv4 or IPv6 address\n", address);
        exit(EXIT_FAILURE);
    }
}

// Creates a socket with given domain
static int socket_create(int domain)
{
    int sockfd = socket(domain, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if(sockfd == -1)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

// Helps connects the client socket to the server's IP address and port
static void socket_connect(int sockfd, struct sockaddr_storage *addr, in_port_t port)
{
    char      addr_str[INET6_ADDRSTRLEN];
    in_port_t net_port;
    socklen_t addr_len;

    if(inet_ntop(addr->ss_family, addr->ss_family == AF_INET ? (void *)&(((struct sockaddr_in *)addr)->sin_addr) : (void *)&(((struct sockaddr_in6 *)addr)->sin6_addr), addr_str, sizeof(addr_str)) == NULL)
    {
        perror("inet_ntop\n");
        exit(EXIT_FAILURE);
    }

    printf("Connecting to: %s:%u\n", addr_str, port);
    net_port = htons(port);

    if(addr->ss_family == AF_INET)
    {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr           = (struct sockaddr_in *)addr;
        ipv4_addr->sin_port = net_port;
        addr_len            = sizeof(struct sockaddr_in);
    }
    else if(addr->ss_family == AF_INET6)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr            = (struct sockaddr_in6 *)addr;
        ipv6_addr->sin6_port = net_port;
        addr_len             = sizeof(struct sockaddr_in6);
    }
    else
    {
        fprintf(stderr, "Invalid address family: %d\n", addr->ss_family);
        exit(EXIT_FAILURE);
    }

    if(connect(sockfd, (struct sockaddr *)addr, addr_len) == -1)
    {
        char *msg;

        msg = strerror(errno);
        fprintf(stderr, "Error: connect (%d): %s\n", errno, msg);
        exit(EXIT_FAILURE);
    }

    printf("Connected to: %s:%u\n", addr_str, port);
}

// Closes the client socket
static void socket_close(int sockfd)
{
    if(close(sockfd) == -1)
    {
        perror("Error closing socket");
        exit(EXIT_FAILURE);
    }
}


