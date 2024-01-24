// Error Handling
#include <errno.h>

// Network Programming
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/wait.h>

// Signal Handling
#include <signal.h>

// Standard Library
#include "../include/server.h"
#include <fcntl.h>
#include <ftw.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Macros
#define LINE_LENGTH_LONG 1024
#define LINE_LENGTH_SHORT 128

// ----- Function Headers -----

// Network Handling
static void convert_address(const char *address, struct sockaddr_storage *addr);
static int  socket_create(int domain, int type, int protocol);
static void socket_bind(int sockfd, struct sockaddr_storage *addr, in_port_t port);
static void start_listening(int server_fd, int backlog);
static int  socket_accept_connection(int server_fd, struct sockaddr_storage *client_addr, socklen_t *client_addr_len);
static void socket_close(int sockfd);

// HTTP Request Functions
static int read_from_socket(int client_sockfd, struct sockaddr_storage *client_addr, char *buffer);
static int parse_request(char *request, struct http_request_arguments *request_args);
static int find_request_endpoint(const char *server_directory, char *request_endpoint);
static int search_for_file(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf);

// HTTP Response Functions
// static void build_response_header(char *header);
static void build_response_header(char *header, int status_code);                                                                // New testing for TODO1.0
static void send_response(int client_sockfd, const char *header, const char *body);                                              // This function still sends responses for head + post
static int  new_send_response(int client_sockfd, const char *header, const char *server_directory, const char *request_file);    // New function to send the response
static void send_head_response(int client_sockfd, const char *server_directory, const char *request_endpoint);                   // For TODO1.1 should be dynamically build the HTTP headers if 200, or 404

// Signal Handling Functions
static void setup_signal_handler(void);
static void sigint_handler(int signum);

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t exit_flag = 0;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static char *target_file;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static int target_file_found = 0;    // 0 = not found, 1 = found

void run_server(const struct arguments *args)
{
    int                     enable;
    int                     sockfd;
    struct sockaddr_storage addr;

    // Set up server
    convert_address(args->ip_address, &addr);
    sockfd = socket_create(addr.ss_family, SOCK_STREAM, 0);

    enable = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) == -1)
    {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }

    socket_bind(sockfd, &addr, args->port);
    start_listening(sockfd, SOMAXCONN);
    setup_signal_handler();

    // Handle incoming client connections
    while(!exit_flag)
    {
        // Client socket variables
        int                           client_sockfd;
        struct sockaddr_storage       client_addr;
        socklen_t                     client_addr_len;
        char                          request_buffer[LINE_LENGTH_LONG] = "";
        struct http_request_arguments request_args                     = {0};

        // TODO: 2. modify the code below so that multiplexing (select/poll) accepts clients

        client_addr_len = sizeof(client_addr);
        client_sockfd   = socket_accept_connection(sockfd, &client_addr, &client_addr_len);

        if(client_sockfd == -1)
        {
            if(exit_flag)
            {
                break;
            }

            continue;
        }

        if(read_from_socket(client_sockfd, &client_addr, request_buffer) == -1)
        {
            socket_close(client_sockfd);
            socket_close(sockfd);
            exit(EXIT_FAILURE);
        }

        parse_request(request_buffer, &request_args);

        if(find_request_endpoint(args->directory, request_args.endpoint) == -1)
        {
            socket_close(client_sockfd);
            socket_close(sockfd);
            exit(EXIT_FAILURE);
        }

        // TODO: 3. set up NDBM for post requests

        // Check request type and generate response
        if(strcmp(request_args.type, "GET") == 0)
        {
            // Handle the GET request
            //            char header[LINE_LENGTH_SHORT] = "";    // Create an empty header to be built from the function below
            //            build_response_header(header);
            //            new_send_response(client_sockfd, header, args->directory, request_args.endpoint);    // Send the response back to the client
            // 404 doesn't work just yet, it's late and im tired when i'm writing this lol
            // when sending 404 it looks for request_args.endpoint, but that doesn't exist so it just returns
            // TODO: 1.0 Update functions above to handle 404 responses correctly

            // This is the updated 1.0 for GET request
            char header[LINE_LENGTH_SHORT] = "";
            int  status_code               = (target_file_found == 1) ? OK : NOT_FOUND;    // Set the status code based on whether the file was found
            build_response_header(header, status_code);                                    // Now call build_response_header with the status code
            new_send_response(client_sockfd, header, args->directory, request_args.endpoint);
        }
        else if(strcmp(request_args.type, "HEAD") == 0)
        {
            // TODO: 1.1 dynamically create and send head response (COMPLETED)
            // Handle HEAD request
            //            const char *header = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n";    // Set the response header (HEAD requests do not have a body)
            //            send_response(client_sockfd, header, "");                                     // Send the response back to the client
            send_head_response(client_sockfd, args->directory, request_args.endpoint);
        }
        else if(strcmp(request_args.type, "POST") == 0)
        {
            // Handle POST request
            // Processing the data sent in the request and possibly store it using NDBM
            const char *header = "HTTP/1.0 200 OK\r\n\r\n";                             // Set the response header for a successful request
            const char *body   = "<html><body><h1>POST Response</h1></body></html>";    // Set a HTML body as the response content
            send_response(client_sockfd, header, body);                                 // Send the response back to the client
        }
        else
        {
            // Handle unknown request type
            const char *header = "HTTP/1.0 400 Bad Request";                              // Set the response header for a bad request
            const char *body   = "<html><body><h1>400 Bad Request</h1></body></html>";    // Set an HTML body which indicates the request was bad
            send_response(client_sockfd, header, body);                                   // Send the response back to the client
        }

        // TODO1 Section^^^

        // Before closing client socket, cleanup child process resources
        socket_close(client_sockfd);
        printf("End of client\n");
    }
    socket_close(sockfd);    // Close server
}

// ----- Function Definitions -----

// Network Handling Functions

/**
 * Converts the address from a human-readable string into a binary
 * representation.
 * @param address string IP address in human-readable format (e.g.,
 * "192.168.0.1")
 * @param addr    pointer to the struct sockaddr_storage where the binary
 * representation will be stored
 */
static void convert_address(const char *address, struct sockaddr_storage *addr)
{
    memset(addr, 0, sizeof(*addr));

    // Converts the str address to binary address and checks for IPv4 or IPv6
    if(inet_pton(AF_INET, address, &(((struct sockaddr_in *)addr)->sin_addr)) == 1)
    {
        // IPv4 address
        addr->ss_family = AF_INET;
        printf("IPv4 found\n");
    }
    else if(inet_pton(AF_INET6, address, &(((struct sockaddr_in6 *)addr)->sin6_addr)) == 1)
    {
        // IPv6 address
        addr->ss_family = AF_INET6;
    }
    else
    {
        fprintf(stderr, "%s is not an IPv4 or IPv6 address\n", address);
        exit(EXIT_FAILURE);
    }
}

/**
 * Creates a socket with the specified domain, type, and protocol.
 * @param domain   the communication domain, e.g., AF_INET for IPv4 or AF_INET6
 * for IPv6
 * @param type     the socket type, e.g., SOCK_STREAM for a TCP socket or
 * SOCK_DGRAM for a UDP socket
 * @param protocol the specific protocol to be used, often set to 0 for the
 * default protocol
 * @return         the file descriptor for the created socket, or -1 on error
 */
static int socket_create(int domain, int type, int protocol)
{
    int sockfd;

    sockfd = socket(domain, type, protocol);

    if(sockfd == -1)
    {
        fprintf(stderr, "Socket creation failed\n");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

/**
 * Binds a socket to the specified address and port.
 * @param sockfd    the socket file descriptor
 * @param addr      a pointer to the struct sockaddr_storage containing the
 * address
 * @param port      the port number to bind the socket
 */
static void socket_bind(int sockfd, struct sockaddr_storage *addr, in_port_t port)
{
    char addr_str[INET6_ADDRSTRLEN];    // Array to store human-readable IP address
                                        // for either IPv4 or IPv6
    socklen_t addr_len;                 // Variable to store the length of the addr struct
    void     *vaddr;                    // Pointer to actual (binary) IP address within addr struct
    in_port_t net_port;                 // Stores network byte order representation of port number

    // Convert port number to network byte order (big endian)
    net_port = htons(port);

    // Handle IPv4
    if(addr->ss_family == AF_INET)
    {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr           = (struct sockaddr_in *)addr;
        addr_len            = sizeof(*ipv4_addr);
        ipv4_addr->sin_port = net_port;
        vaddr               = (void *)&(((struct sockaddr_in *)addr)->sin_addr);
    }
    // Handle IPv6
    else if(addr->ss_family == AF_INET6)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr            = (struct sockaddr_in6 *)addr;
        addr_len             = sizeof(*ipv6_addr);
        ipv6_addr->sin6_port = net_port;
        vaddr                = (void *)&(((struct sockaddr_in6 *)addr)->sin6_addr);
    }
    else
    {
        fprintf(stderr,
                "Internal error: addr->ss_family must be AF_INET or AF_INET6, was: "
                "%d\n",
                addr->ss_family);
        exit(EXIT_FAILURE);
    }

    // Converts binary IP address to a human-readable string and stores it in
    // addr_str
    if(inet_ntop(addr->ss_family, vaddr, addr_str, sizeof(addr_str)) == NULL)
    {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }

    printf("Binding to %s:%u\n", addr_str, port);

    // Bind socket to port
    if(bind(sockfd, (struct sockaddr *)addr, addr_len) == -1)
    {
        perror("Binding failed");
        fprintf(stderr, "Error code: %d\n", errno);
        exit(EXIT_FAILURE);
    }

    printf("Bound to socket: %s:%u\n", addr_str, port);
}

/**
 * Starts listening on a server socket for incoming connections with a specified
 * backlog.
 * @param server_fd the file descriptor of the server socket to start listening
 * on
 * @param backlog   the maximum number of pending connections that can be queued
 * up
 */
static void start_listening(int server_fd, int backlog)
{
    if(listen(server_fd, backlog) == -1)
    {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Listening for incoming connections...\n");
}

/**
 * Accepts an incoming connection on the server socket.
 * @param server_fd         the file descriptor of the server socket
 * @param client_addr       a pointer to a struct sockaddr_storage for storing
 * client address information
 * @param client_addr_len   a pointer to the length of the client address
 * structure
 * @return                 the file descriptor for the accepted connection, or
 * -1 on error
 */
static int socket_accept_connection(int server_fd, struct sockaddr_storage *client_addr, socklen_t *client_addr_len)
{
    int  client_fd;
    char client_host[NI_MAXHOST];       // Array to store the hostname of the client
    char client_service[NI_MAXSERV];    // Array to store the port information of the client
    errno     = 0;
    client_fd = accept(server_fd, (struct sockaddr *)client_addr, client_addr_len);

    if(client_fd == -1)
    {
        if(errno != EINTR)
        {
            perror("accept failed");
        }

        return -1;
    }

    // Attempts to successfully convert the address information
    if(getnameinfo((struct sockaddr *)client_addr, *client_addr_len, client_host, NI_MAXHOST, client_service, NI_MAXSERV, 0) == 0)
    {
        printf("Accepted a new connection from %s:%s\n", client_host, client_service);
    }
    else
    {
        printf("Unable to get client information\n");
    }

    return client_fd;
}

/**
 * Closes a socket with the specified file descriptor.
 * @param sockfd the file descriptor of the socket to be closed
 */
static void socket_close(int sockfd)
{
    if(close(sockfd) == -1)
    {
        perror("error closing socket");
        exit(EXIT_FAILURE);
    }
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

/**
 * Reads input from the network socket
 * @param client_sockfd   the file descriptor for the connected client socket
 * @param client_addr     a pointer to a struct sockaddr_storage containing
 * client address information
 */
static int read_from_socket(int client_sockfd, struct sockaddr_storage *client_addr, char *buffer)
{
    char        word[UINT8_MAX + 1];
    const char *key       = "\r\n\r\n";
    bool        key_found = false;

    while(!key_found)
    {
        const char *header_end;
        ssize_t     bytes_read = read(client_sockfd, word, sizeof(uint8_t));

        if(bytes_read < 1)
        {
            fprintf(stderr, "Connection closed or error occurred\n");
            return -1;
        }

        word[UINT8_MAX] = '\0';
        strncat(buffer, word, strlen(word));    // Concatenate the word to the buffer

        header_end = strstr(buffer, key);
        if(header_end != NULL)
        {
            key_found = true;    // Entire header has been read
        }
    }
    return 0;
}

#pragma GCC diagnostic pop

/**
 * Parses the buffer to get request information.
 * @param buffer request to be parsed
 * @return
 */
static int parse_request(char *request, struct http_request_arguments *request_args)
{
    const char *delimiter = " ";
    char       *savePtr;

    // Lines below parses the first line of the request
    request_args->type         = strtok_r(request, delimiter, &savePtr);
    request_args->endpoint     = strtok_r(NULL, delimiter, &savePtr);
    request_args->http_version = strtok_r(NULL, "\r\n", &savePtr);

    // Test print
    printf("Parse Request:\nRequest type: %s\nRequest endpoint: %s\nHTTP Version: %s\n", request_args->type, request_args->endpoint, request_args->http_version);
    return 0;
}

static int find_request_endpoint(const char *server_directory, char *request_endpoint)
{
    // Can't add any more parameters to nftw() so a global variable fixes this issue
    target_file       = request_endpoint;
    target_file_found = 0;
    if(nftw(server_directory, search_for_file, 1, FTW_PHYS) == -1)    // Use file tree walking to search for the request_endpoint
    {
        perror("nftw");
        return -1;
    }
    return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static int search_for_file(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
    if(target_file == NULL)
    {
        return 0;
    }

    if(tflag == FTW_F)
    {
        size_t fpath_length       = strlen(fpath);          // Get the length of full path
        size_t target_file_length = strlen(target_file);    // Get the length of target_file

        if(fpath_length >= target_file_length)
        {
            // fpath + (fpath_length - target_file_length) starts the fpath string at the index of (fpath_length - target_file_length)
            // eg fpath = /CLionProjects/HTTP-Server/search/test.html, target_file = /test.html
            // fpath + (fpath_length - target_file_length) = /test.html
            if(strcmp(fpath + (fpath_length - target_file_length), target_file) == 0)
            {
                target_file_found = 1;
                return 1;    // Stop the tree walk, file found
            }
        }
    }
    return 0;    // Continue the tree walk, if everything is exhausted, this function ends
}

#pragma GCC diagnostic pop

// This is simple right now, might scale to include Content-type, Content-length, more status codes, etc
// static void build_response_header(char *header)
//{
//    enum status_codes status_code;
//    const char       *status_phrase;
//
//    if(target_file_found == 1)    // Set for 200 code
//    {
//        status_code   = OK;
//        status_phrase = "OK";
//    }
//    else    // Set for 404 code
//    {
//        status_code   = NOT_FOUND;
//        status_phrase = "Not Found";
//    }
//
//    snprintf(header, LINE_LENGTH_SHORT, "HTTP/1.0 %d %s\r\n\r\n", (int)status_code, status_phrase);
//}

// Trying a different build response header code
static void build_response_header(char *header, int status_code)
{
    const char *status_phrase;

    switch(status_code)
    {
        case OK:
            status_phrase = "OK";
            break;
        case NOT_FOUND:
            status_phrase = "Not Found";
            break;
        default:
            // Handle unexpected status_code
            status_phrase = "Unknown";
            break;
    }

    snprintf(header, LINE_LENGTH_SHORT, "HTTP/1.0 %d %s\r\nContent-Type: text/html\r\nContent-Length: %ld\r\n\r\n", status_code, status_phrase, (long)((status_code == OK) ? strlen(target_file) : strlen("<html><body><h1>Not Found</h1></body></html>")));
}

// Response Sending Function
static void send_response(int client_sockfd, const char *header, const char *body)
{
    char response[LINE_LENGTH_LONG * 2];    // Allocate a buffer for the response

    sprintf(response, "%s%s", header, body);             // Format the response by combining the header and body
    write(client_sockfd, response, strlen(response));    // Sends the response to the client
}

// New function to send response, i didn't want to refactor the one above and potentially screw everything up
static int new_send_response(int client_sockfd, const char *header, const char *server_directory, const char *request_file)
{
    char response[LINE_LENGTH_LONG * 2];
    char fpath[LINE_LENGTH_SHORT] = "";
    char body[LINE_LENGTH_LONG];

    if(target_file_found == 1)    // Build response from found file
    {
        FILE *file;
        long  file_size;
        snprintf(fpath, LINE_LENGTH_SHORT, "%s%s", server_directory, request_file);    // Create absolute path to request file

        file = fopen(fpath, "re");
        if(file == NULL)
        {
            fprintf(stderr, "Error opening file.\n");
            return -1;
        }

        fseek(file, 0, SEEK_END);    // Set file position indicator to EOF
        file_size = ftell(file);     // Retrieve size of the file and store it in file_size
        fseek(file, 0, SEEK_SET);    // Set file position indicator to beginning

        fread(body, 1, (size_t)file_size, file);    // Read file into string
        body[file_size] = '\0';                     // Null-terminating the body after reading the file contents

        fclose(file);
    }
    else    // Build 404 response
    {
        sprintf(body, "<html><body><p>Cannot GET %s</p></body></html>", request_file);
    }

    sprintf(response, "%s%s", header, body);             // Format the response by combining the header and body
    printf("Get response:\n%s\n\n", response);           // Test print
    write(client_sockfd, response, strlen(response));    // Sends the response to the client

    return 0;
}

// Part of TODO1.1
static void send_head_response(int client_sockfd, const char *server_directory, const char *request_endpoint)
{
    char header[LINE_LENGTH_SHORT];
    char fpath[LINE_LENGTH_SHORT];
    long file_size   = 0;
    int  status_code = (target_file_found == 1) ? OK : NOT_FOUND;    // Use target_file_found to determine status

    // Constructs the full file path
    snprintf(fpath, LINE_LENGTH_SHORT, "%s%s", server_directory, request_endpoint);

    if(target_file_found == 1)
    {
        // If the file was found, determine its size
        FILE *file = fopen(fpath, "re");
        if(file)
        {
            fseek(file, 0, SEEK_END);
            file_size = ftell(file);
            fclose(file);
        }
    }

    // Builds the response header
    snprintf(header, LINE_LENGTH_SHORT, "HTTP/1.0 %d %s\r\nContent-Type: text/html\r\nContent-Length: %ld\r\n\r\n", status_code, (status_code == 200) ? "OK" : "Not Found", file_size);

    // Sends the header
    write(client_sockfd, header, strlen(header));
}

// Signal Handling Functions

/**
 * Sets up a signal handler for the application.
 */
static void setup_signal_handler(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

// Disable specific clang compiler warning related to macro expansion.
#if defined(__clang__)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
#endif

    // Set the signal handler function for SIGINT (Ctrl+C) to 'sigint_handler'.
    sa.sa_handler = sigint_handler;

// Restore the previous Clang compiler warning settings.
#if defined(__clang__)
    #pragma clang diagnostic pop
#endif

    sigemptyset(&sa.sa_mask);    // Clear the sa_mask, which is used to block signals
                                 // during the signal handler execution.
    sa.sa_flags = 0;             // Set sa_flags to 0, indicating no special flags for signal handling.

    // Register the signal handler configuration ('sa') for the SIGINT signal.
    if(sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

/**
 * Signal handler function for the SIGINT (Ctrl+C) signal.
 * @param signum the signal number, typically SIGINT (2) in this context
 */
static void sigint_handler(int signum)
{
    exit_flag = 1;
}

#pragma GCC diagnostic pop
