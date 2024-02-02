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
#include <ndbm.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Macros
#define LINE_LENGTH_LONG 1024
#define LINE_LENGTH_SHORT 128
#define FILE_PERMISSION 0666

// TODO: Figure out how to use NDBM to handle POST requests
/*
 * store data with post infinite glitch !!!!!
 * all we gots to do is store info
 * steps
 * init db (done)
 *  ONLY BUILD ERROR RESPONSES IF THERE'S TIME EXCEPT FOR ONES WITH *
 *  read post request body (build 500 response if error) (done)
 *  maybe change the format to only json idk -> this is done from the request with curl, we just gotta handle it correctly
 *  check if endpoint matches /store_data (else return 404) *
 *  check if syntax is correct (else return 400)
 *  store req body in db
 *  build 201 response if stored successfully, else build 500 response (internal server error)
 *  close db (done)
 *  profit !!!!
 */
// TODO: Test with port forwarder
// TODO: Start writing report documents

// ----- Function Headers -----

// Network Handling
static void convert_address(const char *address, struct sockaddr_storage *addr);
static int  socket_create(int domain, int type, int protocol);
static void socket_bind(int sockfd, struct sockaddr_storage *addr, in_port_t port);
static void start_listening(int server_fd, int backlog);
static int  socket_accept_connection(int server_fd, struct sockaddr_storage *client_addr, socklen_t *client_addr_len);
static void socket_close(int sockfd);
static int  handle_client_connection(int client_sockfd, const char *server_directory, char *request_buffer);

// HTTP Request Functions
static int  get_request_content_length(char *request_buffer, int *content_length);
static int  read_from_socket(int client_sockfd, char *buffer);
static void parse_request(const char *request, struct http_request_arguments *request_args);
static bool find_request_endpoint(const char *server_directory, const char *request_endpoint);

// HTTP Response Functions
static void build_response_header(char *header, const char *server_directory, const char *request_endpoint, bool request_file_found);
// static void build_response_header(char *header, int status_code);
static int  send_get_response(int client_sockfd, const char *header, const char *server_directory, const char *request_file, bool request_file_found);
static void send_head_response(int client_sockfd, const char *server_directory, const char *request_endpoint, bool request_file_found);
// POST Response
static int read_post_request_body(int client_sockfd, char *post_request_body, int content_length);

// Signal Handling Functions
static void setup_signal_handler(void);
static void sigint_handler(int signum);

// NDBM Database
void init_db(void);
void close_db(void);

// Pointer to Global database
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static DBM *db;

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t exit_flag = 0;

void run_server(const struct arguments *args)
{
    fd_set             readfds;
    int               *client_sockets;
    int                enable;
    int                new_socket;
    int                sd;
    size_t             max_clients;
    struct server_info server = {0};

    client_sockets = NULL;
    max_clients    = 0;
    init_db();    // Initialize the database

    // Set up server
    convert_address(args->ip_address, &server.addr);
    server.sockfd = socket_create(server.addr.ss_family, SOCK_STREAM, 0);

    enable = 1;
    if(setsockopt(server.sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) == -1)
    {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }

    socket_bind(server.sockfd, &server.addr, args->port);
    start_listening(server.sockfd, SOMAXCONN);
    setup_signal_handler();

    // Handle incoming client connections
    while(!exit_flag)
    {
        // multiplexing variables
        int max_fd;
        int activity;

        // Clear the socket set
#ifndef __clang_analyzer__
        FD_ZERO(&readfds);
#endif

        // Add the server socket to the set
        FD_SET((unsigned int)server.sockfd, &readfds);
        max_fd = server.sockfd;

        // Add the client sockets to the set
        for(size_t i = 0; i < max_clients; i++)
        {
            sd = client_sockets[i];

            if(sd > 0)
            {
                FD_SET((unsigned int)sd, &readfds);    // Add sd to the set
            }
            if(sd > max_fd)
            {
                max_fd = sd;
            }
        }

        activity = select(max_fd + 1, &readfds, NULL, NULL, NULL);

        if(activity < 0)
        {
            perror("Select error");
            exit(EXIT_FAILURE);
        }

        if(FD_ISSET(server.sockfd, &readfds))
        {
            int                    *temp;
            struct sockaddr_storage addr;
            socklen_t               addr_len;

            addr_len   = sizeof(addr);
            new_socket = socket_accept_connection(server.sockfd, &addr, &addr_len);

            if(new_socket == -1)
            {
                if(exit_flag)
                {
                    break;
                }
                continue;
            }

            printf("New client connected\n");

            // Increase the size of the client_sockets array
            max_clients++;
            temp = (int *)realloc(client_sockets, sizeof(int) * max_clients);

            if(temp == NULL)
            {
                perror("Realloc");
                free(client_sockets);
                exit(EXIT_FAILURE);
            }
            else
            {
                client_sockets                  = temp;
                client_sockets[max_clients - 1] = new_socket;
            }
        }

        // Handle incoming data from existing clients
        for(size_t i = 0; i < max_clients; i++)
        {
            sd = client_sockets[i];

            if(FD_ISSET((unsigned int)sd, &readfds))
            {
                char request_buffer[LINE_LENGTH_LONG] = "";
                // read
                if(read_from_socket(sd, request_buffer) == -1)
                {
                    // Connection closed or error
                    printf("Client %d disconnected\n", sd);
                    socket_close(sd);
                    FD_CLR((unsigned int)sd, &readfds);    // Remove the closed socket from the set
                    client_sockets[i] = 0;
                    continue;
                }

                handle_client_connection(sd, args->directory, request_buffer);
            }
        }
    }

    // Cleanup and close all client sockets
    for(size_t i = 0; i < max_clients; i++)
    {
        sd = client_sockets[i];

        if(sd > 0)
        {
            socket_close(sd);
        }
    }
    close_db();    // closing db
    free(client_sockets);
    socket_close(server.sockfd);    // Close server
    printf("Server closed successfully\n");
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

static int handle_client_connection(int client_sockfd, const char *server_directory, char *request_buffer)
{
    const char                   *post_data_const = "test post data";           // Trying to get post data
    char                         *post_data       = strdup(post_data_const);    // NDBM
    datum                         key;                                          // NDBM
    datum                         value;                                        // NDBM
    char                         *key_data = strdup("unique_post_key");         // NDBM
    bool                          request_file_found;
    struct http_request_arguments request_args = {0};

    parse_request(request_buffer, &request_args);
    request_file_found = find_request_endpoint(server_directory, request_args.endpoint);
    //    const char *post_data_const = "test post data";           // Trying to get post data
    //    char       *post_data       = strdup(post_data_const);    // NDBM
    //    char       *key_data = strdup("unique_post_key");         // NDBM

    // Check request type and generate response
    if(strcmp(request_args.type, "GET") == 0)
    {
        // Handle the GET request
        char header[LINE_LENGTH_SHORT] = "";                                                                      // Create an empty header to be built from the function below
        build_response_header(header, server_directory, request_args.endpoint, request_file_found);               // Dynamically build the response header based on if request file was found
        send_get_response(client_sockfd, header, server_directory, request_args.endpoint, request_file_found);    // Send the response back to the client
    }
    else if(strcmp(request_args.type, "HEAD") == 0)
    {
        // Handle HEAD request
        send_head_response(client_sockfd, server_directory, request_args.endpoint, request_file_found);
    }
    else if(strcmp(request_args.type, "POST") == 0)
    {
        char post_request_body[LINE_LENGTH_SHORT] = "";
        // Handle POST request
        // Processing the data sent in the request and possibly store it using NDBM
        get_request_content_length(request_buffer, &request_args.content_length);
        read_post_request_body(client_sockfd, post_request_body, request_args.content_length);

        // new NDBM items
        // Assuming post_data is extracted from request_buffer
        //        const char *post_data_const = "test post data";    // Trying to get post data

        // Dynamically allocate memory for a modifiable copy of post_data
        //        char *post_data = strdup(post_data_const);
        if(!post_data)
        {
            perror("Failed to allocate memory for post_data");
            exit(EXIT_FAILURE);    // Handle error, e.g., cleanup and exit
        }

        // Dynamically allocate memory for the key to ensure it is modifiable if needed
        if(!key_data)
        {
            free(post_data);    // Clean up post_data before exiting
            perror("Failed to allocate memory for key_data");
            exit(EXIT_FAILURE);
        }

        // Set up datum key and value with the modifiable copies
        key.dptr  = key_data;
        key.dsize = (int)strlen(key_data) + 1;

        value.dptr  = post_data;
        value.dsize = (int)strlen(post_data) + 1;

        // Store data in the database
        if(dbm_store(db, key, value, DBM_REPLACE) != 0)
        {
            fprintf(stderr, "Failed to store data in the NDBM database\n");
        }
        printf("Stored in DB\n");
    }
    else
    {
        // Handle unknown request type
        printf("400 error, text is here to avoid errors\n");
        //            const char *header = "HTTP/1.0 400 Bad Request";                              // Set the response header for a bad request
        //            const char *body   = "<html><body><h1>400 Bad Request</h1></body></html>";    // Set an HTML body which indicates the request was bad
        //            send_response(client_sockfd, header, body);                                   // Send the response back to the client
    }
    // Frees the allocated key data
    free(key_data);
    free(post_data);
    free(request_args.type);
    free(request_args.endpoint);
    free(request_args.http_version);
    return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static int get_request_content_length(char *request_buffer, int *content_length)
{
    const char *needle             = "Content-Length: ";
    const char *content_length_ptr = strstr(request_buffer, needle);
    char       *endptr;
    const int   base_ten = 10;

    printf("Request buffer: %s\n", request_buffer);

    if(content_length_ptr != NULL)
    {
        content_length_ptr += strlen(needle);    // Move the pointer to the value of Content-Length

        *content_length = (int)strtol(content_length_ptr, &endptr, base_ten);    // Get the Content-Length as an int
    }
    else
    {
        printf("Content-Length not found\n");
        return -1;
    }

    return 0;
}

/**
 * Reads input from the network socket
 * @param client_sockfd   the file descriptor for the connected client socket
 * @param client_addr     a pointer to a struct sockaddr_storage containing
 * client address information
 */
static int read_from_socket(int client_sockfd, char *buffer)
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
    printf("Buffer: %s\n", buffer);
    return 0;
}

#pragma GCC diagnostic pop

/**
 * Parses the buffer to get request information.
 * @param buffer request to be parsed
 * @return
 */
static void parse_request(const char *request, struct http_request_arguments *request_args)
{
    const char *delimiter = " ";
    char       *savePtr;
    char       *request_copy = strdup(request);    // dup from original to not modify the original

    // Lines below parses the first line of the request, dup from each to be able to free the copy and still use these args else where
    request_args->type         = strdup(strtok_r(request_copy, delimiter, &savePtr));
    request_args->endpoint     = strdup(strtok_r(NULL, delimiter, &savePtr));
    request_args->http_version = strdup(strtok_r(NULL, "\r\n", &savePtr));

    // Test print
    printf("Parse Request:\nRequest type: %s\nRequest endpoint: %s\nHTTP Version: %s\n", request_args->type, request_args->endpoint, request_args->http_version);
    free(request_copy);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static bool find_request_endpoint(const char *server_directory, const char *request_endpoint)
{
    char fpath[LINE_LENGTH_SHORT];

    // Hard code / to find /index.html
    if(strcmp(request_endpoint, "/") == 0)
    {
        snprintf(fpath, LINE_LENGTH_SHORT, "%s%s", server_directory, "/index.html");
    }
    else
    {
        snprintf(fpath, LINE_LENGTH_SHORT, "%s%s", server_directory, request_endpoint);
    }

    if(access(fpath, F_OK) != -1)
    {
        return true;    // File exists, build 200 response
    }

    return false;    // File doesn't exist, build 404 response
}

#pragma GCC diagnostic pop

// This is simple right now, might scale to include Content-type, Content-length, more status codes, etc
static void build_response_header(char *header, const char *server_directory, const char *request_endpoint, bool request_file_found)
{
    enum status_codes status_code;
    const char       *status_phrase;
    long              content_length;

    if(request_file_found)    // Set for 200 code
    {
        char  fpath[LINE_LENGTH_SHORT];
        char  content_buffer[LINE_LENGTH_LONG];
        FILE *file;
        long  file_size;

        status_code   = OK;
        status_phrase = "OK";

        if(strcmp(request_endpoint, "/") == 0)
        {
            snprintf(fpath, LINE_LENGTH_SHORT, "%s%s", server_directory, "/index.html");
        }
        else
        {
            snprintf(fpath, LINE_LENGTH_SHORT, "%s%s", server_directory, request_endpoint);
        }

        file = fopen(fpath, "re");
        if(file == NULL)
        {
            fprintf(stderr, "Error opening file.\n");
            return;
        }

        fseek(file, 0, SEEK_END);    // Set file position indicator to EOF
        file_size = ftell(file);     // Retrieve size of the file and store it in file_size
        fseek(file, 0, SEEK_SET);    // Set file position indicator to beginning

        fread(content_buffer, 1, (size_t)file_size, file);    // Read file into string
        content_buffer[file_size] = '\0';                     // Null-terminating the body after reading the file contents

        fclose(file);
        content_length = (long)strlen(content_buffer);
    }
    else    // Set for 404 code
    {
        char error_body[LINE_LENGTH_SHORT];
        status_code   = NOT_FOUND;
        status_phrase = "Not Found";

        snprintf(error_body, LINE_LENGTH_SHORT, "<html><body><p>Cannot GET %s</p></body></html>", request_endpoint);
        content_length = (long)strlen(error_body);
    }

    snprintf(header, LINE_LENGTH_SHORT, "HTTP/1.0 %d %s\r\nContent-Type: text/html\r\nContent-Length: %ld\r\n\r\n", (int)status_code, status_phrase, content_length);
}

// Response Sending Function
static int send_get_response(int client_sockfd, const char *header, const char *server_directory, const char *request_file, bool request_file_found)
{
    char response[LINE_LENGTH_LONG * 2];
    char fpath[LINE_LENGTH_SHORT] = "";
    char body[LINE_LENGTH_LONG];

    if(request_file_found)    // Build response from found file
    {
        FILE *file;
        long  file_size;

        if(strcmp(request_file, "/") == 0)
        {
            snprintf(fpath, LINE_LENGTH_SHORT, "%s%s", server_directory, "/index.html");
        }
        else
        {
            snprintf(fpath, LINE_LENGTH_SHORT, "%s%s", server_directory, request_file);
        }

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
static void send_head_response(int client_sockfd, const char *server_directory, const char *request_endpoint, bool request_file_found)
{
    char header[LINE_LENGTH_SHORT];
    char fpath[LINE_LENGTH_SHORT];
    long file_size   = 0;
    int  status_code = (request_file_found) ? OK : NOT_FOUND;    // Use request_file_found to determine status

    // Constructs the full file path
    snprintf(fpath, LINE_LENGTH_SHORT, "%s%s", server_directory, request_endpoint);

    if(request_file_found)
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
    snprintf(header, LINE_LENGTH_SHORT, "HTTP/1.0 %d %s\r\nContent-Type: text/html\r\nContent-Length: %ld\r\n\r\n", status_code, (status_code == OK) ? "OK" : "Not Found", file_size);

    // Sends the header
    write(client_sockfd, header, strlen(header));
}

static int read_post_request_body(int client_sockfd, char *post_request_body, int content_length)
{
    char    word[UINT8_MAX + 1];
    ssize_t total_bytes_read = 0;

    printf("Content Length: %d\n", content_length);

    while((int)total_bytes_read < content_length)
    {
        ssize_t bytes_read = read(client_sockfd, word, sizeof(uint8_t));
        if(bytes_read < 1)
        {
            printf("error occurred\n");    // return -1 and go to next iteration for now, could build 500 response
            return -1;
        }

        word[UINT8_MAX] = '\0';
        strncat(post_request_body, word, strlen(word));
        total_bytes_read += bytes_read;
    }

    printf("post request body: %s\n", post_request_body);
    return 0;
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

/**
 * Database Initialization and file permission management for NDBM.
 */
void init_db(void)
{
    // Open the database; create if it doesn't exist
    // FILE_PERMISSION sets the file permission to read and write for the user, group, and others
    const char file[LINE_LENGTH_SHORT] = "post_data_db";
    char      *file_copy               = strdup(file);
    db                                 = dbm_open(file_copy, O_RDWR | O_CREAT, FILE_PERMISSION);
    if(!db)
    {
        perror("Failed to open/create the NDBM database");
        free(file_copy);
        exit(EXIT_FAILURE);    // Exits the program if the database cannot be opened or created
    }
    free(file_copy);
}

/**
 * Database closing and resource management for NDBM.
 */
void close_db(void)
{
    if(db)
    {
        dbm_close(db);    // Closes the NDBM database and release resources.
        db = NULL;        // Safeguard
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
