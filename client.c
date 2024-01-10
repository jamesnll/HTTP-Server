// Name: Wallace Trinh
// Student #:A01289206
// Date: Oct 2023

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
void             read_server_response(int sock);
static void      parse_arguments(int argc, char *argv[], char **ip_address, char **port, char **command);
static in_port_t parse_in_port_t(const char *port_str);
static void      convert_address(const char *address, struct sockaddr_storage *addr);
static int       socket_create(int domain);
static void      socket_connect(int sockfd, struct sockaddr_storage *addr, in_port_t port);
static void      socket_close(int sockfd);

// Main function
int main(int argc, char *argv[])
{
    char                   *ip;
    char                   *port_str;
    char                   *command;
    in_port_t               port;
    int                     sockfd;
    struct sockaddr_storage addr;

    parse_arguments(argc, argv, &ip, &port_str, &command);
    port = parse_in_port_t(port_str);
    convert_address(ip, &addr);
    sockfd = socket_create(addr.ss_family);
    socket_connect(sockfd, &addr, port);

    write(sockfd, command, strlen(command));
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

// Parses command-line argument for the IP, port and command
static void parse_arguments(int argc, char *argv[], char **ip_address, char **port, char **command)
{
    if(argc != 4)
    {
        fprintf(stderr, "Usage: %s <ip address> <port> <command>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    *ip_address = argv[1];
    *port       = argv[2];
    *command    = argv[3];
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
