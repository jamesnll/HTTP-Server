#ifndef HTTP_SERVER_SERVER_H
#define HTTP_SERVER_SERVER_H

struct arguments
{
    char *ip_address;
    char *port_str;
    char *directory;
};

void run_server(const struct arguments *args);

#endif    // HTTP_SERVER_SERVER_H
