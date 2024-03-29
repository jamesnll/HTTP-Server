#include "../include/server.h"
#include <p101_env/env.h>
#include <p101_error/error.h>
#include <p101_posix/p101_unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void           parse_arguments(const struct p101_env *env, int argc, char *argv[], struct arguments *args);
static void           check_arguments(const struct p101_env *env, const char *binary_name, const struct arguments *args);
static in_port_t      parse_in_port_t(const struct p101_env *env, struct p101_error *error, const char *port_str);
_Noreturn static void usage(const struct p101_env *env, const char *program_name, int exit_code, const char *message);

#define UNKNOWN_OPTION_MESSAGE_LEN 24
#define BASE_TEN 10

int main(int argc, char *argv[])
{
    struct p101_env   *env;    // Environment management system
    struct p101_error *err;
    struct arguments   args = {0};
    int                exit_code;

    err = p101_error_create(false);
    env = p101_env_create(err, true, NULL);

    parse_arguments(env, argc, argv, &args);
    check_arguments(env, argv[0], &args);
    args.port = parse_in_port_t(env, err, args.port_str);

    if(p101_error_has_error(err))
    {
        goto error;
    }

    run_server(&args);

    if(p101_error_has_error(err))
    {
        goto error;
    }

    exit_code = EXIT_SUCCESS;
    goto done;

error:
    fprintf(stderr, "Error %s\n", p101_error_get_message(err));
    exit_code = EXIT_FAILURE;

done:
    p101_error_reset(err);
    free(env);
    free(err);

    return exit_code;
}

static void parse_arguments(const struct p101_env *env, int argc, char *argv[], struct arguments *args)
{
    int opt;
    P101_TRACE(env);
    opterr = 0;

    while((opt = p101_getopt(env, argc, argv, "h:")) != -1)
    {
        switch(opt)
        {
            case 'h':
            {
                usage(env, argv[0], EXIT_SUCCESS, NULL);
            }
            case '?':
            {
                char message[UNKNOWN_OPTION_MESSAGE_LEN];

                snprintf(message, sizeof(message), "Unknown option '-%c'.", optopt);
                usage(env, argv[0], EXIT_FAILURE, message);
            }
            default:
            {
                usage(env, argv[0], EXIT_FAILURE, NULL);
            }
        }
    }

    if(optind >= argc)
    {
        usage(env, argv[0], EXIT_FAILURE, "Error: Insufficient arguments.");
    }

    if(optind < argc - 3)
    {
        usage(env, argv[0], EXIT_FAILURE, "Error: Too many arguments.");
    }

    args->ip_address = argv[optind];
    args->port_str   = argv[optind + 1];
    args->directory  = argv[optind + 2];
}

static void check_arguments(const struct p101_env *env, const char *binary_name, const struct arguments *args)
{
    P101_TRACE(env);

    if(args->ip_address == NULL)
    {
        usage(env, binary_name, EXIT_FAILURE, "The ip address is required.");
    }

    if(args->port_str == NULL)
    {
        usage(env, binary_name, EXIT_FAILURE, "The port is required.");
    }

    if(args->directory == NULL)
    {
        usage(env, binary_name, EXIT_FAILURE, "The directory is required.");
    }
}

static in_port_t parse_in_port_t(const struct p101_env *env, struct p101_error *error, const char *port_str)
{
    char     *endptr;
    uintmax_t parsed_value;

    P101_TRACE(env);
    errno        = 0;
    parsed_value = strtoumax(port_str, &endptr, BASE_TEN);

    // Check for errno was signalled
    if(errno != 0)
    {
        P101_ERROR_RAISE_USER(error, "Error parsing in_port_t.", 1);
        parsed_value = 0;
        goto done;
    }

    // Check for any non-numeric characters in the input string
    if(*endptr != '\0')
    {
        P101_ERROR_RAISE_USER(error, "Invalid characters in input.", 2);
        parsed_value = 0;
        goto done;
    }

    // Check if the parsed value is within valid range of in_port_t
    if(parsed_value > UINT16_MAX)
    {
        P101_ERROR_RAISE_USER(error, "in_port_t value out of range.", 3);
        parsed_value = 0;
        goto done;
    }

done:
    return (in_port_t)parsed_value;
}

_Noreturn static void usage(const struct p101_env *env, const char *program_name, int exit_code, const char *message)
{
    P101_TRACE(env);

    if(message)
    {
        fprintf(stderr, "%s\n", message);
    }

    fprintf(stderr, "Usage: %s [-h] <ip address> <port> <directory>\n", program_name);
    fputs("Options:\n", stderr);
    fputs(" -h Display this help message\n", stderr);
    exit(exit_code);
}
