#ifndef _HELPERS_H_
#define _HELPERS_H_

#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifdef DEBUG
#define VERBOSE(...) printf(__VA_ARGS__)
#else
#define VERBOSE(...)
#endif

#define KiB (1 << 10)
#define MiB (1 << 20)

#define CHKRES(res, msg)                                     \
    {                                                        \
        if ((res) == -1)                                     \
        {                                                    \
            fprintf(stderr, "%s: %d\n", __FILE__, __LINE__); \
            perror(msg);                                     \
            exit(EXIT_FAILURE);                              \
        }                                                    \
    }

#define TAB "\t"
#define NL "\n"
#define PRINT_HELP()                                                           \
    {                                                                          \
        fprintf(stderr,                                                        \
                "FLAGS:" TAB "-d: Sets work dir" NL                            \
                    TAB "-h: Prints this message" NL                           \
                        TAB "-p: Sets porn number to listen on (1-65535)" NL); \
        exit(EXIT_SUCCESS);                                                    \
    }

#define SET_FLAGS(ARGC, ARGV)                                                                    \
    {                                                                                            \
        int flag = 0;                                                                            \
        for (int i = 1; i < ARGC; ++i)                                                           \
        {                                                                                        \
            switch (flag)                                                                        \
            {                                                                                    \
            case 0:                                                                              \
                if (ARGV[i][0] == '-')                                                           \
                    flag = ARGV[i][1];                                                           \
                switch (flag)                                                                    \
                {                                                                                \
                case 'd':                                                                        \
                    if (i + 1 < ARGC)                                                            \
                        strncpy(www_dir, ARGV[i + 1], strlen(ARGV[i + 1]) + 1);                  \
                    else                                                                         \
                    {                                                                            \
                        fprintf(stderr, NL "ERROR:" TAB "Provide path to -d flag" NL);           \
                        PRINT_HELP();                                                            \
                        exit(EXIT_FAILURE);                                                      \
                    }                                                                            \
                    flag = 0;                                                                    \
                    break;                                                                       \
                case 'h':                                                                        \
                    PRINT_HELP();                                                                \
                    flag = 0;                                                                    \
                    break;                                                                       \
                case 'p':                                                                        \
                    if (i + 1 < ARGC)                                                            \
                    {                                                                            \
                        char *garbo = NULL;                                                      \
                        port = strtol(argv[i + 1], &garbo, 10);                                  \
                        (port < 1) ? (port = 0) : (port <= 65535) ? (port)                       \
                                                                  : (port = 0);                  \
                        if (argv[i + 1] == garbo || port == 0 || argv[i + 1][0] == '-')          \
                        {                                                                        \
                            fprintf(stderr, "'%s' is not a proper port number" NL, argv[i + 1]); \
                            PRINT_HELP();                                                        \
                        }                                                                        \
                    }                                                                            \
                    else                                                                         \
                    {                                                                            \
                        fprintf(stderr, NL "ERROR:" TAB "Provide port number (1-65535)" NL);     \
                        PRINT_HELP();                                                            \
                    }                                                                            \
                }                                                                                \
            default:                                                                             \
                flag = 0;                                                                        \
            }                                                                                    \
        }                                                                                        \
    }

// inline
int ishex(int x)
{
    return (x >= '0' && x <= '9') ||
           (x >= 'a' && x <= 'f') ||
           (x >= 'A' && x <= 'F');
}

int decode(const char *s, char *dec)
{
    char *o;
    const char *end = s + strlen(s);
    int c;

    for (o = dec; s <= end; o++)
    {
        c = *s++;
        if (c == '+')
            c = ' ';
        else if (c == '%' && (!ishex(*s++) ||
                              !ishex(*s++) ||
                              !sscanf(s - 2, "%2x", &c)))
            return -1;

        if (dec)
            *o = c;
    }
    return o - dec;
}

#endif
