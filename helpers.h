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
#define PRINT_HELP()                                   \
    {                                                  \
        fprintf(stderr,                                \
                "FLAGS:" TAB "-d: Sets work dir" NL    \
                    TAB "-h: Prints this message" NL); \
        exit(EXIT_SUCCESS);                            \
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
