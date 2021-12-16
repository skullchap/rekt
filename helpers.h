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

#define KiB (1 << 10)
#define MiB (1 << 20)
#define GiB (1 << 30)
#define TAB "\t"
#define NL "\n"
#define PRINT_HELP()                                                         \
    {                                                                        \
        fprintf(stderr,                                                      \
                "FLAGS:" TAB "-d: Sets work dir" NL                          \
                    TAB "-h: Prints this message" NL                         \
                        TAB "-p: Sets porn number to listen on (1-65535)" NL \
                            TAB "-s: Enables SSL mode" NL                    \
                                TAB TAB "-c: Sets SSL PEM cert file" NL      \
                                    TAB TAB "-k: Sets SSL PEM key file" NL); \
        exit(EXIT_SUCCESS);                                                  \
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
                        port = strtol(ARGV[i + 1], &garbo, 10);                                  \
                        (port < 1) ? (port = 0) : (port <= 65535) ? (port)                       \
                                                                  : (port = 0);                  \
                        if (ARGV[i + 1] == garbo || port == 0 || ARGV[i + 1][0] == '-')          \
                        {                                                                        \
                            fprintf(stderr, "'%s' is not a proper port number" NL, ARGV[i + 1]); \
                            PRINT_HELP();                                                        \
                        }                                                                        \
                    }                                                                            \
                    else                                                                         \
                    {                                                                            \
                        fprintf(stderr, NL "ERROR:" TAB "Provide port number (1-65535)" NL);     \
                        PRINT_HELP();                                                            \
                    }                                                                            \
                case 's':                                                                        \
                    ssl_flag++;                                                                  \
                    flag = 0;                                                                    \
                    break;                                                                       \
                case 'c':                                                                        \
                    if (i + 1 < ARGC && (access(ARGV[i + 1], F_OK)) == 0)                        \
                        pem_cert_file = ARGV[i + 1];                                             \
                    else                                                                         \
                    {                                                                            \
                        fprintf(stderr, NL "ERROR:" TAB "Provide path to PEM cert file" NL);     \
                        PRINT_HELP();                                                            \
                        exit(EXIT_FAILURE);                                                      \
                    }                                                                            \
                    flag = 0;                                                                    \
                    break;                                                                       \
                case 'k':                                                                        \
                    if (i + 1 < ARGC && (access(ARGV[i + 1], F_OK)) == 0)                        \
                        pem_key_file = ARGV[i + 1];                                              \
                    else                                                                         \
                    {                                                                            \
                        fprintf(stderr, NL "ERROR:" TAB "Provide path to PEM key file" NL);      \
                        PRINT_HELP();                                                            \
                        exit(EXIT_FAILURE);                                                      \
                    }                                                                            \
                    flag = 0;                                                                    \
                    break;                                                                       \
                }                                                                                \
            default:                                                                             \
                flag = 0;                                                                        \
            }                                                                                    \
        }                                                                                        \
        if (ssl_flag)                                                                            \
        {                                                                                        \
            if (pem_cert_file == NULL || pem_key_file == NULL)                                   \
            {                                                                                    \
                fprintf(stderr, NL "ERROR:" TAB "Provide path to PEM files" NL);                 \
                PRINT_HELP();                                                                    \
                exit(EXIT_FAILURE);                                                              \
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

void siginthand(int sig)
{
    killpg(0, SIGKILL);
}

void sendfd(int socket, int fd) // send fd by socket
{
    struct msghdr msg = {0};
    char buf[CMSG_SPACE(sizeof(fd))];
    memset(buf, '\0', sizeof(buf));
    struct iovec io = {.iov_base = "ABC", .iov_len = 3};

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

    *((int *)CMSG_DATA(cmsg)) = fd;

    msg.msg_controllen = CMSG_SPACE(sizeof(fd));

    if (sendmsg(socket, &msg, 0) < 0)
        fprintf(stderr, "Failed to send message\n");
}

int recvfd(int socket) // receive fd from socket
{
    struct msghdr msg = {0};

    char m_buffer[256];
    struct iovec io = {.iov_base = m_buffer, .iov_len = sizeof(m_buffer)};
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    char c_buffer[256];
    msg.msg_control = c_buffer;
    msg.msg_controllen = sizeof(c_buffer);

    if (recvmsg(socket, &msg, 0) < 0)
        fprintf(stderr, "Failed to receive message\n");

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    unsigned char *data = CMSG_DATA(cmsg);

    // fprintf(stderr, "About to extract fd\n");
    int fd = *((int *)data);
    // fprintf(stderr, "Extracted fd %d\n", fd);

    return fd;
}

#endif
