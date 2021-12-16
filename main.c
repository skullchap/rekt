#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/mman.h>
#include <netinet/in.h>

#if __has_include(<openssl/ssl.h>)
#define REKTSSL 1
#include <openssl/ssl.h>
#include <openssl/err.h>
#else
#warning NO OPENSSL LIBRARY HEADER DETECTED, COMPILING WITHOUT SSL SUPPORT
#endif

#ifndef __APPLE__
#include <sys/sendfile.h>
#endif

#ifdef EXPERIMENTAL
#include <sys/resource.h>
#endif

#include "helpers.h"

#define PORT 8080
#define BFSZ 1400

static long port = PORT;
static int ssl_flag = 0;
char *pem_cert_file = NULL;
char *pem_key_file = NULL;

static char httpStatus200[] = "HTTP/1.1 200 OK\r\n\r\n";
static char httpStatus403[] = "HTTP/1.1 403 Forbidden\r\n\r\n";
static char httpStatus404[] = "HTTP/1.1 404 Not Found\r\n\r\n";
static char httpStatus500[] = "HTTP/1.1 500 Internal Server Error\r\n\r\n";

static char www_dir[PATH_MAX] = "./";

#ifdef POST
#define VALSZ 128
struct
{
    char content_type[VALSZ];
    char boundary[VALSZ];
    size_t content_length;
} ReqHeader = {
    .boundary = "--",
};
#endif

#define NSPAWN 16
static volatile int *volatile spawn_pids = NULL;
static volatile int *volatile taken = NULL;

int main(int argc, char **argv)
{
    SET_FLAGS(argc, argv);

#ifdef REKTSSL
    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;
    if (ssl_flag)
    {
        const SSL_METHOD *method;

        method = TLS_server_method();

        ctx = SSL_CTX_new(method);
        if (!ctx)
        {
            perror("Unable to create SSL context");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        /* Set the key and cert */
        if (SSL_CTX_use_certificate_file(ctx, pem_cert_file, SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, pem_key_file, SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        VERBOSE("SSL Enabled\n");
    }

#endif

    // int nproc = sysconf(_SC_NPROCESSORS_ONLN);
    if (!chdir(www_dir))
        VERBOSE(NL "work dir set to %s" NL, www_dir);

    int server_fd = 0, conn_fd = 0, valread = 0;
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(port),
    };

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    CHKRES(server_fd, "socket error");

    CHKRES(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)), "setsockopt error");

    CHKRES(bind(server_fd, (struct sockaddr *)&address, sizeof(address)), "bind error");
    CHKRES(listen(server_fd, 0), "listen error");
    VERBOSE("listening on %ld port" NL NL, port);

    VERBOSE("Launched workers mode\n");
    spawn_pids = mmap(NULL, NSPAWN * sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    taken = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    *taken = -1;
    int sv[2];
    CHKRES(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv), "socketpair");

    signal(SIGINT, siginthand);
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGUSR1);
    sigprocmask(SIG_BLOCK, &sigset, NULL);
    int sig = 0;

    sigset_t sigset2;
    sigemptyset(&sigset2);
    sigaddset(&sigset2, SIGUSR2);
    sigprocmask(SIG_BLOCK, &sigset2, NULL);
    int sig2 = 0;

    int parent_pid = getpid();

    signal(SIGCHLD, SIG_IGN);

    struct timeval tv1 = {0}, tv2 = {0};
    struct stat stats = {0};
    DIR *d = NULL;
    struct dirent *dir = NULL;

    struct pollfd fds = {0};
    struct stat st = {0};

/*
     * ONLY WORKS WITH EXPERIMENTAL FLAG
     * SETS STACK SIZE OF FORKED CHILD TO 8 KiB.
     * IN CASE OF FAULTS OR BROKEN PAGES, REMOVE IT!
    */
#ifdef EXPERIMENTAL
    CHKRES(setrlimit(RLIMIT_STACK,
                     &(struct rlimit){.rlim_max = 8 * KiB,
                                      .rlim_cur = 8 * KiB}),
           "setrlimit error");
#endif
    int child = 0;
    int pid = 0;
    for (int i = 0; i < NSPAWN; ++i)
    {
        if (!child)
        {
            pid = fork();
            if (pid != 0) // parent
            {
                spawn_pids[i] = pid;
                continue;
            }
            child = 1;
            break;
        }
    }

    if (!child)
    {
        VERBOSE("Spawned %d workers\n", NSPAWN);
        // for (int i = 0; i < NSPAWN; ++i)
        //     printf("%d\n", spawn_pids[i]);

        close(sv[1]);
        int sock = sv[0];

        while (1)
        {
            conn_fd = accept(server_fd, NULL, NULL);
            CHKRES(conn_fd, "accept error");

            sendfd(sock, conn_fd);
            *taken = 0;
            sigwait(&sigset2, &sig2);
            kill(*taken, SIGUSR1);
            // kill(0, SIGUSR1);
            close(conn_fd);
        }
    }

    if (child)
    {
        close(sv[0]);
        int sock = sv[1];
        int fd = 0;
        char buf[BFSZ] = {0};

    child_loop:
        while (1)
        {
            memset(buf, 0, BFSZ);
            *taken = getpid();
            kill(parent_pid, SIGUSR2);
            sigwait(&sigset, &sig);
            if ((*taken))
            {
                // *taken = getpid();
                conn_fd = recvfd(sock);
                gettimeofday(&tv1, NULL);

                fds.fd = conn_fd;
                fds.events = POLLIN;

                if (!poll(&fds, 1, 10 * 1000))
                {
                    close(conn_fd);
                    goto child_loop;
                }

#ifdef REKTSSL
                if (ssl_flag)
                {
                    ssl = SSL_new(ctx);

                    SSL_set_fd(ssl, conn_fd);
                    if (SSL_accept(ssl) <= 0)
                    {
                        ERR_print_errors_fp(stderr);
                        goto cleanup;
                    }
                    SSL_read(ssl, buf, BFSZ);
                }
                else
#endif
                    read(conn_fd, buf, BFSZ);

                char *route = NULL; /* part after METHOD (GET, POST, ...) */
                int should_parse = 0, n = 0;
                if (buf[0] == 'G' &&
                    buf[1] == 'E' &&
                    buf[2] == 'T')
                {
                    should_parse = 1, n = 3;
                    VERBOSE("Serving by %d pid\n", getpid());
                    VERBOSE("%s\n", buf);
                    VERBOSE("Method:\tGET\n");
                }
#ifdef POST
                else if (buf[0] == 'P' &&
                         buf[1] == 'O' &&
                         buf[2] == 'S' &&
                         buf[3] == 'T')
                {
                    should_parse = 1, n = 4;
                    VERBOSE("%s\n", buf);
                    VERBOSE("Method:\tPOST\n");
                }
#endif
                if (should_parse)
                {
                    if (buf[n++] == ' ')
                    {
                        if (buf[n] != '/')
                            goto cleanup;

                        buf[--n] = '.'; // adding '.' before '/' - "./"
                        route = &buf[n];
                    }
                    else
                        goto cleanup;

                    route[strcspn(route, " ")] = '\0';

                    if (strstr(route, "../") != NULL ||
                        strstr(route, "/..") != NULL)
                        goto cleanup; // back path-traversal prevention

                    VERBOSE("Route :\t%s\n", route);

                    char *routecp = route;

                    if (!strcmp(routecp, "./"))
                    {
                        routecp = "./index.html";
                        goto skip_decode;
                    }
                    {
                        int routesz = strlen(routecp) + 1;
                        char decoded_routecp[routesz];
                        memset(decoded_routecp, 0, sizeof(decoded_routecp));

                        decode(routecp, decoded_routecp) < 0
                            ? routecp = "./index.html"
                            : memcpy(routecp, decoded_routecp, routesz);
                    }
                skip_decode:
                    if (access(routecp, F_OK) == 0)
                    {
                        stat(routecp, &stats);
                        if (S_ISDIR(stats.st_mode))
                        {
                            d = opendir(routecp);
                            if (d)
                            {
                                routecp = strdup(routecp);
                                memset(buf, 0, BFSZ);
                                snprintf(buf, BFSZ, "%s", httpStatus200);
                                int slen = strlen(buf);
                                snprintf(buf + slen, BFSZ - slen, "<!DOCTYPE html><h1 style=\"font-family:sans-serif;padding:1em;border-bottom:5px solid;\">%s</h1>\r\n", routecp);
#ifdef REKTSSL
                                if (ssl_flag)
                                    SSL_write(ssl, buf, strlen(buf));
                                else
#endif
                                    write(conn_fd, buf, strlen(buf));

                                while ((dir = readdir(d)) != NULL)
                                {
                                    memset(buf, 0, BFSZ);

                                    if (dir->d_name[0] == '.' &&
                                        (dir->d_name[1] == '.' || dir->d_name[1] == '\0'))
                                        continue;
                                    snprintf(buf, BFSZ, "<a style=\"font-family:sans-serif;padding:1em;display:inline-block;border-bottom:5px solid;\""
                                                        "href=\"/%s/%s\">%s</a>\n",
                                             routecp, dir->d_name, dir->d_name);
#ifdef REKTSSL
                                    if (ssl_flag)
                                        SSL_write(ssl, buf, strlen(buf));
                                    else
#endif
                                        write(conn_fd, buf, strlen(buf));
                                }
                                free(routecp);
                                closedir(d);

                                goto cleanup;
                            }
                        }

#ifdef POST
                        if (n == 4) // POST
                        {
                            int offset = 0;
                            char *ptr = NULL;
                            while (fgets(buf, BFSZ, f_recv) != NULL)
                            {
                                ptr = buf;
                                if (offset = 14, !strncmp(buf, "Content-Type: ", offset))
                                {
                                    ptr = buf + offset;
                                    int sep = strcspn(ptr, " ");
                                    strncpy(ReqHeader.content_type, ptr, (sep < VALSZ) ? sep : VALSZ);
                                    ;
                                    if ((ptr = strstr(ptr, "boundary")) != NULL)
                                    {
                                        sep = strcspn(ptr, "=") + 1;
                                        ptr += sep;
                                        sep = strcspn(ptr, " ");
                                        strncpy(ReqHeader.boundary + 2, ptr, (sep < VALSZ - 2) ? sep : VALSZ - 2);
                                    }
                                }
                                if (offset = 16, !strncmp(buf, "Content-Length: ", offset))
                                {
                                    ptr = buf + offset;
                                    ptr[strcspn(ptr, " ")] = '\0';
                                    ReqHeader.content_length = strtol(ptr, NULL, 10);
                                }
                                if (buf[1] == '\n' || buf[1] == '\0')
                                    break;
                            }
                            VERBOSE("%s\n", ReqHeader.content_type);
                            VERBOSE("%s\n", ReqHeader.boundary);
                            VERBOSE("%lu\n", ReqHeader.content_length);

                            size_t bodyBufSize = (ReqHeader.content_length < 32 * MiB)
                                                     ? ReqHeader.content_length
                                                     : 32 * MiB;
                            char *bodyBuf = NULL;
                            if ((bodyBuf = malloc(bodyBufSize)) == NULL)
                            {
                                fprintf(f_send, "%s", httpStatus500);
                                fclose(f_recv);
                                fclose(f_send);
                                close(conn_fd);
                                goto child_loop;
                            }
                            int b = (ReqHeader.content_length <= bodyBufSize)
                                        ? ReqHeader.content_length
                                        : bodyBufSize,
                                len = 0;
                            VERBOSE("take %d bytes\n", b);

                            while ((b = fread(bodyBuf + len, 1, b, f_recv)) > 0)
                            {
                                printf("b: %d\n", b);
                                len += b;
                                if (len > bodyBufSize)
                                {
                                    free(bodyBuf);
                                    fclose(f_recv);
                                    fclose(f_send);
                                    close(conn_fd);
                                    goto child_loop;
                                }
                                b = ReqHeader.content_length - b;
                                if (len >= ReqHeader.content_length)
                                {
                                    printf("%d is len\n", len);
                                    break;
                                }
                            }

                            printf("%s\n", bodyBuf);
                            free(bodyBuf);
                        }
#endif

                        VERBOSE("%s\n", routecp);
                        int fd = open(routecp, O_RDONLY);
                        if (fd > 0)
                        {
                            fstat(fd, &st);
                            ssize_t fileSize = (ssize_t)st.st_size;
#ifdef REKTSSL
                            if (ssl_flag)
                            {
                                memset(buf, 0, BFSZ);
                                snprintf(buf, BFSZ, "%s", httpStatus200);
                                SSL_write(ssl, buf, strlen(buf));

                                void *fileBuf = malloc(fileSize);
                                read(fd, fileBuf, fileSize);
                                SSL_write(ssl, fileBuf, fileSize);
                                free(fileBuf);
                            }
                            else
#endif
                            {
                                dprintf(conn_fd, "%s", httpStatus200);
#ifdef __APPLE__
                                CHKRES(sendfile(fd, conn_fd, 0, &fileSize, NULL, 0), "sendfile error");
#else
                                CHKRES(sendfile(conn_fd, fd, NULL, fileSize), "sendfile error");
#endif
                            }

                            gettimeofday(&tv2, NULL);

                            VERBOSE("Size :\t%zu KiB\n", fileSize / (1 << 10));
                            VERBOSE("Handle time = %f seconds\n\n",
                                    (double)(tv2.tv_usec - tv1.tv_usec) / 1000000 +
                                        (double)(tv2.tv_sec - tv1.tv_sec));

                            close(fd);
                            goto cleanup;
                        }
                        else
                        {
                            perror("open error");
#ifdef REKTSSL
                            if (ssl_flag)
                            {
                                memset(buf, 0, BFSZ);
                                snprintf(buf, BFSZ, "%s"
                                                    "<!DOCTYPE html><h2 style=\"font-family:sans-serif;\">Access denied</h2>\r\n",
                                         httpStatus403);
                                SSL_write(ssl, buf, strlen(buf));
                            }
                            else
#endif
                                dprintf(conn_fd, "%s"
                                                 "<!DOCTYPE html><h2 style=\"font-family:sans-serif;\">Access denied</h2>\r\n",
                                        httpStatus403);

                            goto cleanup;
                        }
                    }
                    else
                    {
                        VERBOSE("%s does not exist\n\n", routecp);
#ifdef REKTSSL
                        if (ssl_flag)
                        {
                            memset(buf, 0, BFSZ);
                            snprintf(buf, BFSZ, "%s"
                                                "<!DOCTYPE html><h2 style=\"font-family:sans-serif;\">%s does not exist</h2>\r\n",
                                     httpStatus404,
                                     routecp);
                            SSL_write(ssl, buf, strlen(buf));
                        }
                        else
#endif
                            dprintf(conn_fd, "%s"
                                             "<!DOCTYPE html><h2 style=\"font-family:sans-serif;\">%s does not exist</h2>\r\n",
                                    httpStatus404,
                                    routecp);

                    cleanup:
#ifdef REKTSSL
                        if (ssl_flag)
                        {
                            SSL_shutdown(ssl);
                            SSL_free(ssl);
                        }
#endif
                        close(conn_fd);
                        goto child_loop;
                    }
                }

#ifdef DEBUG
                write(conn_fd, buf, BFSZ);
#endif
                close(conn_fd);
            } // end if taken
        }     // main loop
    }         // end if child
    return 0;
}
