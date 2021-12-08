#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <netinet/in.h>

#ifdef EXPERIMENTAL
#include <sys/resource.h>
#endif

#include "helpers.h"

#define PORT 8080
#define BFSZ 1400

static long port = PORT;

static char httpStatus200[] = "HTTP/1.1 200 OK\r\n\r\n";
static char httpStatus403[] = "HTTP/1.1 403 Forbidden\r\n\r\n";
static char httpStatus404[] = "HTTP/1.1 404 Not Found\r\n\r\n";
static char httpStatus500[] = "HTTP/1.1 500 Internal Server Error\r\n\r\n";

static char www_dir[PATH_MAX] = "./";

#define VALSZ 128
struct
{
    char content_type[VALSZ];
    char boundary[VALSZ];
    size_t content_length;
} ReqHeader = {
    .boundary = "--",
};

#define KiB (1 << 10)
#define MiB (1 << 20)
#define GiB (1 << 30)

int main(int argc, char const **argv)
{
    SET_FLAGS(argc, argv);
    if (!chdir(www_dir))
        VERBOSE(NL"work dir set to %s"NL, www_dir);

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

    signal(SIGCHLD, SIG_IGN);

    struct timeval tv1 = {0}, tv2 = {0};
    struct stat stats = {0};
    DIR *d = NULL;
    struct dirent *dir = NULL;

    struct pollfd fds;

    while (1)
    {
        conn_fd = accept(server_fd, NULL, NULL);
        CHKRES(conn_fd, "accept error");

        gettimeofday(&tv1, NULL);
        FILE *f_recv = fdopen(conn_fd, "rb");
        FILE *f_send = fdopen(dup(conn_fd), "wb");

        fds.fd = conn_fd;
        fds.events = POLLIN;

        /*
         * ONLY WORKS WITH EXPERIMENTAL FLAG
         * SETS STACK SIZE OF FORKED CHILD TO 16 KiB.
         * IN CASE OF FAULTS OR BROKEN PAGES, REMOVE IT!
        */
        #ifdef EXPERIMENTAL
        CHKRES(setrlimit(RLIMIT_STACK,
                         &(struct rlimit){.rlim_max = 16384,
                                          .rlim_cur = 16384}),
               "setrlimit error");
        #endif

        if (!fork()) // child
        {
            char buf[BFSZ] = {0}; 
            {
                if (!poll(&fds, 1, 10 * 1000))
                    exit(EXIT_FAILURE);

                if (fgets(buf, BFSZ, f_recv) == NULL)
                    exit(EXIT_FAILURE);

                char *route = NULL; /* part after METHOD (GET, POST, ...) */
                int should_parse = 0, n = 0;
                if (buf[0] == 'G' &&
                    buf[1] == 'E' &&
                    buf[2] == 'T')
                {
                    should_parse = 1, n = 3;
                    printf("%s\n", buf);
                    VERBOSE("Method:\tGET\n");
                }
                else if (buf[0] == 'P' &&
                         buf[1] == 'O' &&
                         buf[2] == 'S' &&
                         buf[3] == 'T')
                {
                    should_parse = 1, n = 4;
                    printf("%s\n", buf);
                    VERBOSE("Method:\tPOST\n");
                }
                if (should_parse)
                {
                    if (buf[n++] == ' ')
                    {
                        if (buf[n] != '/')
                            exit(EXIT_FAILURE);
                        route = &buf[n];
                    }
                    else
                        exit(EXIT_FAILURE);

                    route[strcspn(route, " ")] = '\0';

                    if (strstr(route, "../") != NULL ||
                        strstr(route, "/..") != NULL)
                        exit(EXIT_FAILURE); // back path-traversal prevention
                    VERBOSE("Route :\t%s\n", route);

                    /* '\0' and '.' at beginning; 13 to fit './index.html' */
                    int sz = (strlen(route) + 2) >= 13 ? strlen(route) + 2 : 13;
                    char routecp[sz];
                    {
                        char decoded_routecp[sz];
                        memset(routecp, 0, sizeof(routecp));
                        memset(decoded_routecp, 0, sizeof(routecp));
                        strncpy(routecp + 1, route, strlen(route));
                        routecp[0] = '.';
                        if (!strcmp(routecp, "./"))
                            strncpy(routecp, "./index.html", 13);

                        decode(routecp, decoded_routecp) < 0
                            ? memcpy(routecp, "./index.html", 13)
                            : memcpy(routecp, decoded_routecp, sizeof(routecp));
                    }

                    if (access(routecp, F_OK) == 0)
                    {
                        stat(routecp, &stats);
                        if (S_ISDIR(stats.st_mode))
                        {
                            d = opendir(routecp);
                            if (d)
                            {
                                fprintf(f_send, "%s", httpStatus200);
                                fprintf(f_send, "<!DOCTYPE html><h1 style=\"font-family:sans-serif;padding:1em;border-bottom:5px solid;\">%s</h1>\r\n", routecp);

                                while ((dir = readdir(d)) != NULL)
                                {
                                    if (dir->d_name[0] == '.' &&
                                        (dir->d_name[1] == '.' || dir->d_name[1] == '\0'))
                                        continue;
                                    fprintf(f_send, "<a style=\"font-family:sans-serif;padding:1em;display:inline-block;border-bottom:5px solid;\""
                                                    "href=\"/%s/%s\">%s</a>\n",
                                            routecp, dir->d_name, dir->d_name);
                                }
                                /* for 'CLEANER' EXIT */
                                #ifndef EXPERIMENTAL
                                fflush(f_send);
                                closedir(d);
                                d = NULL;
                                dir = NULL;
                                #endif
                                exit(EXIT_SUCCESS);
                            }
                        }

                        // #ifdef EXPERIMENTAL
                        if(n == 5) // POST
                        {
                            int offset = 0;
                            char  * ptr = NULL;
                            while (fgets(buf, BFSZ, f_recv) != NULL)
                            {
                                ptr = buf;
                                if (offset = 14, !strncmp(buf, "Content-Type: ", offset))
                                {
                                    ptr = buf + offset;
                                    int sep = strcspn(ptr, " ");
                                    strncpy(ReqHeader.content_type, ptr, (sep < VALSZ) ? sep : VALSZ);
                                    ;
                                    if((ptr = strstr(ptr, "boundary"))!=NULL)
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
                            char* bodyBuf = NULL;
                            if ((bodyBuf = malloc(bodyBufSize)) == NULL)
                            {
                                fprintf(f_send, "%s", httpStatus500);
                                exit(EXIT_FAILURE);
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
                                if(len > bodyBufSize)
                                    exit(EXIT_FAILURE);
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
                        // #endif

                        VERBOSE("%s\n", routecp);
                        FILE *fp = fopen(routecp, "rb");
                        if (fp != NULL)
                        {
                            fseek(fp, 0, SEEK_END);
                            size_t fileSize = ftell(fp);
                            rewind(fp);

                            fprintf(f_send, "%s", httpStatus200);

                            void *fileBuf = NULL;
                            fileBuf = malloc(fileSize);
                            int n = fread(fileBuf, 1, fileSize, fp);
                            fwrite(fileBuf, 1, n, f_send);
                            fflush(f_send);
                            gettimeofday(&tv2, NULL);

                            VERBOSE("Size :\t%zu KiB\n", fileSize / (1 << 10));
                            VERBOSE("Handle time = %f seconds\n\n",
                                    (double)(tv2.tv_usec - tv1.tv_usec) / 1000000 +
                                        (double)(tv2.tv_sec - tv1.tv_sec));
                            
                            /* for 'CLEANER' EXIT */
                            #ifndef EXPERIMENTAL            
                            fclose(fp);
                            free(fileBuf);
                            #endif
                            exit(EXIT_SUCCESS);
                        }
                        else
                        {
                            perror("fopen");
                            fprintf(f_send, "%s"
                                            "<!DOCTYPE html><h2 style=\"font-family:sans-serif;\">Access denied</h2>\r\n",
                                    httpStatus403);
                            exit(EXIT_FAILURE);
                        }
                    }
                    else
                    {
                        VERBOSE("%s does not exist\n\n", routecp);
                        fprintf(f_send, "%s"
                                        "<!DOCTYPE html><h2 style=\"font-family:sans-serif;\">%s does not exist</h2>\r\n",
                                httpStatus404,
                                routecp);
                        exit(EXIT_SUCCESS);
                    }
                }
            }
            #ifdef DEBUG
            fwrite(buf, 1, BFSZ, f_send);
            #endif
            exit(EXIT_SUCCESS);
        } // end child
        fclose(f_recv);
        fclose(f_send);
        close(conn_fd);
    } // main loop
    return 0;
}
