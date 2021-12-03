#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#ifdef DEBUG
#define VERBOSE(...) printf(__VA_ARGS__)
#else
#define VERBOSE(...)
#endif

#define CHKRES(res, msg)        \
    {                           \
        if ((res) == -1)        \
        {                       \
            perror(msg);        \
            exit(EXIT_FAILURE); \
        }                       \
    }

#define PORT 8080
#define BFSZ 1400

int main(int argc, char const **argv)
{
    int server_fd = 0, conn_fd = 0, valread = 0;
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(PORT),
    };

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    CHKRES(server_fd, "socket error");

    CHKRES(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)), "setsockopt error");

    CHKRES(bind(server_fd, (struct sockaddr *)&address, sizeof(address)), "bind error");
    CHKRES(listen(server_fd, 0), "listen error");

    signal(SIGCHLD, SIG_IGN);

    struct timeval tv1, tv2;

    while (1)
    {
        conn_fd = accept(server_fd, NULL, NULL);
        CHKRES(conn_fd, "accept error");

        gettimeofday(&tv1, NULL);
        FILE *f_recv = fdopen(dup(conn_fd), "rb");
        FILE *f_send = fdopen(dup(conn_fd), "wb");

        if (!fork()) // child
        {
            char buf[BFSZ] = {0};
            void *fileBuf = NULL;
            {
                if (fgets(buf, BFSZ, f_recv) == NULL)
                    exit(EXIT_FAILURE);

                if (buf[0] == 'G' &&
                    buf[1] == 'E' &&
                    buf[2] == 'T')
                {
                    VERBOSE("Method:\tGET\n");
                    char *route = NULL; /* part after GET */
                    if (buf[3] == ' ')
                    {
                        if (buf[4] != '/')
                            exit(EXIT_FAILURE);
                        route = &buf[4];
                    }
                    else
                        exit(EXIT_FAILURE);

                    route[strcspn(route, " ")] = '\0';

                    if (strstr(route, "../") != NULL)
                        exit(EXIT_FAILURE); // back path-traversal prevention
                    VERBOSE("Route :\t%s\n", route);

                    /* '\0' and '.' at beginning; 13 to fit './index.html' */
                    char routecp[(strlen(route) + 2) >= 13 ? strlen(route) + 2 : 13];
                    memset(routecp, 0, sizeof(routecp));
                    strncpy(routecp + 1, route, strlen(route));
                    routecp[0] = '.';
                    if (!strcmp(routecp, "./"))
                        strncpy(routecp, "./index.html", 13);

                    if (access(routecp, F_OK) == 0)
                    {
                        VERBOSE("%s\n", routecp);
                        FILE *fp = fopen(routecp, "rb");
                        if (fp != NULL)
                        {
                            fseek(fp, 0, SEEK_END);
                            size_t fileSize = ftell(fp);
                            rewind(fp);

                            static char httpStatus200[] = "HTTP/1.1 200 OK\r\n\r\n";
                            fprintf(f_send, "%s", httpStatus200);

                            fileBuf = malloc(fileSize);
                            int n = fread(fileBuf, 1, fileSize, fp);
                            fwrite(fileBuf, 1, n, f_send);
                            fflush(f_send);
                            gettimeofday(&tv2, NULL);

                            VERBOSE("Size :\t%zu KiB\n", fileSize / (1 << 10));
                            VERBOSE("Handle time = %f seconds\n\n",
                                   (double)(tv2.tv_usec - tv1.tv_usec) / 1000000 +
                                       (double)(tv2.tv_sec - tv1.tv_sec));
                            fclose(fp);
                            free(fileBuf);
                            exit(EXIT_SUCCESS);
                        }
                    }
                    else
                    {
                        VERBOSE("%s does not exist\n\n", routecp);
                        fprintf(f_send, "HTTP/1.1 404\r\n\r\n"
                                        "<h2 style=\"font-family:sans-serif;\">%s does not exist</h2>\r\n",
                                routecp);
                        exit(EXIT_SUCCESS);
                    }
                }
            }
            fwrite(buf, 1, BFSZ, f_send);
            exit(EXIT_SUCCESS);
        } // end child
        fclose(f_recv);
        fclose(f_send);
        close(conn_fd);
    } // main loop
    return 0;
}
