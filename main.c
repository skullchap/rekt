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

static char httpStatus200[] = "HTTP/1.1 200 OK\r\n\r\n";
static char httpStatus404[] = "HTTP/1.1 404 Not Found\r\n\r\n";

static char www_dir[PATH_MAX] = "./";

#define SET_FLAGS(ARGC, ARGV)                                       \
    {                                                               \
        int flag = 0;                                               \
        for (int i = 1; i < ARGC; ++i)                              \
        {                                                           \
            switch (flag)                                           \
            {                                                       \
            case 0:                                                 \
                if (ARGV[i][0] == '-')                              \
                    flag = ARGV[i][1];                              \
                break;                                              \
            case 'd':                                               \
                strncpy(www_dir + 2, ARGV[i], strlen(ARGV[i]) + 1); \
                if (strstr(www_dir, "../") != NULL ||               \
                    strstr(www_dir, "/..") != NULL)                 \
                    www_dir[2] = '\0';                              \
                flag = 0;                                           \
                break;                                              \
            default:                                                \
                flag = 0;                                           \
            }                                                       \
        }                                                           \
    }

int main(int argc, char const **argv)
{
    SET_FLAGS(argc, argv);
    if (!chdir(www_dir))
        VERBOSE("\nwork dir set to %s\n\n", www_dir);

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

                valread = read(conn_fd, buf, BFSZ);
                CHKRES(valread, "read error");

                if (buf[0] == 'G' &&
                    buf[1] == 'E' &&
                    buf[2] == 'T')
                {
                    printf("%s\n", buf);

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

                    if (strstr(route, "../") != NULL ||
                        strstr(route, "/..") != NULL)
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
                        stat(routecp, &stats);
                        if (S_ISDIR(stats.st_mode))
                        {
                            d = opendir(routecp);
                            if (d)
                            {
                                fprintf(f_send, "%s", httpStatus200);
                                fprintf(f_send, "<h1 style=\"font-family:sans-serif;padding:1em;border-bottom:5px solid;\">%s</h1>\r\n", routecp);

                                while ((dir = readdir(d)) != NULL)
                                {
                                    if (dir->d_name[0] == '.' &&
                                        (dir->d_name[1] == '.' || dir->d_name[1] == '\0'))
                                        continue;
                                    fprintf(f_send, "<a style=\"font-family:sans-serif;padding:1em;border-bottom:5px solid;\""
                                                    "href=\"/%s/%s\">%s</a>\n",
                                            routecp, dir->d_name, dir->d_name);
                                }
                                /* for 'CLEANER' EXIT */
                                #ifdef EXPERIMENTAL
                                fflush(f_send);
                                closedir(d);
                                d = NULL;
                                dir = NULL;
                                #endif
                                exit(EXIT_SUCCESS);
                            }
                        }

                        VERBOSE("%s\n", routecp);
                        FILE *fp = fopen(routecp, "rb");
                        if (fp != NULL)
                        {
                            fseek(fp, 0, SEEK_END);
                            size_t fileSize = ftell(fp);
                            rewind(fp);

                            fprintf(f_send, "%s", httpStatus200);

                            void *fileBuf = NULL;
                            // (fileSize > BFSZ) ? fileBuf = malloc(fileSize) : (fileBuf = buf);
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
                            #ifdef EXPERIMENTAL            
                            fclose(fp);
                            free(fileBuf);
                            #endif
                            exit(EXIT_SUCCESS);
                        }
                    }
                    else
                    {
                        VERBOSE("%s does not exist\n\n", routecp);
                        fprintf(f_send, "%s"
                                        "<h2 style=\"font-family:sans-serif;\">%s does not exist</h2>\r\n",
                                httpStatus404,
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
