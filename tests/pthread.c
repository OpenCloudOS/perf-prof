#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <getopt.h>

void *depth = NULL;

void *threadFunc(void *arg) {
    pthread_t threads;
    int n = 1000;

    if ((rand()%100) < 30)
        while(n--) usleep(10);

    usleep(rand()%1000000);
    if (arg < depth)
        pthread_create(&threads, NULL, threadFunc, ++arg);

    return NULL;
}

int main(int argc, char *argv[]) {
    int daemonize = 0;
    int loop_n = 50;
    int sleep_us = 200000;
    int opt, option_index = 0;
    pthread_t threads;
    static struct option long_options[] = {
        {"daemonize", no_argument, 0, 'd'},
        {"loop", required_argument, 0, 'l'},
        {"usleep", required_argument, 0, 's'},
		{"depth", required_argument, 0, 'p'},
        {0, 0, 0, 0}
    };
    while ((opt = getopt_long(argc, argv, "dl:s:p:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'd':
                daemonize = 1;
                break;
            case 'l':
                loop_n = atoi(optarg);
                break;
            case 's':
                sleep_us = atoi(optarg);
                break;
            case 'p':
                depth += atoi(optarg);
                break;
            case '?':
            default:
                fprintf(stderr, "Usage: %s [-d|--daemonize] [-l|--loop loop] [-s|--usleep usleep] [-p|--depth depth]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (daemonize)
        daemon(1,0);

    while (loop_n --) {
        pthread_create(&threads, NULL, threadFunc, NULL);
        usleep(sleep_us);
    }
	return 0;
}
