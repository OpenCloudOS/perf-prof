#ifndef __LOCALTIME_H
#define __LOCALTIME_H

#include <time.h>
void nolocks_localtime(struct tm *tmp, time_t t, time_t tz, int dst);

#endif

