/*
 * Simple Stop Watch
 * how fast does your code run?
 * 2017 Tong Zhang<ztong@vt.edu>
 */

#ifndef _STOP_WATCH_
#define _STOP_WATCH_

#include <sys/time.h>
#include <sys/types.h>

#define USE_STOP_WATCH 0

#if USE_STOP_WATCH
/*
 * put STOP_WATH right after including "stopwatch.h"
 */
#define STOP_WATCH \
static struct timeval _sw_time_start; \
static struct timeval _sw_time_end;

#define STOP_WATCH_START \
    gettimeofday(&_sw_time_start, NULL);

#define STOP_WATCH_STOP \
    gettimeofday(&_sw_time_end, NULL);

#define STOP_WATCH_REPORT \
{ \
    double speed = (double)(_sw_time_end.tv_sec - _sw_time_start.tv_sec)*1000.0+ \
        (_sw_time_end.tv_usec-_sw_time_start.tv_usec)/1000.0; \
    printf("STOP WATCH: %f ms\n", speed); \
}

#else

#define STOP_WATCH
#define STOP_WATCH_START
#define STOP_WATCH_STOP
#define STOP_WATCH_REPORT

#endif

#endif //_STOP_WATCH_

