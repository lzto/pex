/*
 * Simple Stop Watch
 * how fast does your code run?
 * 2017-2018 Tong Zhang<ztong@vt.edu>
 */

#ifndef _STOP_WATCH_
#define _STOP_WATCH_

#include <sys/time.h>
#include <sys/types.h>

#define USE_STOP_WATCH 1

#if USE_STOP_WATCH
/*
 * put STOP_WATCH right after including "stopwatch.h"
 * X - number of stop watch you want to use
 * Y,Z - watch id
 */
#define STOP_WATCH(X)                                                          \
  static struct timeval _sw_time_start[X];                                     \
  static struct timeval _sw_time_end[X];

#define STOP_WATCH_START(Y) gettimeofday(&_sw_time_start[Y], NULL);

#define STOP_WATCH_STOP(Y) gettimeofday(&_sw_time_end[Y], NULL);

#define STOP_WATCH_REPORT(Z)                                                   \
  {                                                                            \
    double speed =                                                             \
        (double)(_sw_time_end[Z].tv_sec - _sw_time_start[Z].tv_sec) * 1000.0 + \
        (_sw_time_end[Z].tv_usec - _sw_time_start[Z].tv_usec) / 1000.0;        \
    fprintf(stderr, "STOP WATCH[%d]: %f ms\n", Z, speed);                      \
    fflush(stderr);                                                            \
  }

#define STOP_WATCH_MON(WATCH_ID, CODE)                                         \
  STOP_WATCH_START(WATCH_ID)                                                   \
  do {                                                                         \
    CODE;                                                                      \
  } while (0);                                                                 \
  STOP_WATCH_STOP(WATCH_ID)                                                    \
  STOP_WATCH_REPORT(WATCH_ID)

#else

#define STOP_WATCH(X)
#define STOP_WATCH_START(Y)
#define STOP_WATCH_STOP(Y)
#define STOP_WATCH_REPORT(Z)
#define STOP_WATCH_MON(WATCH_ID, CODE)                                         \
  do {                                                                         \
    CODE;                                                                      \
  } while (0);

#endif

#endif //_STOP_WATCH_
