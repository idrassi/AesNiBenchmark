#pragma once

#ifdef _WIN32
#include <Windows.h>
#include <errno.h>
#include <malloc.h>
#include <time.h>

#define posix_memalign(p, a, s) (((*(p)) = _aligned_malloc((s), (a))), *(p) ?0 :errno)

// from: https://github.com/openvswitch/ovs

#ifndef RUSAGE_SELF
#define RUSAGE_SELF 1
#endif

#ifndef RUSAGE_CHILDREN
#define RUSAGE_CHILDREN 2
#endif

#ifndef RUSAGE_THREAD
#define RUSAGE_THREAD 3
#endif

#if defined(__cplusplus)
extern "C"
{
#endif

struct rusage {
    struct timeval ru_utime; /* user CPU time used */
    struct timeval ru_stime; /* system CPU time used */
    long   ru_maxrss;        /* maximum resident set size */
    long   ru_ixrss;         /* integral shared memory size */
    long   ru_idrss;         /* integral unshared data size */
    long   ru_isrss;         /* integral unshared stack size */
    long   ru_minflt;        /* page reclaims (soft page faults) */
    long   ru_majflt;        /* page faults (hard page faults) */
    long   ru_nswap;         /* swaps */
    long   ru_inblock;       /* block input operations */
    long   ru_oublock;       /* block output operations */
    long   ru_msgsnd;        /* IPC messages sent */
    long   ru_msgrcv;        /* IPC messages received */
    long   ru_nsignals;      /* signals received */
    long   ru_nvcsw;         /* voluntary context switches */
    long   ru_nivcsw;        /* involuntary context switches */
};

int getrusage(int who, struct rusage *usage);

void timersub(const struct timeval* tvp, const struct timeval* uvp, struct timeval* vvp);

#if defined(__cplusplus)
}
#endif

#else
#include <err.h>
#include <stdint.h>
#include <sysexits.h>
#include <unistd.h>

/* For benchmarking */
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#endif

#if defined(__cplusplus)
extern "C"
{
#endif

unsigned char HexCharToByte (char c);
unsigned long HexStringToByteArray(const char* hexStr, unsigned char* pbData);

#if defined(__cplusplus)
}
#endif