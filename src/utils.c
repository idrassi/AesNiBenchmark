#include "utils.h"

#ifdef _WIN32
#include <psapi.h>

#pragma comment(lib, "Psapi.lib")

static void usage_to_timeval(FILETIME *ft, struct timeval *tv)
{
    ULARGE_INTEGER time;
    time.LowPart = ft->dwLowDateTime;
    time.HighPart = ft->dwHighDateTime;

    tv->tv_sec = (long) (time.QuadPart / 10000000);
    tv->tv_usec = (time.QuadPart % 10000000) / 10;
}

int
getrusage(int who, struct rusage *usage)
{
    FILETIME creation_time, exit_time, kernel_time, user_time;
    PROCESS_MEMORY_COUNTERS pmc;

    memset(usage, 0, sizeof(struct rusage));

    if (who == RUSAGE_SELF) {
        if (!GetProcessTimes(GetCurrentProcess(), &creation_time, &exit_time,
                             &kernel_time, &user_time)) {
            return -1;
        }

        if (!GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            return -1;
        }

        usage_to_timeval(&kernel_time, &usage->ru_stime);
        usage_to_timeval(&user_time, &usage->ru_utime);
        usage->ru_majflt = pmc.PageFaultCount;
        usage->ru_maxrss = (long) (pmc.PeakWorkingSetSize / 1024);
        return 0;
    } else if (who == RUSAGE_THREAD) {
        if (!GetThreadTimes(GetCurrentThread(), &creation_time, &exit_time,
                            &kernel_time, &user_time)) {
            return -1;
        }
        usage_to_timeval(&kernel_time, &usage->ru_stime);
        usage_to_timeval(&user_time, &usage->ru_utime);
        return 0;
    } else {
        return -1;
    }
}

void timersub(const struct timeval* tvp, const struct timeval* uvp, struct timeval* vvp)
{
  vvp->tv_sec = tvp->tv_sec - uvp->tv_sec;
  vvp->tv_usec = tvp->tv_usec - uvp->tv_usec;
  if (vvp->tv_usec < 0)
  {
     --vvp->tv_sec;
     vvp->tv_usec += 1000000;
  }
}

#endif

unsigned char HexCharToByte (char c)
{
   if (c >= ('0') && c <= ('9'))
      return c - ('0');
   else if (c >= ('A') && c <= ('F'))
      return c - ('A') + 10;
   else if (c >= ('a') && c <= ('f'))
      return c - ('a') + 10;
   else
      return 0xFF;
}

unsigned long HexStringToByteArray(const char* hexStr, unsigned char* pbData)
{
	unsigned long count = 0;
	while (*hexStr)
	{
		*pbData++ = (HexCharToByte(hexStr[0]) << 4) | HexCharToByte(hexStr[1]);
		hexStr += 2;
		count++;
	}
	return count;
}
