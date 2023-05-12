#include <iostream>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define TRIM ((1800.0L * 1000 * 1000) / 1800062914)

static inline uint64_t read_time_stamp_ctr()
{
    uint32_t __a, __d;
    __asm__ __volatile__("rdtsc"
                         : "=a"(__a), "=d"(__d));
    return static_cast<uint64_t>(__a) | (static_cast<uint64_t>(__d) << 32ULL);
}

int volatile alarmsig = 0;
static void sigalarm(int i)
{
    alarmsig = 1;
    std::cout << "Got signal " << i << "\n";
}

int main()
{
    puts("measure TSC freq");
    signal(SIGALRM, sigalarm);
    alarmsig = 0;
    int i = 0;
    uint64_t t1 = read_time_stamp_ctr();
    alarm(1);
    do {
        ++i;
    } while (!alarmsig);
    uint64_t t2 = read_time_stamp_ctr() - t1;
    std::cout << "tsc frequency = " << std::fixed << TRIM * static_cast<double>(t2) / 1 << " Hz" << std::endl;
    return i;
}
