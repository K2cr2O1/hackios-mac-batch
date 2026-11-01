// SPDX-License-Identifier: MIT
// Per-process problem sender for nabu's immediate, bounded RAM capture channel.
#pragma once
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <pthread.h>

namespace nabuproblem {
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static std::atomic<unsigned> reports{0},exceptions{0};
static unsigned event;
template<class Marker>
static void send(Marker mark,const char *text,bool exception=false) {
    if(!text)return;
    auto &quota=exception?exceptions:reports;
    if(quota.fetch_add(1,std::memory_order_relaxed)>=(exception?1u:8u))return;
    pthread_mutex_lock(&lock);
    const unsigned id=++event;
    // At most 512 chars per event, 52 per line. An explicit terminator captures
    // each line now instead of hoping a ten-second diagnostic sample sees it.
    const size_t bytes=strnlen(text,512);
    for(size_t at=0;at<bytes;at+=52) {
        char line[64];
        const unsigned count=unsigned(bytes-at>52?52:bytes-at);
        std::snprintf(line,sizeof(line),"E%u/%u %.*s",id,unsigned(at/52),int(count),text+at);
        mark(0x6d00);
        for(unsigned i=0;i<sizeof(line)-1 && line[i];++i) {
            unsigned char ch=static_cast<unsigned char>(line[i]);
            mark(0x6d00u|(ch>=32 && ch<127?ch:static_cast<unsigned char>('_')));
        }
        mark(0x6dff);
    }
    pthread_mutex_unlock(&lock);
}
}
