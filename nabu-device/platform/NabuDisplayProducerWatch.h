// SPDX-License-Identifier: BSD-2-Clause-Patent
// First four actual presentation callers, retained until this boot ends.
#pragma once
#include <stdint.h>

class NabuDisplayProducerWatch {
public:
    enum : unsigned { Capacity = 4 };
    struct Caller {
        uintptr_t thread = 0;
        uint64_t tid = 0, uniqueid = 0;
        int pid = 0;
    };
    struct Snapshot {
        Caller callers[Capacity] = {};
        unsigned count = 0;
        uint64_t busy = 0, full = 0;
    };
private:
    Caller callers_[Capacity] = {};
    uint32_t count_ = 0, gate_ = 0;
    uint64_t busy_ = 0, full_ = 0;
public:
    template <class Retain> bool record(Caller caller, Retain retain) {
        if (!caller.thread || !caller.tid || !caller.uniqueid || caller.pid <= 0) return false;
        uint32_t expected = 0;
        if (!__atomic_compare_exchange_n(&gate_, &expected, 1, false,
                __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            __atomic_fetch_add(&busy_, 1, __ATOMIC_RELAXED);
            return false;
        }
        unsigned count = __atomic_load_n(&count_, __ATOMIC_RELAXED);
        for (unsigned i = 0; i < count; ++i) {
            if (callers_[i].thread == caller.thread && callers_[i].tid == caller.tid &&
                    callers_[i].uniqueid == caller.uniqueid && callers_[i].pid == caller.pid) {
                __atomic_store_n(&gate_, 0, __ATOMIC_RELEASE);
                return true;
            }
        }
        if (count == Capacity) {
            __atomic_fetch_add(&full_, 1, __ATOMIC_RELAXED);
            __atomic_store_n(&gate_, 0, __ATOMIC_RELEASE);
            return false;
        }
        // The callback only retains the current thread while its syscall is live.
        // Metadata is immutable once count_ publishes it; snapshots take no refs.
        retain(caller.thread);
        callers_[count] = caller;
        __atomic_store_n(&count_, count + 1, __ATOMIC_RELEASE);
        __atomic_store_n(&gate_, 0, __ATOMIC_RELEASE);
        return true;
    }
    Snapshot snapshot() const {
        Snapshot result;
        result.count = __atomic_load_n(&count_, __ATOMIC_ACQUIRE);
        result.busy = __atomic_load_n(&busy_, __ATOMIC_RELAXED);
        result.full = __atomic_load_n(&full_, __ATOMIC_RELAXED);
        for (unsigned i = 0; i < result.count; ++i) result.callers[i] = callers_[i];
        return result;
    }
};
