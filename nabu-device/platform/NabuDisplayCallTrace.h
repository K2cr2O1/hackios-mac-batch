// SPDX-License-Identifier: BSD-2-Clause-Patent
// Caller-owned entry/return observations; no lock spans the observed method.
#pragma once
#include <stdint.h>

class NabuDisplayCallTrace {
public:
    enum : unsigned { Capacity = 16, Selectors = 3 };
    struct Input {
        uint64_t sequence = 0, tid = 0, started_us = 0, scalars[3] = {}, structure_bytes = 0;
        int pid = 0;
        uint32_t selector = 0, scalar_count = 0, async_refs = 0, async_port = 0;
    };
    struct Entry {
        Input input;
        uint64_t ended_us = 0;
        uint32_t state = 0, result = 0;
    };
    struct Snapshot {
        Entry entries[Capacity] = {};
        uint64_t entered[Selectors] = {}, returned[Selectors] = {}, dropped = 0;
        unsigned active = 0, count = 0;
    };
    struct Lease {
        uint64_t sequence = 0;
        int slot = -1, operation = -1;
    };
private:
    struct Record {
        Input input;
        uint64_t ended_us = 0;
        uint32_t state = 0, result = 0;
    };
    Record records_[Capacity] = {};
    uint64_t entered_[Selectors] = {}, returned_[Selectors] = {}, dropped_ = 0, next_ = 0;
    uint32_t gate_ = 0, enabled_ = 0, cursor_ = 0;
    bool tryLock() {
        uint32_t expected = 0;
        return __atomic_compare_exchange_n(&gate_, &expected, 1, false,
            __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
    }
    void unlock() { __atomic_store_n(&gate_, 0, __ATOMIC_RELEASE); }
public:
    void enable() { __atomic_store_n(&enabled_, 1, __ATOMIC_RELEASE); }
    bool enabled() const { return __atomic_load_n(&enabled_, __ATOMIC_ACQUIRE) != 0; }
    Lease begin(Input input) {
        Lease lease;
        if (!enabled() || input.selector < 4 || input.selector > 6) return lease;
        lease.operation = int(input.selector - 4);
        __atomic_fetch_add(&entered_[lease.operation], 1, __ATOMIC_RELAXED);
        if (!tryLock()) {
            __atomic_fetch_add(&dropped_, 1, __ATOMIC_RELAXED);
            return lease;
        }
        for (unsigned i = 0; i < Capacity; ++i) {
            const unsigned index = (cursor_ + i) % Capacity;
            Record &record = records_[index];
            if (__atomic_load_n(&record.state, __ATOMIC_ACQUIRE) == 1) continue;
            input.sequence = ++next_;
            record.input = input;
            __atomic_store_n(&record.ended_us, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&record.result, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&record.state, 1, __ATOMIC_RELEASE);
            cursor_ = (index + 1) % Capacity;
            lease.sequence = input.sequence;
            lease.slot = int(index);
            break;
        }
        if (lease.slot < 0) __atomic_fetch_add(&dropped_, 1, __ATOMIC_RELAXED);
        unlock();
        return lease;
    }
    void finish(Lease &lease, uint64_t ended_us, uint32_t result) {
        if (lease.operation < 0) return;
        __atomic_fetch_add(&returned_[lease.operation], 1, __ATOMIC_RELAXED);
        if (lease.slot >= 0) {
            // This record remains active until this caller publishes its return.
            // A snapshot excludes reuse with gate_, but never holds up finish.
            Record &record = records_[lease.slot];
            __atomic_store_n(&record.ended_us, ended_us, __ATOMIC_RELAXED);
            __atomic_store_n(&record.result, result, __ATOMIC_RELAXED);
            __atomic_store_n(&record.state, 2, __ATOMIC_RELEASE);
        }
        lease.operation = -1;
        lease.slot = -1;
    }
    bool snapshot(Snapshot &out) {
        out = Snapshot{};
        for (unsigned i = 0; i < Selectors; ++i) {
            out.entered[i] = __atomic_load_n(&entered_[i], __ATOMIC_RELAXED);
            out.returned[i] = __atomic_load_n(&returned_[i], __ATOMIC_RELAXED);
        }
        out.dropped = __atomic_load_n(&dropped_, __ATOMIC_RELAXED);
        if (!tryLock()) return false;
        for (unsigned i = 0; i < Capacity; ++i) {
            const Record &record = records_[i];
            const uint32_t state = __atomic_load_n(&record.state, __ATOMIC_ACQUIRE);
            if (!state) continue;
            Entry &entry = out.entries[out.count++];
            entry.input = record.input;
            entry.state = state;
            if (state == 1) ++out.active;
            else {
                entry.ended_us = __atomic_load_n(&record.ended_us, __ATOMIC_RELAXED);
                entry.result = __atomic_load_n(&record.result, __ATOMIC_RELAXED);
            }
        }
        unlock();
        return true;
    }
};
