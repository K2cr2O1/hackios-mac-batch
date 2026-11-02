// SPDX-License-Identifier: BSD-2-Clause-Patent
// Bounded observation metadata. A skipped observation leaves the client alone.
#pragma once
#include <stddef.h>
#include <stdint.h>

template <class Observation, unsigned Capacity = 8, unsigned VtableSlots = 256>
class NabuDisplayClientRegistry {
    static_assert(Capacity > 0 && Capacity <= 128 && VtableSlots > 175, "Bounded valid client registry");
    struct RegistrationGuard {
        uint32_t *gate;
        bool acquired;
        explicit RegistrationGuard(uint32_t *value) : gate(value), acquired(false) {
            uint32_t expected = 0;
            acquired = __atomic_compare_exchange_n(gate, &expected, 1, false,
                __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
        }
        ~RegistrationGuard() {
            if (acquired) __atomic_store_n(gate, 0, __ATOMIC_RELEASE);
        }
    };
public:
    enum : unsigned { ExternalSlot = 168, RegisterSlot = 175 };
    struct Identity {
        uintptr_t object = 0, vtable = 0, original_external = 0, original_register = 0;
        int pid = 0;
        char name[20] = {};
    };
    struct Slot {
        // Immutable once count_ publishes this slot. No client is dereferenced
        // by a snapshot; the vtable identity also distinguishes address reuse.
        Identity identity;
        Observation observation = {};
        uint32_t observation_gate = 0;
        uint64_t observation_dropped = 0;

        template <class Record> bool observe(Record record) {
            RegistrationGuard guard(&observation_gate);
            if (!guard.acquired) {
                __atomic_fetch_add(&observation_dropped, 1, __ATOMIC_RELAXED);
                return false;
            }
            record(observation);
            return true;
        }
        bool snapshot(Observation &out) {
            RegistrationGuard guard(&observation_gate);
            if (!guard.acquired) return false;
            out = observation;
            return true;
        }
    };
    enum Result { Installed, AlreadyInstalled, Busy, Full, AllocationFailed, ChangedVtable };
    struct Summary {
        unsigned count;
        uint64_t busy, full, failed, duplicates;
    };
private:
    Slot slots_[Capacity] = {};
    uint32_t registration_gate_ = 0, count_ = 0;
    uint64_t busy_ = 0, full_ = 0, failed_ = 0, duplicates_ = 0;
public:
    unsigned count() const { return __atomic_load_n(&count_, __ATOMIC_ACQUIRE); }
    Slot *at(unsigned index) { return index < count() ? &slots_[index] : nullptr; }
    Summary summary() const {
        return {count(), __atomic_load_n(&busy_, __ATOMIC_RELAXED),
            __atomic_load_n(&full_, __ATOMIC_RELAXED), __atomic_load_n(&failed_, __ATOMIC_RELAXED),
            __atomic_load_n(&duplicates_, __ATOMIC_RELAXED)};
    }
    Slot *find(uintptr_t object) {
        if (!object) return nullptr;
        const uintptr_t vtable = reinterpret_cast<uintptr_t>(
            __atomic_load_n(reinterpret_cast<uintptr_t **>(object), __ATOMIC_ACQUIRE));
        const unsigned published = count();
        for (unsigned i = 0; i < published; ++i) {
            const Identity &identity = slots_[i].identity;
            if (identity.object == object && identity.vtable == vtable) return &slots_[i];
        }
        return nullptr;
    }
    template <class Allocate, class Free>
    Result install(uintptr_t object, int pid, const char *name, uintptr_t external,
        uintptr_t notification, Allocate allocate, Free free) {
        RegistrationGuard guard(&registration_gate_);
        if (!guard.acquired) {
            __atomic_fetch_add(&busy_, 1, __ATOMIC_RELAXED);
            return Busy;
        }
        if (find(object)) {
            __atomic_fetch_add(&duplicates_, 1, __ATOMIC_RELAXED);
            return AlreadyInstalled;
        }
        const unsigned index = count();
        if (index == Capacity) {
            __atomic_fetch_add(&full_, 1, __ATOMIC_RELAXED);
            return Full;
        }
        uintptr_t *original = object ?
            __atomic_load_n(reinterpret_cast<uintptr_t **>(object), __ATOMIC_ACQUIRE) : nullptr;
        if (!original || !original[ExternalSlot] || !original[RegisterSlot] ||
            original[ExternalSlot] == external || original[RegisterSlot] == notification) {
            __atomic_fetch_add(&failed_, 1, __ATOMIC_RELAXED);
            return ChangedVtable;
        }
        const size_t bytes = VtableSlots * sizeof(uintptr_t);
        uintptr_t *copy = static_cast<uintptr_t *>(allocate(bytes));
        if (!copy) {
            __atomic_fetch_add(&failed_, 1, __ATOMIC_RELAXED);
            return AllocationFailed;
        }
        for (unsigned i = 0; i < VtableSlots; ++i) copy[i] = original[i];
        if (__atomic_load_n(reinterpret_cast<uintptr_t **>(object), __ATOMIC_ACQUIRE) != original) {
            free(copy, bytes);
            __atomic_fetch_add(&failed_, 1, __ATOMIC_RELAXED);
            return ChangedVtable;
        }
        Slot &slot = slots_[index];
        slot.identity.object = object;
        slot.identity.vtable = reinterpret_cast<uintptr_t>(copy);
        slot.identity.original_external = copy[ExternalSlot];
        slot.identity.original_register = copy[RegisterSlot];
        slot.identity.pid = pid;
        if (name) {
            for (unsigned i = 0; i + 1 < sizeof(slot.identity.name) && name[i]; ++i)
                slot.identity.name[i] = name[i];
        }
        copy[ExternalSlot] = external;
        copy[RegisterSlot] = notification;
        // A wrapper can become callable only after its complete metadata is
        // published. The immutable slot is never reused, even after client free.
        __atomic_store_n(&count_, index + 1, __ATOMIC_RELEASE);
        __atomic_store_n(reinterpret_cast<uintptr_t **>(object), copy, __ATOMIC_RELEASE);
        return Installed;
    }
};
