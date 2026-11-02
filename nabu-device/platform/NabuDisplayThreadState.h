// SPDX-License-Identifier: BSD-2-Clause-Patent
// Same 23.6 XNU thread-state flags used by the qualified osfmk UI sampler.
#pragma once
#include <stdint.h>

enum : uint32_t {
    NabuThreadWait = 0x01,
    NabuThreadRun = 0x04,
    NabuThreadUninterruptible = 0x08,
    NabuThreadTerminate = 0x10,
    NabuThreadTerminate2 = 0x20
};

static inline bool nabu_display_thread_terminated(uint32_t state) {
    return (state & (NabuThreadTerminate | NabuThreadTerminate2)) != 0;
}
