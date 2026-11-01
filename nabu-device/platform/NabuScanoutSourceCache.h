// SPDX-License-Identifier: MIT
// Slot identities come from the kernel's boot-lifetime, non-evicting source maps.
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace nabu_scanout {

class SourceCache {
public:
    enum { Slots = 8 };
    enum Match { Invalid, Empty, Same };

    Match match(uint32_t slot, const void *address, size_t bytes) const {
        if (!slot || slot > Slots || !address || !bytes || bytes > MaxBytes ||
            (reinterpret_cast<uintptr_t>(address) & 4095) || (bytes & 4095)) return Invalid;
        const Key &key = keys_[slot - 1];
        if (!key.address) return Empty;
        return key.address == address && key.bytes == bytes ? Same : Invalid;
    }

    bool imported(uint32_t slot, const void *address, size_t bytes) {
        if (match(slot, address, bytes) != Empty) return false;
        keys_[slot - 1] = {address, bytes};
        ++imports_;
        return true;
    }

    bool reused(uint32_t slot, const void *address, size_t bytes) {
        if (match(slot, address, bytes) != Same) return false;
        ++hits_;
        return true;
    }

    uint64_t imports() const { return imports_; }
    uint64_t hits() const { return hits_; }

private:
    static constexpr size_t MaxBytes = 32u * 1024u * 1024u;
    struct Key { const void *address; size_t bytes; };
    Key keys_[Slots] = {};
    uint64_t imports_ = 0, hits_ = 0;
};

} // namespace nabu_scanout
