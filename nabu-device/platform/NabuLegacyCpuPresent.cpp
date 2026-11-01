// SPDX-License-Identifier: BSD-2-Clause-Patent
// Legacy presentation with an opt-in GPU blit hand-off and the verified CPU fallback.
#include "OriginalLegacyFramebufferABI.h"
#include "NabuLegacyCpuPixels.h"
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <IOKit/pwr_mgt/IOPMpowerState.h>
#include <libkern/c++/OSData.h>
#include <pexpert/pexpert.h>
#include <machine/machine_routines.h>
#include <kern/clock.h>

#if !defined(NABU_LEGACY_CPU_PRESENT) || !defined(NABU_LEGACY_CPU_ABI_VERIFIED)
#error CPU presentation requires an explicitly qualified build mode
#endif

extern "C" __attribute__((noreturn)) void native_legacy_backend_guard(unsigned, void *, void *);
extern "C" bool native_legacy_gop_mapping_observed(IOService *, IOMemoryMap *, uint32_t, uint32_t);
extern "C" void native_legacy_registration_observed(IOService *);
extern "C" void native_legacy_client_enter(task_t, uint32_t);
extern "C" void native_legacy_client_observed(IOReturn, IOUserClient *);
extern "C" IOMemoryDescriptor *native_legacy_surface_descriptor(OSObject *);
extern "C" uint64_t native_legacy_surface_width(OSObject *), native_legacy_surface_height(OSObject *);
extern "C" uint64_t native_legacy_surface_stride(OSObject *), native_legacy_surface_allocation(OSObject *);
extern "C" uint32_t native_legacy_surface_format(OSObject *), native_legacy_surface_planes(OSObject *);
extern "C" void native_legacy_swap_validation_observed(bool, unsigned, const void *, const void *);
extern "C" void native_legacy_surface_rejected(uint64_t, uint64_t, uint32_t, uint32_t, uint64_t, uint64_t, uint64_t);
extern "C" void native_legacy_transfer_observed(IOReturn, const void *, uint64_t);
extern "C" void native_legacy_retirement_observed(IOService *);
extern "C" void native_legacy_pm_observed(unsigned, IOReturn, unsigned long);
// This binding must be generated from this version's original activation path.
extern "C" void nabu_legacy_request_active(void *, const OriginalLegacySwapRequest *, uint32_t);
extern "C" int nabu_legacy_display_state(void *, void *, bool);

extern "C" {
volatile uint32_t nabu_legacy_cpu_present_abi = 1;
volatile uint32_t nabu_legacy_cpu_console_owned, nabu_legacy_cpu_console_status;
volatile uint32_t nabu_legacy_cpu_first_request_valid;
unsigned char nabu_legacy_cpu_first_request[0x340];
volatile uint64_t nabu_legacy_cpu_copied_frames, nabu_legacy_cpu_blank_frames;
volatile uint64_t nabu_legacy_cpu_stored_bytes, nabu_legacy_cpu_copy_ticks;
volatile uint64_t nabu_legacy_cpu_max_copy_ticks, nabu_legacy_cpu_diff_frames;
volatile uint64_t nabu_legacy_cpu_shadow_bytes;
}
#if defined(NABU_LEGACY_GPU_SCANOUT)
#include "NabuGpuScanoutHandoff.h"
#endif

class NativeLegacyDisplay : public IOMobileFramebufferLegacy {
    OSDeclareDefaultStructors(NativeLegacyDisplay)
    IOMemoryMap *bootMapping = nullptr;
    uint64_t bootStride = 0;
    bool primary = false, enabled = false, consoleOwned = false, logicalPM = false;
    bool kicking = false, rekick = false;
    void *shadow = nullptr;
    size_t shadowBytes = 0;
    bool shadowValid = false, diffEnabled = true;
    const OriginalLegacySwapRequest *validated[64] = {};
#if defined(NABU_LEGACY_GPU_SCANOUT)
    NabuGpuScanoutHandoff *gpuHandoff = nullptr;
    const OriginalLegacySwapRequest *gpuRequest = nullptr;
    uint64_t gpuSequence = 0;
    bool gpuBypass = false;

    static void gpuCompletion(IOService *display, uint64_t sequence, IOReturn status) {
        NativeLegacyDisplay *self = static_cast<NativeLegacyDisplay *>(display);
        IOWorkLoop *workloop = self->getWorkLoop();
        if (!workloop) return;
        struct Completion { uint64_t sequence; IOReturn status; } done = {sequence, status};
        workloop->runAction([](OSObject *target, void *argument, void *, void *, void *) -> IOReturn {
            NativeLegacyDisplay *self = static_cast<NativeLegacyDisplay *>(target);
            const Completion &done = *static_cast<Completion *>(argument);
            self->gpuComplete(done.sequence, done.status);
            return kIOReturnSuccess;
        }, self, &done);
    }
#endif
    void finishSwap(const OriginalLegacySwapRequest *request, uint64_t bytes) {
        native_legacy_transfer_observed(kIOReturnSuccess, request, bytes);
        if (!activateOnlyPendingSwap(request)) return;
        nabu_legacy_request_active(this, request, 3);
        const int slot = slotFor(request);
        if (slot >= 0) validated[slot] = nullptr;
        IOMobileFramebufferLegacy::completeCurrentSwap();
        native_legacy_retirement_observed(this);
        rekick = true;
    }
#if defined(NABU_LEGACY_GPU_SCANOUT)
    void gpuComplete(uint64_t sequence, IOReturn status) {
        if (!gpuRequest || sequence != gpuSequence) return;
        const OriginalLegacySwapRequest *request = gpuRequest;
        gpuRequest = nullptr; gpuSequence = 0;
        if (!enabled || request != pendingSwapRequest()) return;
        if (status == kIOReturnSuccess) {
            uint32_t width = 0, height = 0;
            getDisplayDimensions(&width, &height);
            const bool wasKicking = kicking;
            kicking = true; // The original completion can re-enter kickSwapQueue.
            __asm__ volatile("dsb sy" ::: "memory");
            finishSwap(request, uint64_t(width) * height * 4);
            kicking = wasKicking;
        } else gpuBypass = true;
        kickSwapQueue();
    }
#endif

    static uint32_t word(const OriginalLegacySwapRequest *request, unsigned offset) {
        uint32_t value = 0;
        memcpy(&value, reinterpret_cast<const unsigned char *>(request) + offset, sizeof(value));
        return value;
    }
    static OSObject *surfaceAt(const OriginalLegacySwapRequest *request, unsigned layer) {
        OSObject *surface = nullptr;
        memcpy(&surface, reinterpret_cast<const unsigned char *>(request) + 2624 + layer * 8, 8);
        return surface;
    }
    int slotFor(const OriginalLegacySwapRequest *request) const {
        for (unsigned i = 0; i < 64; ++i) if (validated[i] == request) return (int)i;
        return -1;
    }
    bool acquireConsole() {
        if (consoleOwned) return true;
        if (ml_at_interrupt_context() || !ml_get_interrupts_enabled()) return false;
        // Standard XNU path drains vcputc/progress locks and pauses pixel writers.
        // Recorder hooks, when enabled, execute before console-disable filtering.
        int status = PE_initialize_console(nullptr, kPEDisableScreen);
        nabu_legacy_cpu_console_status = (uint32_t)status;
        if (status) return false;
        consoleOwned = true;
        nabu_legacy_cpu_console_owned = 1;
        return true;
    }
    void restoreConsole() {
        if (!consoleOwned) return;
        PE_initialize_console(nullptr, kPEEnableScreen);
        consoleOwned = false;
        nabu_legacy_cpu_console_owned = 0;
    }
    void releaseShadow() {
        shadowValid = false;
        if (shadow) IOFree(shadow, shadowBytes);
        shadow = nullptr; shadowBytes = 0; nabu_legacy_cpu_shadow_bytes = 0;
    }
    void kickOnce() {
        const OriginalLegacySwapRequest *request = pendingSwapRequest();
        if (!enabled || !bootMapping || !request || ml_at_interrupt_context()) return;
#if defined(NABU_LEGACY_GPU_SCANOUT)
        if (gpuRequest) return;
#endif
        int acceptedSlot = slotFor(request);
        if (acceptedSlot < 0) return;
        const void *current = nullptr;
        memcpy(&current, reinterpret_cast<const unsigned char *>(this) + 5472, 8);
        if (current) return;
        uint32_t width = 0, height = 0;
        getDisplayDimensions(&width, &height);
        OSObject *surface = surfaceAt(request, 0);
        IOMemoryMap *source = nullptr;
        uint64_t sourceStride = 0;
        if (surface) {
            IOMemoryDescriptor *memory = native_legacy_surface_descriptor(surface);
            if (!memory) return;
            sourceStride = native_legacy_surface_stride(surface);
#if defined(NABU_LEGACY_GPU_SCANOUT)
            if (gpuHandoff && !gpuBypass && acquireConsole()) {
                const uint64_t sequence = gpuHandoff->offer(memory, sourceStride, width, height);
                if (sequence) {
                    gpuRequest = request; gpuSequence = sequence;
                    shadowValid = false;
                    return;
                }
            }
#endif
            source = memory->map(kIOMapAnywhere | kIOMapReadOnly);
            if (!source || !source->getVirtualAddress() ||
                source->getLength() < native_legacy_surface_allocation(surface)) {
                OSSafeReleaseNULL(source);
                native_legacy_transfer_observed(kIOReturnNoMemory, request, 0);
                return;
            }
        }
        if (!acquireConsole()) { OSSafeReleaseNULL(source); return; }
        const uint64_t begin = mach_absolute_time();
        const uint64_t frameBytes = (uint64_t)width * height * 4;
        uint64_t stored = UINT64_MAX;
        if (source && shadow && shadowBytes == frameBytes) {
            stored = nabu_cpu_copy_diff(
                reinterpret_cast<volatile void *>(bootMapping->getVirtualAddress()), bootMapping->getLength(), bootStride,
                reinterpret_cast<const void *>(source->getVirtualAddress()), source->getLength(), sourceStride, width, height,
                shadow, shadowBytes, shadowValid);
        }
        bool copied = stored != UINT64_MAX;
        if (copied) { shadowValid = true; ++nabu_legacy_cpu_diff_frames; }
        else {
            shadowValid = false;
            copied = source ? nabu_cpu_copy_bgra(
                reinterpret_cast<volatile void *>(bootMapping->getVirtualAddress()), bootMapping->getLength(), bootStride,
                reinterpret_cast<const void *>(source->getVirtualAddress()), source->getLength(), sourceStride, width, height) :
                nabu_cpu_black(reinterpret_cast<volatile void *>(bootMapping->getVirtualAddress()),
                    bootMapping->getLength(), bootStride, width, height);
            if (copied) stored = frameBytes;
        }
        OSSafeReleaseNULL(source);
        if (!copied) {
            native_legacy_transfer_observed(kIOReturnBadArgument, request, 0);
            if (!nabu_legacy_cpu_copied_frames && !nabu_legacy_cpu_blank_frames) restoreConsole();
            return;
        }
        __asm__ volatile("dsb sy" ::: "memory");
        const uint64_t ticks = mach_absolute_time() - begin;
        nabu_legacy_cpu_stored_bytes += stored;
        nabu_legacy_cpu_copy_ticks += ticks;
        if (ticks > nabu_legacy_cpu_max_copy_ticks) nabu_legacy_cpu_max_copy_ticks = ticks;
        if (surface) ++nabu_legacy_cpu_copied_frames; else ++nabu_legacy_cpu_blank_frames;
        finishSwap(request, stored);
    }
public:
    void free() override {
        if (logicalPM) { PMstop(); logicalPM = false; }
        releaseShadow();
        OSSafeReleaseNULL(bootMapping);
        IOMobileFramebufferLegacy::free();
    }
    void stop(IOService *provider) override {
#if defined(NABU_LEGACY_GPU_SCANOUT)
        if (gpuHandoff) {
            getWorkLoop()->runAction([](OSObject *target, void *, void *, void *, void *) -> IOReturn {
                NativeLegacyDisplay *self = static_cast<NativeLegacyDisplay *>(target);
                self->enabled = false;
                self->gpuHandoff->stop();
                return kIOReturnSuccess;
            }, this);
        }
#endif
        enabled = false;
        if (logicalPM) { PMstop(); logicalPM = false; }
        IOMobileFramebufferLegacy::stop(provider);
#if defined(NABU_LEGACY_GPU_SCANOUT)
        if (!gpuRequest) restoreConsole(); // Unknown DMA must not race a revived console pixel writer.
#else
        restoreConsole();
#endif
        releaseShadow();
        OSSafeReleaseNULL(bootMapping);
    }
    bool start(IOService *provider) override {
        unsigned value = 0;
        PE_parse_boot_argn("nabu-cpu-present", &value, sizeof(value));
        enabled = value == 1;
        value = 1;
        PE_parse_boot_argn("nabu-cpu-diff", &value, sizeof(value));
        diffEnabled = value == 1;
        if (!IOMobileFramebufferLegacy::start(provider)) return false;
        if (enabled && primary && bootMapping) {
            // As UniXNU's logical PM plus announcePoweredByFirmware: request the
            // original scheduling state (+5836=1, read by the swap entry before
            // validation) and record the firmware-lit GOP panel as powered (+5840=1;
            // without it selector 6's wait answers busy). No physical power control.
            struct StateRequest { uint32_t skipRequested, requested, skipPowered, powered;
                                  uint8_t changed; uint8_t pad[11]; } request = {0,1,0,1,1,{}};
            nabu_legacy_display_state(this, &request, false);
            uint32_t scheduled = 0, powered = 0;
            memcpy(&scheduled, reinterpret_cast<const unsigned char *>(this) + 5836, 4);
            memcpy(&powered, reinterpret_cast<const unsigned char *>(this) + 5840, 4);
            if (scheduled != 1 || powered != 1) {
                enabled = false;
                IOMobileFramebufferLegacy::stop(provider);
                return false;
            }
            if (!startLogicalPM(provider)) {
                enabled = false;
                IOMobileFramebufferLegacy::stop(provider);
                return false;
            }
#if defined(NABU_LEGACY_GPU_SCANOUT)
            unsigned scanout = 0;
            PE_parse_boot_argn("nabu-gpu-scanout", &scanout, sizeof(scanout));
            if (scanout == 1 && getWorkLoop() && !__atomic_load_n(&nabuScanoutHandoff, __ATOMIC_ACQUIRE)) {
                uint32_t width = 0, height = 0;
                getDisplayDimensions(&width, &height);
                NabuGpuScanoutHandoff *handoff = new NabuGpuScanoutHandoff;
                if (handoff && handoff->initialize(this, bootMapping, width, height, bootStride, gpuCompletion)) {
                    gpuHandoff = handoff;
                    __atomic_store_n(&nabuScanoutHandoff, handoff, __ATOMIC_RELEASE);
                    IOLog("NABU DISPLAY gpu-blit handoff ready %ux%u stride=%llu\n", width, height, bootStride);
                } else if (handoff) delete handoff;
            }
#endif
        }
        return true;
    }
    // UniXNU startDisplay: the actual IOKit PM lifecycle for logical scanout
    // scheduling (offline-legacy-pm=1, phase 4). GOP has no panel power switch;
    // no state advertises physical power output or a hardware transition.
    bool startLogicalPM(IOService *provider) {
        unsigned pm = 0, phase = 0;
        PE_parse_boot_argn("offline-legacy-pm", &pm, sizeof(pm));
        if (!pm) return true;
        PE_parse_boot_argn("offline-legacy-phase", &phase, sizeof(phase));
        if (pm != 1 || phase != 4 || !provider) {
            native_legacy_pm_observed(1, kIOReturnNotReady, 0);
            return false;
        }
        static IOPMPowerState states[2] = {};
        states[0].version = states[1].version = 1;
        states[1].capabilityFlags = kIOPMDeviceUsable;
        PMinit();
        logicalPM = initialized;
        if (!logicalPM) { native_legacy_pm_observed(1, kIOReturnNotReady, 0); return false; }
        provider->joinPMtree(this);
        IOReturn status = registerPowerDriver(this, states, 2);
        native_legacy_pm_observed(1, status, 0);
        if (status == kIOReturnSuccess) {
            status = changePowerStateToPriv(1);
            native_legacy_pm_observed(2, status, 1);
        }
        if (status != kIOReturnSuccess) { PMstop(); logicalPM = false; return false; }
        return true;
    }
    IOReturn setPowerState(unsigned long ordinal, IOService *device) override {
        if (!logicalPM) return IOMobileFramebufferLegacy::setPowerState(ordinal, device);
        if (ordinal > 1 || !bootMapping) {
            native_legacy_pm_observed(3, kIOReturnUnsupported, ordinal);
            return kIOReturnUnsupported;
        }
        native_legacy_pm_observed(3, kIOReturnSuccess, ordinal);
        IOReturn status = IOMobileFramebufferLegacy::setPowerState(ordinal, device);
        native_legacy_pm_observed(4, status, ordinal);
        return status;
    }
    void registerService(IOOptionBits options = 0) override {
        unsigned value = 0;
        PE_parse_boot_argn("offline-legacy-register", &value, sizeof(value));
        if (value != 1) native_legacy_backend_guard(84, this, __builtin_return_address(0));
        IOService::registerService(options);
        native_legacy_registration_observed(this);
    }
    bool isMainDisplay() override { return primary; }
    void kickLocked() {
        if (kicking) { rekick = true; return; }
        kicking = true;
        do { rekick = false; kickOnce(); } while (rekick);
        kicking = false;
    }
    void kickSwapQueue() override {
#if defined(NABU_LEGACY_GPU_SCANOUT)
        if (gpuHandoff) {
            getWorkLoop()->runAction([](OSObject *target, void *, void *, void *, void *) -> IOReturn {
                static_cast<NativeLegacyDisplay *>(target)->kickLocked();
                return kIOReturnSuccess;
            }, this);
            return;
        }
#endif
        kickLocked();
    }
    bool validateSwap(const OriginalLegacySwapRequest *request) override {
#if defined(NABU_LEGACY_GPU_SCANOUT)
        if (gpuHandoff) {
            struct Validation {const OriginalLegacySwapRequest *request; bool accepted;};
            Validation validation = {request, false};
            getWorkLoop()->runAction([](OSObject *target, void *argument, void *, void *, void *) -> IOReturn {
                Validation &validation = *static_cast<Validation *>(argument);
                validation.accepted = static_cast<NativeLegacyDisplay *>(target)->validateSwapLocked(validation.request);
                return kIOReturnSuccess;
            }, this, &validation);
            return validation.accepted;
        }
#endif
        return validateSwapLocked(request);
    }
    bool validateSwapLocked(const OriginalLegacySwapRequest *request) {
        bool accepted = false;
        OSObject *surface = nullptr;
        unsigned reason = 1;
        int previousSlot = request ? slotFor(request) : -1;
        if (previousSlot >= 0) validated[previousSlot] = nullptr;
        if (request && enabled && primary && bootMapping) {
            if (!nabu_legacy_cpu_first_request_valid) {
                memcpy(nabu_legacy_cpu_first_request, request, sizeof(nabu_legacy_cpu_first_request));
                nabu_legacy_cpu_first_request_valid = 1;
            }
            surface = surfaceAt(request, 0);
            uint32_t width = 0, height = 0;
            getDisplayDimensions(&width, &height);
            reason = 2;
            bool othersEmpty = !surfaceAt(request, 1) && !surfaceAt(request, 2) && !surfaceAt(request, 3);
            bool geometry = word(request, 816) == width && word(request, 820) == height;
            // Unsupported options/types are rejected, not silently ignored.
            bool options = !word(request, 804) && !word(request, 808) && !word(request, 812);
            if (othersEmpty && options && geometry &&
                nabu_cpu_single_layer(word(request, 792), word(request, 796), word(request, 800), !surface)) {
                reason = 3;
                bool rectangles = true;
                const unsigned rectOffsets[] = {17, 81};
                for (unsigned offset : rectOffsets) {
                    rectangles = rectangles && !word(request, offset) && !word(request, offset + 4) &&
                        word(request, offset + 8) == width && word(request, offset + 12) == height;
                }
                if (!surface) accepted = true;
                else if (rectangles && surface->metaCast("IOSurface")) {
                    IOMemoryDescriptor *memory = native_legacy_surface_descriptor(surface);
                    uint64_t allocation = native_legacy_surface_allocation(surface);
                    // UniXNU's '&BGA' exception relies on its own producer writing plain
                    // rows. That layout has not been established for this CPU producer.
                    uint32_t format = native_legacy_surface_format(surface), planes = native_legacy_surface_planes(surface);
                    accepted = memory && memory->metaCast("IOMemoryDescriptor") &&
                        format == 0x42475241 && !planes &&
                        native_legacy_surface_width(surface) >= width && native_legacy_surface_height(surface) >= height &&
                        allocation <= memory->getLength() &&
                        nabu_cpu_rows(width, height, native_legacy_surface_stride(surface), allocation);
                    if (!accepted) native_legacy_surface_rejected(
                        native_legacy_surface_width(surface), native_legacy_surface_height(surface), format, planes,
                        native_legacy_surface_stride(surface), allocation, memory ? memory->getLength() : 0);
                }
            }
            int slot = previousSlot;
            if (accepted && slot < 0) slot = slotFor(nullptr);
            if (accepted && slot < 0) { accepted = false; reason = 4; }
            if (slot >= 0) validated[slot] = accepted ? request : nullptr;
        }
        native_legacy_swap_validation_observed(accepted, accepted ? 0 : reason, request, surface);
        return accepted;
    }
    IOReturn collectCompletionReports(uint32_t, void *, uint32_t *count, uint32_t) override {
        if (count) *count = 0;
        return kIOReturnUnsupported;
    }
    // As UniXNU: the outputs are written before any status. GOP supplies no dot
    // pitch unless the provider carries one; selector 74's trace keys are unsupported.
    IOReturn getDotPitch(uint32_t *pitch) override {
        if (!pitch) return kIOReturnBadArgument;
        *pitch = 0;
        IOService *provider = getProvider();
        if (!provider) return kIOReturnNotReady;
        OSData *data = OSDynamicCast(OSData, provider->getProperty("dot-pitch"));
        if (!data) return kIOReturnNotFound;
        if (data->getLength() != sizeof(*pitch)) return kIOReturnBadArgument;
        memcpy(pitch, data->getBytesNoCopy(), sizeof(*pitch));
        return kIOReturnSuccess;
    }
    IOReturn supportedFrameInfo(uint32_t, uint32_t *count, char *key, uint32_t *mask) override {
        if (!count || !key || !mask) return kIOReturnBadArgument;
        *count = 0; *mask = 0; bzero(key, 64);
        return kIOReturnUnsupported;
    }
    IOReturn newUserClient(task_t task, void *security, UInt32 type, IOUserClient **client) override {
        native_legacy_client_enter(task, type);
        IOReturn status = IOMobileFramebufferLegacy::newUserClient(task, security, type, client);
        native_legacy_client_observed(status, status == kIOReturnSuccess && client ? *client : nullptr);
        return status;
    }
    bool startHardware() override {
        unsigned value = 0;
        PE_parse_boot_argn("offline-legacy-gop", &value, sizeof(value));
        PE_Video video = {};
        IOService *provider = getProvider();
        if (value != 1 || !provider || PE_current_console(&video) || !video.v_baseAddr ||
            video.v_depth != 32 || video.v_rotate || video.v_width > 16384 || video.v_height > 16384 ||
            !nabu_cpu_rows((uint32_t)video.v_width,
                (uint32_t)video.v_height, video.v_rowBytes, UINT64_MAX)) return false;
        IOMemoryMap *mapping = provider->mapDeviceMemoryWithIndex(0, kIOMapInhibitCache);
        if (!mapping) return false;
        bool valid = mapping->getVirtualAddress() && mapping->getPhysicalAddress() == video.v_baseAddr &&
            mapping->getLength() == video.v_rowBytes * video.v_height;
        if (valid) {
            installBootDimensions((uint32_t)video.v_width, (uint32_t)video.v_height);
            uint32_t width = 0, height = 0;
            getDisplayDimensions(&width, &height);
            valid = width == video.v_width && height == video.v_height;
            if (valid) {
                OSSafeReleaseNULL(bootMapping);
                bootMapping = mapping; mapping = nullptr;
                bootStride = video.v_rowBytes;
                primary = video.v_display == 1;
                releaseShadow();
                const uint64_t packed = (uint64_t)width * height * 4;
                if (enabled && diffEnabled && primary && !(width & 1) && packed <= 32 * 1024 * 1024) {
                    shadow = IOMalloc((size_t)packed);
                    if (shadow) { shadowBytes = (size_t)packed; nabu_legacy_cpu_shadow_bytes = packed; }
                    IOLog("NABU CPU present: differential=%u shadow=%llu full-copy-fallback=%u\n",
                        diffEnabled, (unsigned long long)shadowBytes, shadow == nullptr);
                }
                valid = native_legacy_gop_mapping_observed(this, bootMapping, width, height);
            }
        }
        OSSafeReleaseNULL(mapping);
        return valid;
    }
#define LEAF(n) __attribute__((noreturn,noinline)) void opaque##n() override { native_legacy_backend_guard(n,this,__builtin_return_address(0)); }
    LEAF(211) LEAF(245) LEAF(246) LEAF(306) LEAF(307) LEAF(338) LEAF(345)
#undef LEAF
};
OSDefineMetaClassAndStructors(NativeLegacyDisplay, IOMobileFramebufferLegacy)
extern "C" IOService *native_legacy_display_allocate(void) { return new NativeLegacyDisplay; }
