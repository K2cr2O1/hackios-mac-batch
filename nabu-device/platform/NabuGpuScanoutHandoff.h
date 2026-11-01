// SPDX-License-Identifier: BSD-2-Clause-Patent
// Nabu display side of UniXNU's GOP hand-off. No pixel copy happens here.
#pragma once
#include "NabuGpuScanoutWire.h"
#include "NabuLegacyCpuPixels.h"
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOWorkLoop.h>
#include <kern/task.h>
#include <kern/clock.h>
#include <sys/proc.h>

extern "C" {
volatile uint64_t nabu_scanout_offers,nabu_scanout_completed,nabu_scanout_fallbacks;
volatile uint64_t nabu_scanout_waits,nabu_scanout_timeouts,nabu_scanout_abandoned;
volatile uint64_t nabu_scanout_maps,nabu_scanout_map_hits;
volatile uint32_t nabu_scanout_ready,nabu_scanout_last_status,nabu_scanout_pending;
}

class NabuGpuScanoutHandoff {
    IOLock *gate_=nullptr;
    IOService *display_=nullptr;
    IOMemoryDescriptor *scanout_=nullptr;
    NGPMode mode_={};
    task_t clientTask_=TASK_NULL;
    const void *client_=nullptr;
    bool online_=false,offered_=false,delivered_=false,blocked_=false,closed_=false;
    uint64_t sequence_=0;
    IOMemoryDescriptor *frame_=nullptr;
    uint64_t frameStride_=0;
    void (*completion_)(IOService *,uint64_t,IOReturn)=nullptr;
    // Keep at most eight source maps (32 MiB each) until reboot. Never evict a
    // user mapping behind an import still held by the Metal runtime. Exhaustion
    // disables GPU offers and falls back before any new copy is submitted.
    struct Kept {IOMemoryDescriptor *memory;IOMemoryMap *map;};
    Kept kept_[8]={};
    static constexpr uint64_t MaxBytes=32u*1024u*1024u;
    static bool allowed(task_t task) {
        if(!task || task!=current_task())return false;
        char process[20]={};proc_selfname(process,sizeof(process));
        return !strcmp(process,"backboardd");
    }
public:
    bool initialize(IOService *display,IOMemoryMap *mapping,uint32_t width,uint32_t height,uint64_t stride,
        void (*completion)(IOService *,uint64_t,IOReturn)) {
        if(gate_ || !display || !mapping || !completion || (stride&3) || !nabu_cpu_rows(width,height,stride,mapping->getLength()) ||
            !mapping->getPhysicalAddress() || (mapping->getPhysicalAddress()&4095) ||
            mapping->getPhysicalAddress()>UINT64_MAX-mapping->getLength() ||
            mapping->getLength()!=stride*height || mapping->getLength()>MaxBytes || (mapping->getLength()&4095))return false;
        gate_=IOLockAlloc();if(!gate_)return false;
        // Unlike an IOMemoryMap's potentially offset descriptor, this extent is
        // precisely the GOP reservation. The GPU import independently checks it.
        scanout_=IODeviceMemory::withRange(mapping->getPhysicalAddress(),mapping->getLength());
        if(!scanout_){IOLockFree(gate_);gate_=nullptr;return false;}
        display_=display;display_->retain();completion_=completion;
        mode_={NGP_VERSION,NGP_BGRX8888,width,height,stride,mapping->getLength()};
        online_=true;nabu_scanout_ready=1;return true;
    }
    // Boot-lifetime objects: the owner and maps remain retained when a stop or
    // client death cannot establish whether another GPU connection still uses them.
    void stop() {
        if(!gate_)return;
        IOLockLock(gate_);online_=false;nabu_scanout_ready=0;
        IOLockWakeup(gate_,&offered_,false);IOLockUnlock(gate_);
    }
    uint64_t offer(IOMemoryDescriptor *memory,uint64_t stride,uint32_t width,uint32_t height) {
        if(!gate_ || !memory || (stride&3) || !nabu_cpu_rows(width,height,stride,memory->getLength()) ||
            memory->getLength()>MaxBytes || (memory->getLength()&4095) || width!=mode_.width || height!=mode_.height)return 0;
        IOLockLock(gate_);
        uint64_t offered=0;
        if(online_ && client_ && !blocked_ && !offered_ && sequence_!=UINT64_MAX) {
            frame_=memory;frame_->retain();frameStride_=stride;
            offered_=true;delivered_=false;offered=++sequence_;
            ++nabu_scanout_offers;nabu_scanout_pending=1;IOLockWakeup(gate_,&offered_,false);
        }
        IOLockUnlock(gate_);return offered;
    }
    IOMemoryDescriptor *memory(task_t task,const void *client) {
        if(!gate_ || !client || !allowed(task))return nullptr;
        IOLockLock(gate_);IOMemoryDescriptor *result=nullptr;
        if(online_ && !blocked_ && (!client_ || (client_==client && clientTask_==task))) {
            scanout_->retain();result=scanout_;
        }
        IOLockUnlock(gate_);return result;
    }
    void close(const void *client) {
        if(!gate_ || !client)return;
        IOLockLock(gate_);
        if(client_!=client || closed_){IOLockUnlock(gate_);return;}
        closed_=true;blocked_=true;nabu_scanout_ready=0;++nabu_scanout_abandoned;
        // A delivered frame may still be undergoing DMA on another connection.
        // Do not copy over it on the CPU or release its backing on client death.
        IOMemoryDescriptor *frame=nullptr;uint64_t sequence=0;
        if(offered_ && !delivered_) {
            frame=frame_;frame_=nullptr;sequence=sequence_;
            offered_=false;nabu_scanout_pending=0;++nabu_scanout_fallbacks;
        }
        IOLockWakeup(gate_,&offered_,false);IOLockUnlock(gate_);
        if(frame)frame->release();
        if(sequence)completion_(display_,sequence,kIOReturnAborted);
    }
    IOReturn call(uint32_t method,task_t task,const void *client,const void *in,size_t inBytes,void *out,size_t outBytes) {
        if(!gate_)return kIOReturnNotReady;
        if(!task || !client || task!=current_task())return kIOReturnBadArgument;
        if(!allowed(task))return kIOReturnNotPermitted;
        if(method==NGP_METHOD_MODE) {
            if(inBytes || !out || outBytes!=sizeof(mode_))return kIOReturnBadArgument;
            IOLockLock(gate_);const bool ready=online_ && !blocked_;
            if(ready)memcpy(out,&mode_,sizeof(mode_));
            IOLockUnlock(gate_);return ready?kIOReturnSuccess:kIOReturnNotReady;
        }
        if(method==NGP_METHOD_WAIT_SWAP) {
            if(!in || inBytes!=sizeof(NGPWait) || !out || outBytes!=sizeof(NGPSwap))return kIOReturnBadArgument;
            NGPWait wait={};memcpy(&wait,in,sizeof(wait));
            if(wait.timeout_ms>1000)wait.timeout_ms=1000;
            uint64_t deadline=0;clock_interval_to_deadline(uint32_t(wait.timeout_ms),kMillisecondScale,&deadline);
            IOLockLock(gate_);
            if(!online_ || blocked_){IOLockUnlock(gate_);return kIOReturnNotReady;}
            if(!client_){client_=client;clientTask_=task;task_reference(task);}
            if(client_!=client || clientTask_!=task){IOLockUnlock(gate_);return kIOReturnExclusiveAccess;}
            ++nabu_scanout_waits;
            while(online_ && !blocked_ && (!offered_ || delivered_)) {
                if(IOLockSleepDeadline(gate_,&offered_,deadline,THREAD_ABORTSAFE)!=THREAD_AWAKENED) {
                    ++nabu_scanout_timeouts;IOLockUnlock(gate_);return kIOReturnTimeout;
                }
            }
            if(!online_ || blocked_){IOLockUnlock(gate_);return kIOReturnNotReady;}
            IOMemoryMap *map=nullptr;unsigned empty=8,id=0;
            for(unsigned i=0;i<8;++i) {
                if(kept_[i].memory==frame_){map=kept_[i].map;id=i+1;++nabu_scanout_map_hits;break;}
                if(!kept_[i].memory && empty==8)empty=i;
            }
            if(!map && empty<8) {
                map=frame_->createMappingInTask(task,0,kIOMapAnywhere);
                if(map && map->getVirtualAddress() && !(map->getVirtualAddress()&4095) && map->getLength()==frame_->getLength()) {
                    frame_->retain();kept_[empty]={frame_,map};id=empty+1;++nabu_scanout_maps;
                } else {OSSafeReleaseNULL(map);}
            }
            if(!map) {
                IOMemoryDescriptor *frame=frame_;frame_=nullptr;const uint64_t sequence=sequence_;
                offered_=false;blocked_=true;nabu_scanout_pending=0;nabu_scanout_ready=0;
                nabu_scanout_last_status=uint32_t(kIOReturnNoMemory);++nabu_scanout_fallbacks;
                IOLockUnlock(gate_);frame->release();completion_(display_,sequence,kIOReturnNoMemory);
                return kIOReturnNoMemory;
            }
            // No CPU cache-attribute changes. The descriptor and cached task map
            // outlive every Vulkan host-memory import made by the GPU process.
            delivered_=true;
            NGPSwap swap={sequence_,map->getVirtualAddress(),map->getLength(),frameStride_,
                uint32_t(mode_.width),uint32_t(mode_.height),NGP_BGRX8888,id};
            memcpy(out,&swap,sizeof(swap));IOLockUnlock(gate_);return kIOReturnSuccess;
        }
        if(method==NGP_METHOD_COMPLETE_SWAP) {
            if(!in || inBytes!=sizeof(NGPComplete) || outBytes)return kIOReturnBadArgument;
            NGPComplete done={};memcpy(&done,in,sizeof(done));
            IOLockLock(gate_);
            if(!online_ || blocked_){IOLockUnlock(gate_);return kIOReturnNotReady;}
            if(client_!=client || clientTask_!=task || !offered_ || !delivered_ || done.sequence!=sequence_ || done.reserved) {
                IOLockUnlock(gate_);return kIOReturnBadArgument;
            }
            nabu_scanout_last_status=done.status;
            // The nabu client reports Error only before GPU submission. Any
            // other failure (including NotResponding) leaves completion unknown.
            if(done.status && done.status!=uint32_t(kIOReturnError)) {
                blocked_=true;nabu_scanout_ready=0;IOLockUnlock(gate_);return kIOReturnSuccess;
            }
            IOMemoryDescriptor *frame=frame_;frame_=nullptr;
            offered_=false;delivered_=false;nabu_scanout_pending=0;
            if(done.status){blocked_=true;nabu_scanout_ready=0;++nabu_scanout_fallbacks;}
            else ++nabu_scanout_completed;
            IOLockUnlock(gate_);frame->release();
            completion_(display_,done.sequence,IOReturn(done.status));return kIOReturnSuccess;
        }
        return kIOReturnUnsupported;
    }
};

static NabuGpuScanoutHandoff *nabuScanoutHandoff;
extern "C" IOReturn nabu_gpu_scanout_display_call(uint32_t method,task_t task,const void *client,
    const void *in,size_t inBytes,void *out,size_t outBytes) {
    NabuGpuScanoutHandoff *handoff=__atomic_load_n(&nabuScanoutHandoff,__ATOMIC_ACQUIRE);
    return handoff?handoff->call(method,task,client,in,inBytes,out,outBytes):kIOReturnNotReady;
}
extern "C" IOMemoryDescriptor *nabu_gpu_scanout_display_memory(task_t task,const void *client) {
    NabuGpuScanoutHandoff *handoff=__atomic_load_n(&nabuScanoutHandoff,__ATOMIC_ACQUIRE);
    return handoff?handoff->memory(task,client):nullptr;
}
extern "C" void nabu_gpu_scanout_display_close(const void *client) {
    NabuGpuScanoutHandoff *handoff=__atomic_load_n(&nabuScanoutHandoff,__ATOMIC_ACQUIRE);
    if(handoff)handoff->close(client);
}
