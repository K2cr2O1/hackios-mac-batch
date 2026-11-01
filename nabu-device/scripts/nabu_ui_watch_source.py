"""Reversible, explicitly enabled UI exec and first-main-thread observations."""

CONTRACT = {
    'version': 2, 'trigger': 'nabu-ui-watch=1',
    'targets': ['SpringBoard', 'backboardd', 'runningboardd'],
    'paths': ['/System/Library/CoreServices/SpringBoard.app/SpringBoard',
              '/usr/libexec/backboardd', '/usr/libexec/runningboardd'],
    'symbols': ['_nabu_ui_watch_snapshot', '_nabu_ui_watch_exit_note',
                '_nabu_ui_watch_activation', '_nabu_ui_watch_signature',
                '_nabu_ui_watch_release_ready', '_nabu_ui_watch_released',
                '_nabu_ui_watch_activate_image_v2', '_nabu_ui_watch_thread_state'],
    'symbols_by_object': {
        'kern_exec.c': ['_nabu_ui_watch_snapshot', '_nabu_ui_watch_exit_note',
                        '_nabu_ui_watch_activation', '_nabu_ui_watch_signature',
                        '_nabu_ui_watch_release_ready', '_nabu_ui_watch_released',
                        '_nabu_ui_watch_activate_image_v2'],
        'thread.c': ['_nabu_ui_watch_thread_state'],
    },
    'symbol_references_by_object': {'kern_exit.c': ['_nabu_ui_watch_exit_note']},
    'max_samples': 64, 'interval_us': 10000000, 'max_threads': 3,
    'max_events': 96, 'max_exec_contexts': 0, 'max_line_bytes': 256, 'first_incarnation_only': True,
    'target_association': 'activation-call-output',
    'user_memory_read': False, 'scheduler_changed': False, 'new_worker': False,
    'runtime_qualified': False,
}
PREFIX = '#define nabu_gpu_userprobe_exec_snapshot nabu_ui_watch_snapshot\n'
SUFFIX = '#undef nabu_gpu_userprobe_exec_snapshot\n'

EXEC_HELPER = r'''/* NABU_UI_WATCH_V2: bounded observation, no exec/scheduler policy change.
 * This is a BSD unit: struct thread and sched locks are not visible here. The
 * scheduler fields are read by nabu_ui_watch_thread_state in osfmk/kern/thread.c. */
extern int nabu_ui_watch_thread_state(thread_t, uint32_t *, uint32_t *, uint64_t *);
/* XNU thread state bits; thread.h's definitions are private to osfmk. */
enum { NABU_UI_TH_TERMINATE = 0x10, NABU_UI_TH_TERMINATE2 = 0x20 };

enum { NABU_UI_TARGETS = 3, NABU_UI_MAX_EVENTS = 96, NABU_UI_MAX_SAMPLES = 64 };
enum { NABU_UI_EMPTY = 0, NABU_UI_CLAIMING = 1, NABU_UI_READY = 2, NABU_UI_CLOSED = 3 };
struct nabu_ui_slot {
    unsigned phase;
    thread_t thread;
    int pid;
    uint64_t uniqueid, tid, first_seq, first_us;
    uint64_t latest_tid;
    unsigned exit_observed, instances;
};
struct nabu_ui_event {
    unsigned ready, emitted, target;
    int pid, result;
    uint64_t uniqueid, tid, seq, us;
    const char *stage;
};
static struct nabu_ui_slot nabu_ui_slots[NABU_UI_TARGETS];
static struct nabu_ui_event nabu_ui_events[NABU_UI_MAX_EVENTS];
static const char *const nabu_ui_names[NABU_UI_TARGETS] = {
    "SpringBoard", "backboardd", "runningboardd"
};
static const char *const nabu_ui_paths[NABU_UI_TARGETS] = {
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
    "/usr/libexec/backboardd", "/usr/libexec/runningboardd"
};
static int nabu_ui_enabled_cache = -1;
static unsigned nabu_ui_closed, nabu_ui_event_count, nabu_ui_event_dropped, nabu_ui_seen_mask;
static unsigned nabu_ui_sample_busy, nabu_ui_sample_contended, nabu_ui_samples, nabu_ui_text_dropped;
static uint64_t nabu_ui_next_us;
extern void nabu_capture_append(const char *, unsigned);
extern void nabu_gpu_userprobe_exec_snapshot(uint32_t out[6]);

static int
nabu_ui_enabled(void)
{
    int value = __atomic_load_n(&nabu_ui_enabled_cache, __ATOMIC_ACQUIRE);
    if (value < 0) {
        unsigned requested = 0;
        value = PE_parse_boot_argn("nabu-ui-watch", &requested, sizeof(requested)) && requested == 1;
        int unset = -1;
        __atomic_compare_exchange_n(&nabu_ui_enabled_cache, &unset, value, 0,
            __ATOMIC_RELEASE, __ATOMIC_RELAXED);
        value = __atomic_load_n(&nabu_ui_enabled_cache, __ATOMIC_ACQUIRE);
    }
    return value == 1;
}

static uint64_t
nabu_ui_now_us(void)
{
    uint64_t ns = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
    return ns / 1000;
}

static int
nabu_ui_target(const char *name, int path)
{
    if (!name) return -1;
    for (unsigned i = 0; i < NABU_UI_TARGETS; ++i) {
        if (!strcmp(name, path ? nabu_ui_paths[i] : nabu_ui_names[i])) return (int)i;
    }
    return -1;
}

int
nabu_ui_watch_activate_image_v2(struct image_params *imgp, int *target)
{
    *target = -1;
    /* The scalar is copied while excpath is valid, directly to this caller.
     * No shared exec table or pointer survives the synchronous activation. */
    return exec_activate_image(imgp, target);
}

static void
nabu_ui_emit(const char *line, int bytes)
{
    if (bytes > 0 && bytes < 256) nabu_capture_append(line, (unsigned)bytes);
    else __atomic_fetch_add(&nabu_ui_text_dropped, 1, __ATOMIC_RELAXED);
}

static unsigned
nabu_ui_event_note(unsigned target, proc_t p, thread_t thread, const char *stage, int result)
{
    if (!nabu_ui_enabled() || __atomic_load_n(&nabu_ui_closed, __ATOMIC_ACQUIRE)) return 0;
    __atomic_fetch_or(&nabu_ui_seen_mask, 1U << target, __ATOMIC_RELAXED);
    unsigned at = __atomic_load_n(&nabu_ui_event_count, __ATOMIC_RELAXED);
    if (at >= NABU_UI_MAX_EVENTS || !__atomic_compare_exchange_n(&nabu_ui_event_count,
            &at, at + 1, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        __atomic_fetch_add(&nabu_ui_event_dropped, 1, __ATOMIC_RELAXED);
        return 0;
    }
    struct nabu_ui_event *event = &nabu_ui_events[at];
    event->target = target;
    event->pid = p ? proc_getpid(p) : 0;
    event->uniqueid = p ? proc_uniqueid(p) : 0;
    event->tid = thread ? thread_tid(thread) : 0;
    event->seq = at + 1;
    event->us = nabu_ui_now_us();
    event->stage = stage;
    event->result = result;
    __atomic_store_n(&event->ready, 1, __ATOMIC_RELEASE);
    return at + 1;
}

void
nabu_ui_watch_activation(proc_t p, int target, unsigned returned, int result)
{
    if (!nabu_ui_enabled()) return;
    if (target >= 0 && target < NABU_UI_TARGETS) nabu_ui_event_note((unsigned)target, p, NULL,
        returned ? "activation_return" : "activation_enter", result);
}

void
nabu_ui_watch_signature(proc_t p, int target, int result)
{
    if (!nabu_ui_enabled() || !p) return;
    if (target >= 0 && target < NABU_UI_TARGETS)
        nabu_ui_event_note((unsigned)target, p, NULL, "signature_return", result);
}

void
nabu_ui_watch_release_ready(proc_t p, thread_t thread, int target, int error, int committed, int no_exec)
{
    if (!nabu_ui_enabled() || !p || no_exec ||
        __atomic_load_n(&nabu_ui_closed, __ATOMIC_ACQUIRE)) return;
    if (target < 0 || target >= NABU_UI_TARGETS) return;
    unsigned release_seq = nabu_ui_event_note((unsigned)target, p, thread,
        !committed ? "not_committed" : error ? "final_error" : "release_ready", error);
    if (error || !committed || !thread) return;
    if (nabu_ui_target(p->p_comm, 0) != target) {
        nabu_ui_event_note((unsigned)target, p, thread, "identity_mismatch", 0);
        return;
    }
    struct nabu_ui_slot *slot = &nabu_ui_slots[target];
    const uint64_t tid = thread_tid(thread);
    __atomic_store_n(&slot->latest_tid, tid, __ATOMIC_RELEASE);
    __atomic_fetch_add(&slot->instances, 1, __ATOMIC_RELAXED);
    unsigned expected = NABU_UI_EMPTY;
    if (!__atomic_compare_exchange_n(&slot->phase, &expected, NABU_UI_CLAIMING, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        if (expected == NABU_UI_READY && slot->tid != tid)
            nabu_ui_event_note((unsigned)target, p, thread, "new_instance", 0);
        return;
    }
    /* The caller already holds the main-thread reference returned by exec. */
    thread_reference(thread);
    slot->thread = thread;
    slot->pid = proc_getpid(p);
    slot->uniqueid = proc_uniqueid(p);
    slot->tid = tid;
    slot->first_seq = release_seq;
    slot->first_us = nabu_ui_now_us();
    expected = NABU_UI_CLAIMING;
    if (!__atomic_compare_exchange_n(&slot->phase, &expected, NABU_UI_READY, 0,
            __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
        /* A closing writer leaves cleanup to an in-flight publisher. */
        __atomic_store_n(&slot->thread, (thread_t)NULL, __ATOMIC_RELAXED);
        thread_deallocate_safe(thread);
    }
}

void
nabu_ui_watch_released(proc_t p, thread_t thread, int target, int error, int committed, int no_exec)
{
    if (!nabu_ui_enabled() || !p || no_exec) return;
    if (target >= 0 && target < NABU_UI_TARGETS) nabu_ui_event_note((unsigned)target, p, thread,
        committed && !error ? "exec_released" : "release_failed", error);
}

void
nabu_ui_watch_exit_note(proc_t p, int status)
{
    if (!nabu_ui_enabled() || !p) return;
    int target = nabu_ui_target(p->p_comm, 0);
    if (target < 0) return;
    struct nabu_ui_slot *slot = &nabu_ui_slots[target];
    int pid = proc_getpid(p);
    uint64_t uid = proc_uniqueid(p);
    int known = 0;
    if (__atomic_load_n(&slot->phase, __ATOMIC_ACQUIRE) == NABU_UI_READY &&
        slot->pid == pid && slot->uniqueid == uid) {
        __atomic_store_n(&slot->exit_observed, 1, __ATOMIC_RELEASE);
        known = 1;
    }
    for (unsigned i = 0; !known && i < NABU_UI_MAX_EVENTS; ++i) {
        struct nabu_ui_event *event = &nabu_ui_events[i];
        if (__atomic_load_n(&event->ready, __ATOMIC_ACQUIRE) && event->target == (unsigned)target &&
            event->pid == pid && event->uniqueid == uid) known = 1;
    }
    if (known) nabu_ui_event_note((unsigned)target, p, NULL, "exit_observed", status);
}

static void
nabu_ui_close(void)
{
    __atomic_store_n(&nabu_ui_closed, 1, __ATOMIC_RELEASE);
    for (unsigned i = 0; i < NABU_UI_TARGETS; ++i) {
        struct nabu_ui_slot *slot = &nabu_ui_slots[i];
        unsigned phase = __atomic_exchange_n(&slot->phase, NABU_UI_CLOSED, __ATOMIC_ACQ_REL);
        if (phase == NABU_UI_READY) {
            thread_t thread = __atomic_exchange_n(&slot->thread, (thread_t)NULL, __ATOMIC_ACQ_REL);
            if (thread) thread_deallocate_safe(thread);
        }
    }
}

void
nabu_ui_watch_snapshot(uint32_t out[6])
{
    nabu_gpu_userprobe_exec_snapshot(out);
    if (!nabu_ui_enabled() || __atomic_load_n(&nabu_ui_closed, __ATOMIC_ACQUIRE)) return;
    unsigned expected = 0;
    if (!__atomic_compare_exchange_n(&nabu_ui_sample_busy, &expected, 1, 0,
            __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        __atomic_fetch_add(&nabu_ui_sample_contended, 1, __ATOMIC_RELAXED);
        return;
    }
    uint64_t now = nabu_ui_now_us();
    if (nabu_ui_samples >= NABU_UI_MAX_SAMPLES || now < nabu_ui_next_us) {
        __atomic_store_n(&nabu_ui_sample_busy, 0, __ATOMIC_RELEASE);
        return;
    }
    nabu_ui_next_us = now > UINT64_MAX - 10000000 ? UINT64_MAX : now + 10000000;
    const unsigned sample = ++nabu_ui_samples;
    char line[256];
    unsigned event_count = __atomic_load_n(&nabu_ui_event_count, __ATOMIC_ACQUIRE);
    if (event_count > NABU_UI_MAX_EVENTS) event_count = NABU_UI_MAX_EVENTS;
    unsigned pending = 0;
    for (unsigned i = 0; i < event_count; ++i) {
        struct nabu_ui_event *event = &nabu_ui_events[i];
        if (!__atomic_load_n(&event->ready, __ATOMIC_ACQUIRE)) { ++pending; continue; }
        if (event->emitted) continue;
        nabu_ui_emit(line, snprintf(line, sizeof(line),
            "NabuUI: event=%llu target=%s pid=%d uid=%llu tid=%llu us=%llu stage=%s result=%d\n",
            (unsigned long long)event->seq, nabu_ui_names[event->target], event->pid,
            (unsigned long long)event->uniqueid, (unsigned long long)event->tid,
            (unsigned long long)event->us, event->stage, event->result));
        event->emitted = 1;
    }
    for (unsigned i = 0; i < NABU_UI_TARGETS; ++i) {
        struct nabu_ui_slot *slot = &nabu_ui_slots[i];
        unsigned phase = __atomic_load_n(&slot->phase, __ATOMIC_ACQUIRE);
        if (phase != NABU_UI_READY) {
            nabu_ui_emit(line, snprintf(line, sizeof(line),
                "NabuUI: sample=%u target=%s status=%s phase=%u first_incarnation=1\n",
                sample, nabu_ui_names[i], phase == NABU_UI_EMPTY &&
                    !(__atomic_load_n(&nabu_ui_seen_mask, __ATOMIC_RELAXED) & (1U << i)) ?
                    "not_observed" : "not_published", phase));
            continue;
        }
        thread_t thread = __atomic_load_n(&slot->thread, __ATOMIC_ACQUIRE);
        uint32_t state = 0, hint = 0;
        uint64_t wait = 0;
        const char *status = "sample_unavailable";
        if (thread) {
            int sampled = nabu_ui_watch_thread_state(thread, &state, &hint, &wait);
            status = sampled == 0 ? "sample_ok" : sampled == 1 ? "lock_busy" : "sample_unavailable";
        }
        unsigned exited = __atomic_load_n(&slot->exit_observed, __ATOMIC_ACQUIRE);
        unsigned instances = __atomic_load_n(&slot->instances, __ATOMIC_RELAXED);
        uint64_t latest_tid = __atomic_load_n(&slot->latest_tid, __ATOMIC_ACQUIRE);
        nabu_ui_emit(line, snprintf(line, sizeof(line),
            "NabuUI: sample=%u target=%s pid=%d uid=%llu tid=%llu status=%s state=%x hint=%u wait_tag=%llx exit=%u stale=%u instances=%u first_incarnation=1\n",
            sample, nabu_ui_names[i], slot->pid, (unsigned long long)slot->uniqueid,
            (unsigned long long)slot->tid, status, state, hint, (unsigned long long)wait,
            exited, exited || latest_tid != slot->tid ||
            (state & (NABU_UI_TH_TERMINATE | NABU_UI_TH_TERMINATE2)), instances));
    }
    nabu_ui_emit(line, snprintf(line, sizeof(line),
        "NabuUI: budget sample=%u us=%llu events=%u pending=%u dropped=%u texts_dropped=%u target_link=direct sample_contended=%u closing=%u snapshot=non-atomic\n",
        sample, (unsigned long long)now, event_count, pending,
        __atomic_load_n(&nabu_ui_event_dropped, __ATOMIC_RELAXED),
        __atomic_load_n(&nabu_ui_text_dropped, __ATOMIC_RELAXED),
        __atomic_load_n(&nabu_ui_sample_contended, __ATOMIC_RELAXED), sample == NABU_UI_MAX_SAMPLES));
    if (sample == NABU_UI_MAX_SAMPLES) nabu_ui_close();
    __atomic_store_n(&nabu_ui_sample_busy, 0, __ATOMIC_RELEASE);
}

'''


def _once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('UI watch source drift: ' + before[:90])
    return text.replace(before, after, 1)


def exec_source(text, restore=False):
    marker = '/* NABU_UI_WATCH_V'
    if marker in text:
        if text.count(EXEC_HELPER) != 1 or any(text.count(after) != 1 for _, after in EXEC_PAIRS):
            raise ValueError('UI watch exec source changed after patching')
        if not restore:
            return text
        for before, after in reversed(EXEC_PAIRS):
            text = _once(text, after, before)
        return _once(text, EXEC_HELPER, '')
    if restore:
        return text
    if 'NABU_GPU_USERPROBE_PROCESS_V1' not in text or 'NABU_GPU_USERPROBE_JOB_V1' not in text:
        raise ValueError('UI watch requires the original GPU probe source first')
    text = _once(text, 'static int\nexec_activate_image(struct image_params *imgp)\n{\n',
                 EXEC_HELPER + 'static int\nexec_activate_image(struct image_params *imgp)\n{\n')
    for before, after in EXEC_PAIRS:
        text = _once(text, before, after)
    return text


def exit_source(text, restore=False):
    marker = '/* NABU_UI_WATCH_EXIT_V1 */'
    if marker in text:
        if any(text.count(after) != 1 for _, after in EXIT_PAIRS):
            raise ValueError('UI watch exit source changed after patching')
        if restore:
            for before, after in reversed(EXIT_PAIRS):
                text = _once(text, after, before)
        return text
    if restore:
        return text
    if 'NABU_GPU_USERPROBE_EXIT_V1' not in text:
        raise ValueError('UI watch requires the original GPU exit source first')
    for before, after in EXIT_PAIRS:
        text = _once(text, before, after)
    return text

EXEC_PAIRS = (
    ('static int exec_activate_image(struct image_params *imgp);\n',
     'static int exec_activate_image(struct image_params *imgp, int *nabu_ui_target_out);\n'),
    ('static int\nexec_activate_image(struct image_params *imgp)\n{\n',
     'static int\nexec_activate_image(struct image_params *imgp, int *nabu_ui_target_out)\n{\n'),
    (r'''	/* NABU_GPU_USERPROBE_JOB_V1 */
	uint32_t nabu_probe = 0;
	if (PE_parse_boot_argn("nabu-gpu-userprobe", &nabu_probe, sizeof(nabu_probe)) && nabu_probe == 1) {
		extern void nabu_gpu_userprobe_exec_snapshot(uint32_t out[6]);
		extern void (*nabu_log_probe_process_snapshot)(uint32_t *);
		__atomic_store_n(&nabu_log_probe_process_snapshot, nabu_gpu_userprobe_exec_snapshot, __ATOMIC_RELEASE);
		native_gpu_addon_install(p, scratch);
		/* Four files, five with the owner-signed Turnip library for the Vulkan known-image test,
		 * or eight/nine/ten with the owner-signed NativeAdrenoMetal bundle (nine: publish marker,
		 * ten/eleven: publish marker with the pipeline-cache pack and/or the client list). */
		if ((native_gpu_addon_files != 4 && native_gpu_addon_files != 5 && native_gpu_addon_files != 8 &&
		    native_gpu_addon_files != 9 && native_gpu_addon_files != 10 && native_gpu_addon_files != 11) ||
		    native_gpu_addon_failed || native_gpu_addon_error) {
			printf("NabuGPU: userprobe addon refused files=%d failed=%d error=%d render_proof=0\n",
			    native_gpu_addon_files, native_gpu_addon_failed, native_gpu_addon_error);
			return;
		}
		static const char source[] = "/private/var/ngpu/daemons";
		static const char point[] = "/System/Library/LaunchDaemons";
		native_gpu_addon_mount(p, scratch, 0x600, source, sizeof(source), point, sizeof(point),
		    "/System/Library/LaunchDaemons/com.apple.backboardd.plist",
		    "/System/Library/LaunchDaemons/org.hackios.nabu-gpu-userprobe.plist",
		    &native_gpu_addon2_stage, &native_gpu_addon2_status);
		printf("NabuGPU: userprobe addon files=%d written=%d same=%d job_stage=%d job_status=%d render_proof=0\n",
		    native_gpu_addon_files, native_gpu_addon_written, native_gpu_addon_same,
		    native_gpu_addon2_stage, native_gpu_addon2_status);
		if (native_gpu_addon2_stage != 5 || native_gpu_addon2_status) return;
		/* The platform sandbox lets xpcproxy exec a regular file outside /private/var
		 * only, so the cached job names the probe through this /usr/bin union view
		 * (UniXNU T733 does the same for its owner executable). */
		static const char bin_source[] = "/private/var/ngpu/bin";
		static const char bin_point[] = "/usr/bin";
		native_gpu_addon_mount(p, scratch, 0x800, bin_source, sizeof(bin_source), bin_point, sizeof(bin_point),
		    "/usr/bin/IOMFB_FDR_Loader", "/usr/bin/nabu-gpu-userprobe",
		    &native_gpu_addon3_stage, &native_gpu_addon3_status);
		printf("NabuGPU: userprobe bin_stage=%d bin_status=%d render_proof=0\n",
		    native_gpu_addon3_stage, native_gpu_addon3_status);
		if (native_gpu_addon3_stage != 5 || native_gpu_addon3_status) return;
		/* The original launchd accepts system jobs from its verified cache.
		 * Keep every original job and let its original loader authenticate this
		 * owner-signed cache through the explicitly supplied trust module. */
		static const char cache_source[] = "/private/var/ngpu/cache";
		static const char cache_point[] = "/System/Library/xpc";
		native_gpu_addon_mount(p, scratch, 0x400, cache_source, sizeof(cache_source),
		    cache_point, sizeof(cache_point), "/System/Library/xpc/foreground_user_endpoints.plist",
		    "/System/Library/xpc/launchd.plist.sig", &native_gpu_addon_stage, &native_gpu_addon_status);
		printf("NabuGPU: userprobe cache_stage=%d cache_status=%d owner_signed=1 original_jobs_preserved=1 render_proof=0\n",
		    native_gpu_addon_stage, native_gpu_addon_status);
		if (native_gpu_addon_stage != 5 || native_gpu_addon_status ||
		    (native_gpu_addon_files < 8 || native_gpu_addon_files > 11)) return;
		/* NABU_GPU_USERPROBE_PLUGIN_V1: the original Metal discovery loads
		 * /System/Library/Extensions/<MetalPluginName>.bundle; present the owner bundle there,
		 * with the sealed A10 bundle still visible below it. Scratch 0xa00..0xb1a, below mkdir's 0xc00. */
		static volatile int nabu_gpu_plugin_stage = 0, nabu_gpu_plugin_status = -1;
		const int publish = native_gpu_addon_files >= 9;
		vnode_t marker = NULLVP;
		if (!publish && !vnode_lookup("/private/var/ngpu/addons/NativeAdrenoMetal.publish", 0, &marker, vfs_context_current())) {
			/* A test-mode addon must not inherit a publish marker from an earlier boot. */
			vnode_put(marker);
			nabu_gpu_plugin_status = EEXIST;
		} else {
			static const char plugin_source[] = "/private/var/ngpu/addons";
			static const char plugin_point[] = "/System/Library/Extensions";
			native_gpu_addon_mount(p, scratch, 0xa00, plugin_source, sizeof(plugin_source), plugin_point,
			    sizeof(plugin_point), "/System/Library/Extensions/AGXMetalA10.bundle",
			    "/System/Library/Extensions/NativeAdrenoMetal.bundle/Info.plist",
			    &nabu_gpu_plugin_stage, &nabu_gpu_plugin_status);
		}
		printf("NabuGPU: userprobe plugin_stage=%d plugin_status=%d publish=%d render_proof=0\n",
		    nabu_gpu_plugin_stage, nabu_gpu_plugin_status, publish);
		return;
	}
''',
     r'''#define nabu_gpu_userprobe_exec_snapshot nabu_ui_watch_snapshot
	/* NABU_GPU_USERPROBE_JOB_V1 */
	uint32_t nabu_probe = 0;
	if (PE_parse_boot_argn("nabu-gpu-userprobe", &nabu_probe, sizeof(nabu_probe)) && nabu_probe == 1) {
		extern void nabu_gpu_userprobe_exec_snapshot(uint32_t out[6]);
		extern void (*nabu_log_probe_process_snapshot)(uint32_t *);
		__atomic_store_n(&nabu_log_probe_process_snapshot, nabu_gpu_userprobe_exec_snapshot, __ATOMIC_RELEASE);
		native_gpu_addon_install(p, scratch);
		/* Four files, five with the owner-signed Turnip library for the Vulkan known-image test,
		 * or eight/nine/ten with the owner-signed NativeAdrenoMetal bundle (nine: publish marker,
		 * ten/eleven: publish marker with the pipeline-cache pack and/or the client list). */
		if ((native_gpu_addon_files != 4 && native_gpu_addon_files != 5 && native_gpu_addon_files != 8 &&
		    native_gpu_addon_files != 9 && native_gpu_addon_files != 10 && native_gpu_addon_files != 11) ||
		    native_gpu_addon_failed || native_gpu_addon_error) {
			printf("NabuGPU: userprobe addon refused files=%d failed=%d error=%d render_proof=0\n",
			    native_gpu_addon_files, native_gpu_addon_failed, native_gpu_addon_error);
			return;
		}
		static const char source[] = "/private/var/ngpu/daemons";
		static const char point[] = "/System/Library/LaunchDaemons";
		native_gpu_addon_mount(p, scratch, 0x600, source, sizeof(source), point, sizeof(point),
		    "/System/Library/LaunchDaemons/com.apple.backboardd.plist",
		    "/System/Library/LaunchDaemons/org.hackios.nabu-gpu-userprobe.plist",
		    &native_gpu_addon2_stage, &native_gpu_addon2_status);
		printf("NabuGPU: userprobe addon files=%d written=%d same=%d job_stage=%d job_status=%d render_proof=0\n",
		    native_gpu_addon_files, native_gpu_addon_written, native_gpu_addon_same,
		    native_gpu_addon2_stage, native_gpu_addon2_status);
		if (native_gpu_addon2_stage != 5 || native_gpu_addon2_status) return;
		/* The platform sandbox lets xpcproxy exec a regular file outside /private/var
		 * only, so the cached job names the probe through this /usr/bin union view
		 * (UniXNU T733 does the same for its owner executable). */
		static const char bin_source[] = "/private/var/ngpu/bin";
		static const char bin_point[] = "/usr/bin";
		native_gpu_addon_mount(p, scratch, 0x800, bin_source, sizeof(bin_source), bin_point, sizeof(bin_point),
		    "/usr/bin/IOMFB_FDR_Loader", "/usr/bin/nabu-gpu-userprobe",
		    &native_gpu_addon3_stage, &native_gpu_addon3_status);
		printf("NabuGPU: userprobe bin_stage=%d bin_status=%d render_proof=0\n",
		    native_gpu_addon3_stage, native_gpu_addon3_status);
		if (native_gpu_addon3_stage != 5 || native_gpu_addon3_status) return;
		/* The original launchd accepts system jobs from its verified cache.
		 * Keep every original job and let its original loader authenticate this
		 * owner-signed cache through the explicitly supplied trust module. */
		static const char cache_source[] = "/private/var/ngpu/cache";
		static const char cache_point[] = "/System/Library/xpc";
		native_gpu_addon_mount(p, scratch, 0x400, cache_source, sizeof(cache_source),
		    cache_point, sizeof(cache_point), "/System/Library/xpc/foreground_user_endpoints.plist",
		    "/System/Library/xpc/launchd.plist.sig", &native_gpu_addon_stage, &native_gpu_addon_status);
		printf("NabuGPU: userprobe cache_stage=%d cache_status=%d owner_signed=1 original_jobs_preserved=1 render_proof=0\n",
		    native_gpu_addon_stage, native_gpu_addon_status);
		if (native_gpu_addon_stage != 5 || native_gpu_addon_status ||
		    (native_gpu_addon_files < 8 || native_gpu_addon_files > 11)) return;
		/* NABU_GPU_USERPROBE_PLUGIN_V1: the original Metal discovery loads
		 * /System/Library/Extensions/<MetalPluginName>.bundle; present the owner bundle there,
		 * with the sealed A10 bundle still visible below it. Scratch 0xa00..0xb1a, below mkdir's 0xc00. */
		static volatile int nabu_gpu_plugin_stage = 0, nabu_gpu_plugin_status = -1;
		const int publish = native_gpu_addon_files >= 9;
		vnode_t marker = NULLVP;
		if (!publish && !vnode_lookup("/private/var/ngpu/addons/NativeAdrenoMetal.publish", 0, &marker, vfs_context_current())) {
			/* A test-mode addon must not inherit a publish marker from an earlier boot. */
			vnode_put(marker);
			nabu_gpu_plugin_status = EEXIST;
		} else {
			static const char plugin_source[] = "/private/var/ngpu/addons";
			static const char plugin_point[] = "/System/Library/Extensions";
			native_gpu_addon_mount(p, scratch, 0xa00, plugin_source, sizeof(plugin_source), plugin_point,
			    sizeof(plugin_point), "/System/Library/Extensions/AGXMetalA10.bundle",
			    "/System/Library/Extensions/NativeAdrenoMetal.bundle/Info.plist",
			    &nabu_gpu_plugin_stage, &nabu_gpu_plugin_status);
		}
		printf("NabuGPU: userprobe plugin_stage=%d plugin_status=%d publish=%d render_proof=0\n",
		    nabu_gpu_plugin_stage, nabu_gpu_plugin_status, publish);
		return;
	}
#undef nabu_gpu_userprobe_exec_snapshot
'''),
    (r'''	int nabu_probe_target = 0; /* NABU_GPU_USERPROBE_EXEC_V1 */
''',
     r'''	int nabu_probe_target = 0; /* NABU_GPU_USERPROBE_EXEC_V1 */
	int nabu_ui_activation_target = -1;
'''),
    (r'''	nabu_probe_target = !strcmp(excpath, "/usr/bin/nabu-gpu-userprobe") ||
	    !strcmp(excpath, "/private/var/ngpu/bin/nabu-gpu-userprobe");
	if (nabu_probe_target) nabu_gpu_userprobe_exec_note(0, proc_getpid(p), 0);
''',
     r'''	nabu_probe_target = !strcmp(excpath, "/usr/bin/nabu-gpu-userprobe") ||
	    !strcmp(excpath, "/private/var/ngpu/bin/nabu-gpu-userprobe");
	if (nabu_probe_target) nabu_gpu_userprobe_exec_note(0, proc_getpid(p), 0);
	if (nabu_ui_enabled() && !__atomic_load_n(&nabu_ui_closed, __ATOMIC_ACQUIRE)) {
		nabu_ui_activation_target = nabu_ui_target(excpath, 1);
		*nabu_ui_target_out = nabu_ui_activation_target;
		nabu_ui_watch_activation(p, nabu_ui_activation_target, 0, 0);
	}
'''),
    (r'''	if (nabu_probe_target) nabu_gpu_userprobe_exec_note(1, proc_getpid(p), error);
''',
     r'''	if (nabu_probe_target) nabu_gpu_userprobe_exec_note(1, proc_getpid(p), error);
	nabu_ui_watch_activation(p, nabu_ui_activation_target, 1, error);
'''),
    (r'''	boolean_t exec_done = FALSE;
	os_reason_t exec_failure_reason = NULL;
''',
     r'''	boolean_t exec_done = FALSE;
	os_reason_t exec_failure_reason = NULL;
	int nabu_ui_exec_target = -1;
'''),
    (r'''	boolean_t exec_done = FALSE;
	void *inherit = NULL;
''',
     r'''	boolean_t exec_done = FALSE;
	void *inherit = NULL;
	int nabu_ui_exec_target = -1;
'''),
    (r'''	error = exec_activate_image(imgp);
#if defined(HAS_APPLE_PAC)
''',
     r'''	error = nabu_ui_watch_activate_image_v2(imgp, &nabu_ui_exec_target);
#if defined(HAS_APPLE_PAC)
'''),
    (r'''	error = exec_activate_image(imgp);
	/* thread and task ref returned for vfexec case */
''',
     r'''	error = nabu_ui_watch_activate_image_v2(imgp, &nabu_ui_exec_target);
	/* thread and task ref returned for vfexec case */
'''),
    (r'''		error = process_signature(p, imgp);
	}

#if defined(HAS_APPLE_PAC)
''',
     r'''		error = process_signature(p, imgp);
		nabu_ui_watch_signature(p, nabu_ui_exec_target, error);
	}

#if defined(HAS_APPLE_PAC)
'''),
    (r'''		error = process_signature(p, imgp);

		/*
		 * Pay for our earlier safety; deliver the delayed signals from
''',
     r'''		error = process_signature(p, imgp);
		if (!spawn_no_exec) nabu_ui_watch_signature(p, nabu_ui_exec_target, error);

		/*
		 * Pay for our earlier safety; deliver the delayed signals from
'''),
    (r'''		/* wake up the new thread */
		task_clear_return_wait(get_threadtask(imgp->ip_new_thread), clearwait_flags);
''',
     r'''		/* wake up the new thread */
		nabu_ui_watch_release_ready(p, imgp->ip_new_thread, nabu_ui_exec_target, error, exec_done && !task_is_exec_copy(get_threadtask(imgp->ip_new_thread)), spawn_no_exec);
		task_clear_return_wait(get_threadtask(imgp->ip_new_thread), clearwait_flags);
		nabu_ui_watch_released(p, imgp->ip_new_thread, nabu_ui_exec_target, error, exec_done && !task_is_exec_copy(get_threadtask(imgp->ip_new_thread)), spawn_no_exec);
'''),
    (r'''			/* wake up the new exec thread */
			task_clear_return_wait(get_threadtask(imgp->ip_new_thread), clearwait_flags);
''',
     r'''			/* wake up the new exec thread */
			nabu_ui_watch_release_ready(p, imgp->ip_new_thread, nabu_ui_exec_target, error, exec_done && !task_is_exec_copy(get_threadtask(imgp->ip_new_thread)), 0);
			task_clear_return_wait(get_threadtask(imgp->ip_new_thread), clearwait_flags);
			nabu_ui_watch_released(p, imgp->ip_new_thread, nabu_ui_exec_target, error, exec_done && !task_is_exec_copy(get_threadtask(imgp->ip_new_thread)), 0);
'''),
)

EXIT_PAIRS = (
    (r'''	/* NABU_GPU_USERPROBE_EXIT_V1: a successful exit must also leave evidence. */
	extern void nabu_gpu_userprobe_exit_note(int, int);
	nabu_gpu_userprobe_exit_note(proc_getpid(p), rv);
''',
     r'''	/* NABU_GPU_USERPROBE_EXIT_V1: a successful exit must also leave evidence. */
	extern void nabu_gpu_userprobe_exit_note(int, int);
	nabu_gpu_userprobe_exit_note(proc_getpid(p), rv);
	/* NABU_UI_WATCH_EXIT_V1 */
	extern void nabu_ui_watch_exit_note(proc_t, int);
	nabu_ui_watch_exit_note(p, rv);
'''),
)

THREAD_HELPER = r'''/* NABU_UI_WATCH_THREAD_V1: scheduler fields stay in this private osfmk unit. */
int
nabu_ui_watch_thread_state(thread_t thread, uint32_t *state, uint32_t *hint, uint64_t *wait_tag)
{
	if (thread == THREAD_NULL || state == NULL || hint == NULL || wait_tag == NULL) return 2;
	uint64_t event = 0, tag = 0;
	spl_t s = splsched();
	if (!simple_lock_try(&thread->sched_lock, &thread_lck_grp)) {
		splx(s);
		return 1;
	}
	*state = (uint32_t)thread->state;
	*hint = (uint32_t)thread->block_hint;
	event = (uint64_t)thread->wait_event;
	thread_unlock(thread);
	splx(s);
	if (event) {
		tag = event ^ thread_tid(thread);
		tag = (tag ^ (tag >> 30)) * 0xbf58476d1ce4e5b9ULL;
		tag = (tag ^ (tag >> 27)) * 0x94d049bb133111ebULL;
		tag = (tag ^ (tag >> 31)) & 0xffffffff;
	}
	*wait_tag = tag;
	return 0;
}
'''

THREAD_PAIRS = (
    (r'''/* Drop a thread refcount safely without triggering a zfree */
void
thread_deallocate_safe(thread_t thread)
{
''',
     r'''/* NABU_UI_WATCH_THREAD_V1: scheduler fields stay in this private osfmk unit. */
int
nabu_ui_watch_thread_state(thread_t thread, uint32_t *state, uint32_t *hint, uint64_t *wait_tag)
{
	if (thread == THREAD_NULL || state == NULL || hint == NULL || wait_tag == NULL) return 2;
	uint64_t event = 0, tag = 0;
	spl_t s = splsched();
	if (!simple_lock_try(&thread->sched_lock, &thread_lck_grp)) {
		splx(s);
		return 1;
	}
	*state = (uint32_t)thread->state;
	*hint = (uint32_t)thread->block_hint;
	event = (uint64_t)thread->wait_event;
	thread_unlock(thread);
	splx(s);
	if (event) {
		tag = event ^ thread_tid(thread);
		tag = (tag ^ (tag >> 30)) * 0xbf58476d1ce4e5b9ULL;
		tag = (tag ^ (tag >> 27)) * 0x94d049bb133111ebULL;
		tag = (tag ^ (tag >> 31)) & 0xffffffff;
	}
	*wait_tag = tag;
	return 0;
}
/* Drop a thread refcount safely without triggering a zfree */
void
thread_deallocate_safe(thread_t thread)
{
'''),
)


def thread_source(text, restore=False):
    marker = '/* NABU_UI_WATCH_THREAD_V1:'
    if marker in text:
        if text.count(THREAD_HELPER) != 1 or any(text.count(after) != 1 for _, after in THREAD_PAIRS):
            raise ValueError('UI watch thread source changed after patching')
        if restore:
            for before, after in reversed(THREAD_PAIRS):
                text = _once(text, after, before)
        return text
    if restore:
        return text
    for before, after in THREAD_PAIRS:
        text = _once(text, before, after)
    return text
