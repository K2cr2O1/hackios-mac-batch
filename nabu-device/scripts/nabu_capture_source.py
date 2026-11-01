#!/usr/bin/env python3
"""Apply the opt-in recorder after upstream XNU patches, before compilation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil


def gpu_userprobe_data_source(text, restore=False, exit_observer=False):
    # Disabled profiles do not load the probe transform or its boot inputs.
    import importlib.util
    spec = importlib.util.spec_from_file_location('gpu_userprobe_boot_source',
        Path(__file__).with_name('nabu_gpu_userprobe_source.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.exit_source(text, restore=restore) if exit_observer else module.data_source(text, restore=restore)


def ui_watch_source(text, restore=False, exit_observer=False, thread_observer=False):
    # Only enabled builds or explicit restoration load this optional module.
    import importlib.util
    spec = importlib.util.spec_from_file_location('nabu_ui_watch_source',
        Path(__file__).with_name('nabu_ui_watch_source.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if thread_observer:
        return module.thread_source(text, restore=restore)
    transform = module.exit_source if exit_observer else module.exec_source
    return transform(text, restore=restore)


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Logging source drift: ' + old[:100])
    return text.replace(old, new, 1)


def patch_console(text):
    marker = '/* NABU_CAPTURE_V2_1 console producer hooks */'
    if marker in text:
        for name in ('console_write(char *str, int size)', 'console_write_unbuffered(char c)'):
            if text.count(name) != 1:
                raise ValueError('Recorder source changed after patching')
        return text
    if 'NABU_CAPTURE_' in text:
        raise ValueError('Older recorder hook present; use a fresh source tree')
    text = replace_once(text, 'void\nconsole_write(char *str, int size)\n{\n',
        marker + '\n#define NABU_LOG_IMPLEMENTATION\n#include "NabuLogCore.h"\n\n'
        'void nabu_console_write_captured(char *, int);\n'
        'static void nabu_console_write_raw(char *, int);\n'
        'void\nconsole_write(char *str, int size)\n{\n'
        '\tif (size > 0) nabu_capture_append(str, (unsigned)size);\n'
        '\tnabu_console_write_raw(str, size);\n}\n\n'
        'void\nnabu_console_write_captured(char *str, int size)\n{\n'
        '\tnabu_console_write_raw(str, size);\n}\n\n'
        'static void\nnabu_console_write_raw(char *str, int size)\n{\n')
    return replace_once(text, 'console_write_unbuffered(char c)\n{\n',
                        'console_write_unbuffered(char c)\n{\n\tnabu_capture_append(&c, 1);\n')


def patch_general(text):
    marker = '/* NABU_CAPTURE_V2 capture before printbuf truncation */'
    if marker in text:
        return text
    text = replace_once(text, 'void\nconsole_printbuf_putc(int ch, void * arg)\n{\n',
        marker + '\nextern void nabu_capture_append(const char *, unsigned);\n'
        'extern void nabu_console_write_captured(char *, int);\n'
        'void\nconsole_printbuf_putc(int ch, void * arg)\n{\n'
        '\tchar captured = (char)ch;\n\tnabu_capture_append(&captured, 1);\n')
    call = 'console_write(info->str, info->pos);'
    if text.count(call) != 3:
        raise ValueError('Expected all three printbuf flush calls')
    return text.replace(call, 'nabu_console_write_captured(info->str, info->pos);')


def patch_kprintf(text):
    marker = '/* NABU_CAPTURE_V2 hardware kprintf producer */'
    if marker in text:
        return text
    return replace_once(text, 'static void\nserial_putc_crlf(char c)\n{\n',
        marker + '\nextern void nabu_capture_append(const char *, unsigned);\n'
        'static void\nserial_putc_crlf(char c)\n{\n\tnabu_capture_append(&c, 1);\n')


def patch_bsd_init(text):
    marker = '/* NABU_CAPTURE_V2_2 opt-in diagnostic calls */'
    if marker in text:
        return text
    old = '/* NABU_CAPTURE_V2_1 opt-in USB probe call */'
    if old in text:
        # Upgrade a tree prepared by the earlier hook without re-injecting.
        text = replace_once(text, old, marker)
        return replace_once(text, '\t\tnabu_usb_probe_start();\n',
            '\t\tnabu_usb_probe_start();\n'
            '\t\textern void nabu_heartbeat_start(void);\n'
            '\t\tnabu_heartbeat_start();\n')
    return replace_once(text, '\tprintf(copyright);\n',
        '\tprintf(copyright);\n'
        '\t' + marker + '\n'
        '\t{\n'
        '\t\textern void nabu_usb_probe_start(void);\n'
        '\t\textern void nabu_heartbeat_start(void);\n'
        '\t\tnabu_usb_probe_start();\n'
        '\t\tnabu_heartbeat_start();\n'
        '\t}\n')


def patch_bsd_init_cdc(text):
    marker = '/* NABU_CAPTURE_V2_1 opt-in USB CDC call after IOKit init */'
    if marker in text:
        return text
    anchor = '\tbsd_autoconf();\n'
    return replace_once(text, anchor, anchor +
        marker + '\n'
        '\t{\n'
        '\t\textern void nabu_usb_cdc_log_start(void);\n'
        '\t\tnabu_usb_cdc_log_start();\n'
        '\t}\n')


def patch_data_mount(text, restore=False):
    marker = '/* NABU_CAPTURE_V2_3 Data mount progress */'
    if restore and marker not in text:
        return text
    if not restore and marker in text:
        return text
    anchor = 'static int\nnative_owner_data_prepare(proc_t p, user_addr_t scratch)\n{\n'
    if anchor not in text:
        # The root-only logging profile has no Data hook.
        return text
    start = text.index(anchor)
    end = text.index('\n}\n#endif', start) + 2
    body = text[start:end]
    edits = ((anchor, anchor + '\t' + marker + '\n'
              '\textern void nabu_data_mount_progress(unsigned, int);\n'),
            ('\tnative_owner_data_stage = 1;\n',
             '\tnative_owner_data_stage = 1;\n\tnabu_data_mount_progress(1, 0);\n'),
            ('\tnative_owner_data_stage = 2;\n',
             '\tnative_owner_data_stage = 2;\n\tnabu_data_mount_progress(2, -1);\n'),
            ('\terror = mount(p, &request, &result);\n',
             '\terror = mount(p, &request, &result);\n\tnabu_data_mount_progress(3, error);\n'),
            ('\terror = vnode_lookup("/private/var", 0, &data_root, vfs_context_current());\n',
             '\terror = vnode_lookup("/private/var", 0, &data_root, vfs_context_current());\n'
             '\tnabu_data_mount_progress(4, error);\n'),
            ('\tif (!error) native_owner_data_stage = 4;\n',
             '\tnabu_data_mount_progress(5, error);\n\tif (!error) native_owner_data_stage = 4;\n'),
            ('\tnative_owner_data_status = error;\n',
             '\tnative_owner_data_status = error;\n\tnabu_data_mount_progress(6, error);\n'))
    for old, new in edits:
        body = replace_once(body, new, old) if restore else replace_once(body, old, new)
    return text[:start] + body + text[end:]


def patch_exit_trace(text):
    marker = '/* NABU_CAPTURE_V2_4 opt-in exit trace */'
    if marker in text:
        return text
    anchor = ('int\n'
              'exit_with_reason(proc_t p, int rv, int *retval, boolean_t thread_can_terminate, boolean_t perf_notify,\n'
              '    int jetsam_flags, struct os_reason *exit_reason)\n'
              '{\n')
    snippet = (marker + '\n'
               '\tint nabu_exit_trace = 0;\n'
               '\tPE_parse_boot_argn("nabu-exit-trace", &nabu_exit_trace, sizeof(nabu_exit_trace));\n'
               '\tif (nabu_exit_trace && (rv || !strcmp(p->p_comm, "SpringBoard") ||\n'
               '\t    !strcmp(p->p_comm, "backboardd") || !strcmp(p->p_comm, "powerd") ||\n'
               '\t    !strcmp(p->p_comm, "servicetimed") || !strcmp(p->p_comm, "chronod") ||\n'
               '\t    !strcmp(p->p_comm, "contextstored") || !strcmp(p->p_comm, "accountsd"))) {\n'
               '\t\tstruct os_reason *nabu_reason = exit_reason ? exit_reason : p->p_exit_reason;\n'
               '\t\tprintf("NABU EXIT comm=%s pid=%d rv=0x%x xstat=0x%x\\n",\n'
               '\t\t    p->p_comm, proc_getpid(p), rv, p->p_xstat);\n'
               '\t\tif (nabu_reason) {\n'
               '\t\t\tchar *nabu_desc = exit_reason_get_string_desc(nabu_reason);\n'
               '\t\t\tprintf("NABU EXIT reason ns=%u code=%llu flags=%llu desc=%.200s\\n",\n'
               '\t\t\t    nabu_reason->osr_namespace, nabu_reason->osr_code,\n'
               '\t\t\t    nabu_reason->osr_flags, nabu_desc ? nabu_desc : "none");\n'
               '\t\t}\n'
               '\t\t/* NABU_CAPTURE_V2_8: a signal exit keeps the Mach exception its thread took\n'
               '\t\t * (ux_exception records it; for EXC_BAD_ACCESS the subcode is the fault address). */\n'
               '\t\tif (WIFSIGNALED(rv) && (WTERMSIG(rv) == SIGBUS || WTERMSIG(rv) == SIGSEGV ||\n'
               '\t\t    WTERMSIG(rv) == SIGILL || WTERMSIG(rv) == SIGTRAP || WTERMSIG(rv) == SIGABRT)) {\n'
               '\t\t\tstruct uthread *nabu_ut = (struct uthread *)get_bsdthread_info(current_thread());\n'
               '\t\t\tif (nabu_ut)\n'
               '\t\t\t\tprintf("NABU EXIT signal=%d exception=%d code=0x%llx subcode=0x%llx\\n",\n'
               '\t\t\t\t    WTERMSIG(rv), nabu_ut->uu_exception, (unsigned long long)nabu_ut->uu_code,\n'
               '\t\t\t\t    (unsigned long long)nabu_ut->uu_subcode);\n'
               '\t\t}\n'
               '\t}\n')
    if text.count(anchor) != 1:
        raise ValueError('Expected one exit_with_reason anchor')
    return text.replace(anchor, anchor + snippet, 1)


def patch_user_exception(text):
    """Observe the saved EL0 state before exception delivery changes it.

    Use task's cached telemetry fields: no shared-region locks, user memory
    reads, disk I/O or exception handling changes on this path.
    """
    marker = '/* NABU_CAPTURE_V2_8 bounded UI exception observation */'
    anchor = ('kern_return_t\nexception_triage(\n'
              '\texception_type_t        exception,\n'
              '\tmach_exception_data_t   code,\n'
              '\tmach_msg_type_number_t  codeCnt)\n{\n')
    call = '\tnabu_trace_user_exception(exception, code, codeCnt);\n'
    if marker in text:
        if text.count(anchor + call) != 1:
            raise ValueError('Exception observer source drift')
        return text
    if any(old in text for old in ('NABU_CAPTURE_V2_5 SpringBoard exception observation',
                                  'NABU_CAPTURE_V2_6 SpringBoard exception observation',
                                  'NABU_CAPTURE_V2_7 bounded UI exception observation')):
        raise ValueError('Use a fresh XNU tree for the panic-state observer upgrade')
    helper = r'''
/* NABU_CAPTURE_V2_8 bounded UI exception observation */
#if defined(__arm64__) && defined(MACH_BSD)
#include <arm/thread.h>
struct vnode;
extern int find_region_details(task_t task, vm_map_offset_t offset, uintptr_t *vnodeaddr, uint32_t *vid,
    uint64_t *start, uint64_t *len);
extern int vnode_getwithvid(struct vnode *vp, uint32_t vid);
extern int vnode_put(struct vnode *vp);
struct vfs_context;
extern struct vfs_context *vfs_context_kernel(void);
extern int build_path(struct vnode *first_vp, char *buff, int buflen, int *outlen, int flags, struct vfs_context *ctx);
static unsigned nabu_exc_calls, nabu_exc_target, nabu_exc_valid;
static unsigned nabu_exc_pid;
static uint64_t nabu_exc_pc, nabu_exc_esr;
static unsigned nabu_ui_exc_emitted[6];
/* The file mapping holding an EL0 address, from the task's own map (no user reads):
 * a SIGBUS from a failed page-in names its image; an anonymous or device mapping prints none. */
static void
nabu_trace_user_region(task_t task, const char *what, uint64_t address)
{
    uintptr_t vnode = 0;
    uint32_t vid = 0;
    uint64_t start = 0, length = 0;
    if (!find_region_details(task, (vm_map_offset_t)address, &vnode, &vid, &start, &length) || !vnode ||
        address < start || address - start >= length) {
        printf("NABU EXC %s=0x%llx file=none\n", what, (unsigned long long)address);
        return;
    }
    char path[160] = "?";
    int bytes = 0;
    if (!vnode_getwithvid((struct vnode *)vnode, vid)) {
        /* Name cache only (BUILDPATH_NO_FS_ENTER): the faulting page-in may be this vnode's. */
        if (build_path((struct vnode *)vnode, path, sizeof(path), &bytes, 0x1, vfs_context_kernel()))
            strlcpy(path, "?", sizeof(path));
        vnode_put((struct vnode *)vnode);
    }
    printf("NABU EXC %s=0x%llx map=0x%llx+0x%llx len=0x%llx file=%s\n", what, (unsigned long long)address,
        (unsigned long long)start, (unsigned long long)(address - start), (unsigned long long)length, path);
}
__attribute__((noinline)) void
nabu_trace_user_exception(exception_type_t exception, mach_exception_data_t code,
    mach_msg_type_number_t codeCnt)
{
    int enabled = 0;
    PE_parse_boot_argn("nabu-exit-trace", &enabled, sizeof(enabled));
    if (!enabled) return;
    __atomic_fetch_add(&nabu_exc_calls, 1, __ATOMIC_RELAXED);
    task_t task = current_task();
    struct proc *p = get_bsdtask_info(task);
    if (!p) return;
    const char *name = proc_name_address(p);
    unsigned target;
    if (!strcmp(name, "SpringBoard")) target = 0;
    else if (!strcmp(name, "Preferences")) target = 1;
    else if (!strcmp(name, "iconservicesagent") || !strcmp(name, "iconservicesagen")) target = 2;
    /* The render server and the other processes that load the GPU plugin (419b: backboardd SIGBUS). */
    else if (!strcmp(name, "backboardd")) target = 3;
    else if (!strncmp(name, "WidgetRenderer", 14)) target = 4;
    else if (!strcmp(name, "mediaserverd")) target = 5;
    else return;
    if (!target) __atomic_fetch_add(&nabu_exc_target, 1, __ATOMIC_RELAXED);
    thread_t thread = current_thread();
    arm_saved_state_t *ss = get_user_regs(thread);
    if (!ss || !is_saved_state64(ss) || (get_saved_state_cpsr(ss) & 0x1f)) return;
    if (!target) {
        __atomic_store_n(&nabu_exc_pid, (unsigned)proc_selfpid(), __ATOMIC_RELAXED);
        __atomic_store_n(&nabu_exc_pc, get_saved_state_pc(ss), __ATOMIC_RELAXED);
        __atomic_store_n(&nabu_exc_esr, get_saved_state_esr(ss), __ATOMIC_RELAXED);
        __atomic_fetch_add(&nabu_exc_valid, 1, __ATOMIC_RELAXED);
    }
    /* Independent budgets prevent a crashing icon service starving PID 1's
     * console or hiding the next Settings/SpringBoard fault. No user reads. */
    if (__atomic_fetch_add(&nabu_ui_exc_emitted[target], 1, __ATOMIC_RELAXED) >= 32) return;
    printf("NABU EXC comm=%s pid=%d tid=%llu type=%d count=%u code0=0x%llx code1=0x%llx\n",
        name, proc_selfpid(), (unsigned long long)thread_tid(thread), exception, codeCnt,
        (unsigned long long)(code && codeCnt > 0 ? code[0] : 0),
        (unsigned long long)(code && codeCnt > 1 ? code[1] : 0));
    printf("NABU EXC pc=0x%llx lr=0x%llx esr=0x%x cpsr=0x%x\n",
        (unsigned long long)get_saved_state_pc(ss),
        (unsigned long long)get_saved_state_lr(ss), get_saved_state_esr(ss), get_saved_state_cpsr(ss));
    printf("NABU EXC sp=0x%llx fp=0x%llx cache_slide=0x%x valid=%u\n",
        (unsigned long long)get_saved_state_sp(ss),
        (unsigned long long)get_saved_state_fp(ss), task->task_shared_region_slide,
        task->task_shared_region_slide != (uint32_t)-1);
    const unsigned char *uuid = task->task_shared_region_uuid;
    printf("NABU EXC cache_uuid=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
        uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
        uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
    /* EXC_BAD_ACCESS: code1 is the fault address; name the file mappings of it and of the PC. */
    if (exception == EXC_BAD_ACCESS && code && codeCnt > 1) {
        nabu_trace_user_region(task, "far", (uint64_t)code[1]);
        nabu_trace_user_region(task, "pcmap", get_saved_state_pc(ss));
    }
}
/* Called only at the already-selected SpringBoard error-exit panic. This
 * reports the exiting thread's saved state, which may differ from the
 * original fault state. Entry counters and last-entry PID keep that boundary
 * explicit. No user dereference, new disk writes, or shared-region locks. */
__attribute__((noinline, noreturn)) void
nabu_trace_exit_panic(int rv, int pid)
{
    task_t task = current_task();
    arm_saved_state_t *ss = get_user_regs(current_thread());
    unsigned state_ok = proc_selfpid() == pid && ss && is_saved_state64(ss);
    const unsigned char *uuid = task->task_shared_region_uuid;
    panic("NABU SB pid=%d rv=%x state=%u hits=%u/%u/%u entrypid=%u entrypc=%llx entryesr=%llx "
        "exitpc=%llx lr=%llx esr=%x cpsr=%x slide=%x uuid=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        pid, rv, state_ok,
        __atomic_load_n(&nabu_exc_calls, __ATOMIC_RELAXED),
        __atomic_load_n(&nabu_exc_target, __ATOMIC_RELAXED),
        __atomic_load_n(&nabu_exc_valid, __ATOMIC_RELAXED),
        __atomic_load_n(&nabu_exc_pid, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&nabu_exc_pc, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&nabu_exc_esr, __ATOMIC_RELAXED),
        (unsigned long long)(state_ok ? get_saved_state_pc(ss) : 0),
        (unsigned long long)(state_ok ? get_saved_state_lr(ss) : 0),
        state_ok ? get_saved_state_esr(ss) : 0, state_ok ? get_saved_state_cpsr(ss) : 0,
        task->task_shared_region_slide,
        uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
        uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}
#else
static void nabu_trace_user_exception(exception_type_t exception __unused,
    mach_exception_data_t code __unused, mach_msg_type_number_t codeCnt __unused) {}
__attribute__((noreturn)) void nabu_trace_exit_panic(int rv, int pid)
{ panic("NABU SB pid=%d rv=%x saved state unavailable", pid, rv); }
#endif

'''
    return replace_once(text, anchor, helper + anchor + call)


def patch_exit_panic_state(text):
    marker = '/* NABU_CAPTURE_V2_6 existing error-exit panic state */'
    if marker in text:
        return text
    anchor = '\t\tpanic("%s: Process %s with pid %d exited on error with code 0x%x.",\n'
    snippet = ('\t\t' + marker + '\n'
               '\t\tif (nabu_exit_trace && !strcmp(p->p_comm, "SpringBoard")) {\n'
               '\t\t\textern void nabu_trace_exit_panic(int, int) __attribute__((noreturn));\n'
               '\t\t\tnabu_trace_exit_panic(rv, proc_getpid(p));\n'
               '\t\t}\n')
    return replace_once(text, anchor, snippet + anchor)


def apply(root, device):
    ui_watch = os.environ.get('NABU_UI_WATCH') == '1'
    if ui_watch and os.environ.get('NABU_GPU_USERPROBE') != '1':
        raise ValueError('UI watch needs the compiled GPU userprobe callback')
    xnu = root / '.cache/xnu-work'
    changed = {}
    for relative, transforms in [
            ('osfmk/console/serial_console.c', [patch_console]),
            ('osfmk/console/serial_general.c', [patch_general]),
            ('pexpert/arm/pe_kprintf.c', [patch_kprintf]),
            # The probe stays at the top of bsd_init (read-only MMIO); the CDC
            # channel starts after bsd_autoconf() so IOKit init has completed
            # and no allocator/personality is assumed before it exists.
            ('bsd/kern/bsd_init.c', [patch_bsd_init, patch_bsd_init_cdc]),
            ('bsd/kern/kern_exec.c', [patch_data_mount]),
            ('bsd/kern/kern_exit.c', [patch_exit_trace, patch_exit_panic_state]),
            ('osfmk/kern/exception.c', [patch_user_exception]),
            ('osfmk/kern/thread.c', [])]:
        path = xnu / relative
        result = path.read_text(encoding='utf-8')
        ui_file = relative in ('bsd/kern/kern_exec.c', 'bsd/kern/kern_exit.c', 'osfmk/kern/thread.c')
        if ui_file and 'NABU_UI_WATCH' in result:
            result = ui_watch_source(result, restore=True, exit_observer=relative.endswith('kern_exit.c'),
                                     thread_observer=relative.endswith('kern/thread.c'))
        for transform in transforms:
            result = transform(result)
        if relative == 'bsd/kern/kern_exec.c' and os.environ.get('NABU_GPU_USERPROBE') == '1':
            result = gpu_userprobe_data_source(result)
        if relative == 'bsd/kern/kern_exit.c' and os.environ.get('NABU_GPU_USERPROBE') == '1':
            result = gpu_userprobe_data_source(result, exit_observer=True)
        if ui_watch and ui_file:
            result = ui_watch_source(result, exit_observer=relative.endswith('kern_exit.c'),
                                     thread_observer=relative.endswith('kern/thread.c'))
        path.write_text(result, encoding='utf-8')
        changed[relative] = hashlib.sha256(result.encode()).hexdigest()
    for name in ('NabuLogCore.h', 'NabuLogFormat.h'):
        shutil.copyfile(device / 'ufs' / name, xnu / 'osfmk/console' / name)
    out = root / 'build/nabu-log'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'source-report.json').write_text(json.dumps({
        'version': 2, 'hooks': changed, 'capture_before_console_disable': True,
        'usb_probe_call': True, 'usb_probe_read_only': True,
        'usb_cdc_call': True, 'usb_cdc_after_iokit_init': True,
        'usb_cdc_entry': 'nabu_usb_cdc_log_start',
        'usb_cdc_static_dma': True, 'usb_cdc_boot_arg_gated': True,
        'heartbeat_call': True, 'heartbeat_entry': 'nabu_heartbeat_start',
        'heartbeat_boot_arg_gated': True, 'heartbeat_read_only': True,
        'writer_counter_watch': True,
        'exit_trace': True,
        'user_exception_trace': ('SpringBoard/Preferences/iconservicesagent/backboardd/WidgetRenderer*/mediaserverd EL0; '
                                 '32 records each; EXC_BAD_ACCESS names the file mappings of the fault address and PC; '
                                 'nabu-exit-trace gated'),
        'user_exception_entry': 'nabu_trace_user_exception',
        'user_exception_delivery_unchanged': True,
        'exit_panic_state': 'existing SpringBoard error-exit panic only; no new panic trigger',
        'data_mount_trace': 'NABU_CAPTURE_V2_3' in (xnu / 'bsd/kern/kern_exec.c').read_text(),
        'gpu_userprobe_boot': os.environ.get('NABU_GPU_USERPROBE') == '1',
        'ui_watch': ui_watch,
        'ui_watch_generator_sha256': (hashlib.sha256(Path(__file__).with_name(
            'nabu_ui_watch_source.py').read_bytes()).hexdigest() if ui_watch else None),
        'data_trace_stages': {'1': 'seed ready', '2': 'mount enter',
                              '3': 'mount returned', '4': 'lookup returned',
                              '5': 'validation/skeleton returned', '6': 'prepare returned'},
        'disk_io_in_capture': False, 'runtime_qualified': False}, indent=2) + '\n')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--device', type=Path)
    p.add_argument('--restore-data-progress', action='store_true')
    a = p.parse_args()
    if a.restore_data_progress:
        path = a.root / '.cache/xnu-work/bsd/kern/kern_exec.c'
        if path.exists():
            before = path.read_text(encoding='utf-8')
            after = ui_watch_source(before, restore=True) if 'NABU_UI_WATCH' in before else before
            after = patch_data_mount(after, restore=True)
            if 'NABU_GPU_USERPROBE_JOB_V1' in after:
                after = gpu_userprobe_data_source(after, restore=True)
            if before != after:
                path.write_text(after, encoding='utf-8')
        thread_path = a.root / '.cache/xnu-work/osfmk/kern/thread.c'
        if thread_path.exists():
            before = thread_path.read_text(encoding='utf-8')
            if 'NABU_UI_WATCH' in before:
                after = ui_watch_source(before, restore=True, thread_observer=True)
                if before != after:
                    thread_path.write_text(after, encoding='utf-8')
        exit_path = a.root / '.cache/xnu-work/bsd/kern/kern_exit.c'
        if exit_path.exists():
            before = exit_path.read_text(encoding='utf-8')
            if 'NABU_UI_WATCH' in before:
                before = ui_watch_source(before, restore=True, exit_observer=True)
            if 'NABU_GPU_USERPROBE_EXIT_V1' in before:
                after = gpu_userprobe_data_source(before, restore=True, exit_observer=True)
                exit_path.write_text(after, encoding='utf-8')
    elif a.device:
        apply(a.root, a.device)
    else:
        p.error('--device is required when applying capture hooks')
