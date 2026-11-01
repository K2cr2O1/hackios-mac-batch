#!/usr/bin/env python3
"""Build only G0 platform archives using the current XNU compilation contract."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess


def compile_command(record, source, output):
    arguments = record['arguments']
    command = []
    index = 0
    while index < len(arguments):
        value = arguments[index]
        if value in ('-o', '-MF', '-MJ'):
            if value == '-o':
                command += ['-o', str(output)]
            index += 2
            continue
        if value not in ('-MD', '-MP'):
            command.append(str(source) if value == record['file'] else value)
        index += 1
    if str(source) not in command or str(output) not in command:
        raise ValueError('XNU recipe lacks the expected source/output arguments')
    return command


def check_object(data):
    if struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 1):
        raise ValueError('Expected ordinary ARM64 relocatable Mach-O')
    at, deployment = 32, None
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, at)
        if size < 8 or at + size > len(data):
            raise ValueError('Invalid Mach-O load command')
        if cmd == 0x32:
            deployment = struct.unpack_from('<II', data, at + 8)
        at += size
    if deployment != (2, 0x110000):
        raise ValueError(f'Expected iOS 17 deployment, got {deployment}')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('component', choices=['ArmDTPlatform', 'ArmCpu'])
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    recipe = root / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
    recipe_bytes = recipe.read_bytes()
    record = json.loads(recipe_bytes.decode('utf-8').strip().rstrip(','))
    source = root / 'drivers' / args.component / (args.component + '.cpp')
    out = root / 'build' / {'ArmDTPlatform': 'armdt-platform', 'ArmCpu': 'armcpu'}[args.component]
    out.mkdir(parents=True, exist_ok=True)
    original_armio = args.component == 'ArmDTPlatform' and os.environ.get('XNU_OWNER_ROOT_TRUST') == '1'
    timer_binding = None
    if args.component == 'ArmCpu':
        from nabu_armcpu_source import patch_source
        patched = out / 'ArmCpu.cpp'
        patched.write_text(patch_source(source.read_text(encoding='utf-8')), encoding='utf-8')
        source = patched
        timer_binding = {'property': '/arm-io/intc/virtual-timer-intid',
                         'encoding': 'u32 little endian', 'allowed_range': [16, 31],
                         'missing_property_default': 27,
                         'enable_and_dispatch_share_value': True,
                         'transform_sha256': hashlib.sha256(
                             Path(__file__).with_name('nabu_armcpu_source.py').read_bytes()).hexdigest()}
    if original_armio:
        from armdt_original_provider import patch_source
        patched = out / 'ArmDTPlatform.cpp'
        patched.write_text(patch_source(source.read_text(encoding='utf-8')), encoding='utf-8')
        source = patched
    obj = out / (args.component + '.o')
    command = compile_command(record, source, obj)
    command += ['-I', str(root / '.cache/xnu-work/osfmk')]
    (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n', encoding='utf-8')
    result = subprocess.run(command, cwd=record['directory'], capture_output=True)
    (out / 'compile.log').write_bytes(result.stdout + result.stderr)
    if recipe.read_bytes() != recipe_bytes:
        raise SystemExit('Platform build modified the original XNU compile record')
    if result.returncode:
        raise SystemExit(result.stderr.decode('utf-8', errors='replace')[-4000:])
    check_object(obj.read_bytes())
    ipi_instructions = None
    if args.component == 'ArmCpu':
        from nabu_armcpu_source import check_ipi_object
        ipi_instructions = check_ipi_object(obj)
    objects = [obj]
    stubs = out / 'PmgrPublishStubs.cpp'
    stubs.write_text(
        'class IOService;\nclass IORegistryEntry;\n'
        'extern "C" {\n'
        '__attribute__((weak)) bool qemu_boot_pmgr_publish (IOService *, IORegistryEntry *) { return false; }\n'
        '__attribute__((weak)) bool nabu_boot_pmgr_publish (IOService *, IORegistryEntry *) { return false; }\n'
        '__attribute__((weak)) bool nabu_watchdog_publish (IOService *) { return false; }\n'
        '__attribute__((weak)) bool nabu_touch_publish (IOService *) { return false; }\n'
        '}\n', encoding='utf-8')
    stubs_obj = out / 'PmgrPublishStubs.o'
    stubs_command = compile_command(record, stubs, stubs_obj)
    stubs_command += ['-I', str(root / '.cache/xnu-work/osfmk')]
    result = subprocess.run(stubs_command, cwd=record['directory'], capture_output=True)
    (out / 'stubs-compile.log').write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise SystemExit(result.stderr.decode('utf-8', errors='replace')[-4000:])
    check_object(stubs_obj.read_bytes())
    objects.append(stubs_obj)
    usb_probe = None
    usb_cdc = None
    heartbeat = None
    if args.component == 'ArmDTPlatform' and os.environ.get('NABU_CAPTURE_LOG') == '1':
        # The read-only USB probe shares the console-log build gate. It is not
        # compiled into minimal/boot profiles and has no effect without the
        # nabu-usb-probe=1 boot argument.
        device = Path(os.environ.get('UNIXNU_DEVICE', root)).resolve()
        probe_source = device / 'platform' / 'NabuUsbProbe.cpp'
        if not probe_source.is_file():
            probe_source = root / 'platform' / 'NabuUsbProbe.cpp'
        if not probe_source.is_file():
            raise SystemExit('USB probe source is missing')
        probe_obj = out / 'NabuUsbProbe.o'
        probe_command = compile_command(record, probe_source, probe_obj)
        probe_command += ['-I', str(root / '.cache/xnu-work/osfmk'), '-DNABU_USB_PROBE=1']
        result = subprocess.run(probe_command, cwd=record['directory'], capture_output=True)
        (out / 'usb-probe-compile.log').write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise SystemExit(result.stderr.decode('utf-8', errors='replace')[-4000:])
        check_object(probe_obj.read_bytes())
        objects.append(probe_obj)
        usb_probe = {
            'source': str(probe_source),
            'source_sha256': hashlib.sha256(probe_source.read_bytes()).hexdigest(),
            'object_sha256': hashlib.sha256(probe_obj.read_bytes()).hexdigest(),
            'boot_arg': 'nabu-usb-probe=1',
            'read_only': True,
            'runtime_qualified': False,
        }
        # The CDC entry only starts a worker after IOKitBSDInit. DMA pages remain
        # static for the lifetime of the kernel, including failed halt paths.
        cdc_source = device / 'usb' / 'NabuUsbCaptureCdc.cpp'
        if not cdc_source.is_file():
            cdc_source = root / 'usb' / 'NabuUsbCaptureCdc.cpp'
        if not cdc_source.is_file():
            raise SystemExit('USB capture CDC source is missing')
        cdc_obj = out / 'NabuUsbCaptureCdc.o'
        cdc_command = compile_command(record, cdc_source, cdc_obj)
        cdc_command += ['-I', str(root / '.cache/xnu-work/osfmk')]
        result = subprocess.run(cdc_command, cwd=record['directory'], capture_output=True)
        (out / 'usb-cdc-compile.log').write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise SystemExit(result.stderr.decode('utf-8', errors='replace')[-4000:])
        check_object(cdc_obj.read_bytes())
        objects.append(cdc_obj)
        usb_cdc = {
            'source': str(cdc_source),
            'source_sha256': hashlib.sha256(cdc_source.read_bytes()).hexdigest(),
            'object_sha256': hashlib.sha256(cdc_obj.read_bytes()).hexdigest(),
            'build_gate': 'NABU_CAPTURE_LOG=1',
            'boot_args': ['nabu-usb-cdc-log=1', 'nabu-usb-cdc-log-init=1',
                          'nabu-usb-cdc-log-smmu=1', 'nabu-usb-cdc-log-rounds=N'],
            'call_site': 'bsd_init after bsd_autoconf (IOKitBSDInit)',
            'dma': 'static BSS pages; ml_vtophys + cache-inhibited ml_io_map; one cache clean before handoff',
            'worker_thread': True,
            'headers_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in sorted(cdc_source.parent.glob('*.h'))},
            'capture_ring': 'NabuLogCore snapshot/copy, 4 MiB capacity',
            'ioservice_personality': False,
            'read_only_probe_separate': True,
            'runtime_qualified': False,
        }
        # Read-only liveness/VM counters; RAM statistics require its real archive.
        heartbeat_source = device / 'platform' / 'NabuHeartbeat.cpp'
        if not heartbeat_source.is_file():
            heartbeat_source = root / 'platform' / 'NabuHeartbeat.cpp'
        if not heartbeat_source.is_file():
            raise SystemExit('heartbeat source is missing')
        heartbeat_obj = out / 'NabuHeartbeat.o'
        heartbeat_command = compile_command(record, heartbeat_source, heartbeat_obj)
        heartbeat_command += ['-I', str(root / '.cache/xnu-work/osfmk')]
        ram_option = os.environ.get('XNU_NATIVE_RAM_BLOCK', '0')
        if ram_option not in ('0', '1'):
            raise SystemExit('XNU_NATIVE_RAM_BLOCK must be 0 or 1 for heartbeat accounting')
        heartbeat_command += ['-DNABU_HEARTBEAT_RAM_ACCOUNTING=' + ram_option]
        result = subprocess.run(heartbeat_command, cwd=record['directory'], capture_output=True)
        (out / 'heartbeat-compile.log').write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise SystemExit(result.stderr.decode('utf-8', errors='replace')[-4000:])
        check_object(heartbeat_obj.read_bytes())
        objects.append(heartbeat_obj)
        heartbeat = {
            'source': str(heartbeat_source),
            'source_sha256': hashlib.sha256(heartbeat_source.read_bytes()).hexdigest(),
            'object_sha256': hashlib.sha256(heartbeat_obj.read_bytes()).hexdigest(),
            'build_gate': 'NABU_CAPTURE_LOG=1',
            'boot_arg': 'nabu-heartbeat=1',
            'interval_arg': 'nabu-heartbeat-interval=N (5..300 s, default 15)',
            'call_site': 'bsd_init beside the USB probe (nabu_capture_source.py)',
            'read_only': True,
            'mmio': False,
            'memory_accounting': {
                'vm_queues_and_wired': True,
                'ram_disk_counters': ram_option == '1',
                'sample_sources': ['heartbeat', 'writer'],
                'independent_counter_reads': True,
                'overlapping_vm_counts_not_a_sum': True,
            },
            'runtime_qualified': False,
        }
    boot_pmgr = None
    watchdog = None
    touch = None
    if original_armio:
        from qemu_pmgr_build import build
        if os.environ.get('NABU_BOOT_PMGR') == '1':
            boot_pmgr = 'NabuBootPMGR'
            objects += build(root, record, out / 'nabu-pmgr', compile_command,
                             Path(os.environ['UNIXNU_KERNELCACHE']),
                             source_name='NabuBootPMGR.cpp', prefix='NabuBootPMGR',
                             aon_storage='volatile nabu boot-session AON latch (not power hardware)')
            # Hardware boards publish the original IOWatchdog for watchdogd;
            # runtime publication additionally requires Apple's wdt=-1.
            from nabu_watchdog_build import build as build_watchdog
            objects += build_watchdog(root, record, out / 'nabu-watchdog', compile_command,
                                      Path(os.environ['UNIXNU_KERNELCACHE']))
            watchdog = {'class': 'NabuWatchdog', 'parent': 'IOWatchdog',
                        'boot_arg': 'wdt=-1', 'soc_hooks_mmio': False,
                        'bindings': str(out / 'nabu-watchdog' / 'bindings.json')}
            if os.environ.get('NABU_TOUCH') == '1':
                # Only profiles that prelink IOHIDFamily build the touch digitizer.
                from nabu_touch_build import build as build_touch
                objects += build_touch(root, record, out / 'nabu-touch', compile_command,
                                       Path(os.environ['UNIXNU_KERNELCACHE']))
                touch = {'class': 'NabuTouchHid', 'parent': 'IOHIDDevice',
                         'boot_arg': 'nabu-touch=1', 'firmware': 'ADT /nabu-touch',
                         'bindings': str(out / 'nabu-touch' / 'bindings.json')}
        else:
            boot_pmgr = 'QemuBootPMGR'
            objects += build(root, record, out / 'qemu-pmgr', compile_command,
                             Path(os.environ['UNIXNU_KERNELCACHE']))
    archive = out / ('lib' + args.component + '.a')
    if archive.exists():
        raise SystemExit('Refuse to reuse an existing platform archive; use a fresh build')
    subprocess.run(['xcrun', 'ar', 'rcs', str(archive), *map(str, objects)], check=True)
    (out / 'build-report.json').write_text(json.dumps({
        'component': args.component, 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'recipe_sha256': hashlib.sha256(recipe_bytes).hexdigest(),
        'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
        'original_armio_factory_enabled': original_armio,
        'boot_pmgr': boot_pmgr,
        'watchdog': watchdog,
        'touch': touch,
        'timer_binding': timer_binding, 'ipi_instructions': ipi_instructions,
        'usb_probe': usb_probe,
        'usb_cdc': usb_cdc,
        'heartbeat': heartbeat,
        'architecture': 'arm64', 'deployment': 'iOS 17.0', 'runtime_qualified': False,
    }, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
