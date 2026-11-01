#!/usr/bin/env python3
"""Package source-build evidence privately; publish only bounded identity metadata."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import sys

from prepare_source import INPUT_SHA256, UPSTREAM
from nabu_logging_build import qualify_logging_candidate
from nabu_data_skeleton import qualify_data_skeleton
from nabu_display_ci import DISPLAY_PROFILES, qualify_display_candidate
from nabu_gpu_ci import (PROFILE as GPU_PROFILE, CONTRACT as GPU_CONTRACT,
                         GPU_PROFILES, accelerator_mode, gpu_contract,
                         PMAP_SOURCE as GPU_PMAP_SOURCE, public_source, qualify_gpu_candidate)
from nabu_cs_stream import qualify_signature_scan


def sha256(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1 << 20), b''):
            value.update(data)
    return value.hexdigest()


def macho_summary(path):
    data = path.read_bytes()
    if len(data) < 32 or struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 2):
        raise ValueError('Candidate must be ordinary ARM64 MH_EXECUTE')
    count, extent = struct.unpack_from('<II', data, 16)
    at, undefined, symbols = 32, [], None
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', data, at)
        if size < 8 or at + size > 32 + extent or at + size > len(data):
            raise ValueError('Malformed Mach-O command')
        if cmd == 2:
            symbols = struct.unpack_from('<4I', data, at + 8)
        at += size
    if symbols is None or at != 32 + extent:
        raise ValueError('Candidate must retain the symbol table')
    offset, number, strings, string_bytes = symbols
    if offset + number * 16 > len(data) or strings + string_bytes > len(data):
        raise ValueError('Malformed symbol/string table')
    for index in range(number):
        name, kind, _, _, _ = struct.unpack_from('<IBBHQ', data, offset + index * 16)
        if kind & 0xe0 or kind & 0xe:
            continue
        if name >= string_bytes:
            raise ValueError('Malformed symbol name')
        end = data.index(b'\0', strings + name, strings + string_bytes)
        undefined.append(data[strings + name:end].decode('utf-8'))
    return {'symbol_count': number, 'undefined_names': undefined}


def selected_files(upstream):
    work = upstream / 'out/nabu'
    if work.is_symlink():
        raise ValueError('Refuse a linked build output root')
    files = []
    selected_xnu_names = {'link.filelist', 'all-alias.exp', 'startup.o.json',
                          'prng_random.o.json', 'IOPlatformExpert.cpo.json', 'KernelConfigTables.cpo.json',
                          'serial_console.o', 'serial_console.o.json', 'serial_general.o', 'serial_general.o.json',
                          'pe_kprintf.o', 'pe_kprintf.o.json', 'bsd_init.o', 'bsd_init.o.json',
                          'kern_exec.o', 'kern_exec.o.json', 'kern_exit.o', 'kern_exit.o.json',
                          'thread.o', 'thread.o.json',
                          'ubc_subr.o', 'ubc_subr.o.json',
                          'exception.o', 'exception.o.json'}
    report_names = {'report.json', 'bindings.json', 'candidate-bindings.json', 'nabu-ufs-source.json', 'readonly-source.json',
                    'compile-command.json', 'compile-command-namespaced.json',
                    'build-report.json', 'build-report-namespaced.json',
                    'link-survey.json', 'link-survey-namespaced.json'}

    def add(path, relative):
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents
                                    if parent != work and work in parent.parents):
            raise ValueError(f'Refuse a linked output: {relative}')
        if path.is_file():
            if any(part in ('.git', '.env') for part in relative.parts):
                raise ValueError(f'Refuse unexpected output: {relative}')
            files.append((path, 'outputs/' + relative.as_posix()))

    for relative in ('kernel', 'logs'):
        directory = work / relative
        if directory.is_dir():
            for path in sorted(directory.rglob('*')):
                add(path, path.relative_to(work))

    build = work / 'tree/build'
    probe = work / 'userprobe'
    if probe.is_dir():
        for path in sorted(probe.iterdir()):
            if path.name in ('nabu-gpu-userprobe', 'build-report.json', 'entitlements.plist') or (
                    path.name.startswith('command-') and path.suffix == '.log'):
                add(path, path.relative_to(work))
    xnu_obj = build / 'xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    if xnu_obj.is_dir():
        for path in sorted(xnu_obj.rglob('*')):
            if path.is_file() and path.name in selected_xnu_names:
                add(path, path.relative_to(work))
    for relative in ('corecrypto-2023', 'armdt-platform', 'armcpu', 'libpthread-kernel',
                     'native-virtio-block', 'verified-root-xnu', 'native-ufs', 'native-ram-block'):
        directory = build / relative
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob('*')):
            if path.is_dir():
                continue
            if path.suffix == '.a' or path.name in report_names or path.name in (
                    'namespace.h', 'inputs.S', 'NativeVirtioBlock.cpp', 'ArmDTPlatform.cpp',
                    'OriginalPMGRABI.h', 'original-bindings.S'):
                add(path, path.relative_to(work))
            elif relative == 'armcpu' and path.name in ('ArmCpu.cpp', 'ArmCpu.o', 'compile.log'):
                add(path, path.relative_to(work))
            elif relative == 'armdt-platform' and path.name in (
                    'NabuUsbProbe.cpp', 'NabuUsbProbe.o', 'NabuUsbProbe.o.json',
                    'NabuUsbCaptureCdc.o', 'usb-cdc-compile.log', 'usb-probe-compile.log'):
                add(path, path.relative_to(work))
            elif relative == 'armdt-platform' and path.name in ('NabuHeartbeat.o', 'heartbeat-compile.log'):
                add(path, path.relative_to(work))
            elif relative == 'native-ufs' and (path.suffix in ('.cpp', '.h') or
                                               path.name in ('NativeUfs.o', 'compile.log')):
                add(path, path.relative_to(work))
            elif relative == 'native-ram-block' and path.name in (
                    'NativeRamBlock.o', 'NativeRamBlock.cpp', 'compile.log', 'NabuGpuUserprobeAddon.h'):
                add(path, path.relative_to(work))

    display = build / 'native-legacy-display'
    if display.is_dir():
        for path in sorted(display.rglob('*')):
            if path.is_file():
                add(path, path.relative_to(work))

    gpu = build / 'native-adreno'
    if gpu.is_dir():
        for path in sorted(gpu.rglob('*')):
            if path.is_file() and path.suffix in ('.json', '.o', '.a', '.c', '.cpp', '.h', '.log', '.S'):
                add(path, path.relative_to(work))
        add(work / GPU_PMAP_SOURCE.removeprefix('outputs/'),
            Path(GPU_PMAP_SOURCE.removeprefix('outputs/')))

    # Small generated public storage headers and their pinned-source receipt,
    # not the SDK tree. This binds the class declarations used by UFS/VirtIO.
    storage = build / 'storage-abi'
    add(storage / 'headers.json', Path('tree/build/storage-abi/headers.json'))
    if (storage / 'include').is_dir():
        for path in sorted((storage / 'include').rglob('*.h')):
            add(path, path.relative_to(work))
    add(work / '.config', Path('.config'))
    for relative in ('tree/build/nabu-log/source-report.json',
                     'tree/.cache/xnu-work/osfmk/console/serial_console.c',
                     'tree/.cache/xnu-work/osfmk/console/serial_general.c',
                     'tree/.cache/xnu-work/osfmk/console/NabuLogCore.h',
                     'tree/.cache/xnu-work/osfmk/console/NabuLogFormat.h',
                     'tree/.cache/xnu-work/pexpert/arm/pe_kprintf.c',
                     'tree/.cache/xnu-work/bsd/kern/bsd_init.c',
                     'tree/.cache/xnu-work/bsd/kern/kern_exec.c',
                     'tree/.cache/xnu-work/bsd/kern/ubc_subr.c',
                     'tree/.cache/xnu-work/bsd/kern/kern_exit.c',
                     'tree/.cache/xnu-work/osfmk/kern/exception.c',
                     'tree/.cache/xnu-work/osfmk/kern/thread.c'):
        add(work / relative, Path(relative))
    # The assembled tree exposes patches through a symlink. Collect the
    # authenticated upstream file itself, never the link target discovered by
    # walking the build tree.
    add(upstream / 'patches/xnu/native-4k-signature-hash-cache.patch',
        Path('tree/patches/xnu/native-4k-signature-hash-cache.patch'))
    return files


def selected_sources(device):
    root = Path(__file__).resolve().parents[1]
    source_dir = root / ('source-ci' if (root / 'source-ci').is_dir() else 'scripts')
    workflow_dir = root / ('.github/workflows' if (root / '.github/workflows').is_dir()
                           else 'workflows')
    sources = [
        (device / 'board.toml', 'device/board.toml'),
        (device / 'configs/nabu_bootstrap_defconfig', 'device/configs/nabu_bootstrap_defconfig'),
        (device / 'configs/nabu_qemu_storage_defconfig', 'device/configs/nabu_qemu_storage_defconfig'),
        (device / 'configs/nabu_qemu_root_defconfig', 'device/configs/nabu_qemu_root_defconfig'),
        (device / 'configs/nabu_qemu_data_defconfig', 'device/configs/nabu_qemu_data_defconfig'),
        (device / 'configs/nabu_qemu_cpu_ui_defconfig', 'device/configs/nabu_qemu_cpu_ui_defconfig'),
        (device / 'configs/nabu_qemu_legacy_defconfig', 'device/configs/nabu_qemu_legacy_defconfig'),
        (device / 'configs/nabu_ufs_passive_defconfig', 'device/configs/nabu_ufs_passive_defconfig'),
        (device / 'configs/nabu_ufs_readonly_defconfig', 'device/configs/nabu_ufs_readonly_defconfig'),
        (device / 'configs/nabu_ufs_root_defconfig', 'device/configs/nabu_ufs_root_defconfig'),
        (device / 'configs/nabu_ufs_data_defconfig', 'device/configs/nabu_ufs_data_defconfig'),
        (device / 'configs/nabu_ufs_cpu_ui_defconfig', 'device/configs/nabu_ufs_cpu_ui_defconfig'),
        (device / 'configs/nabu_ufs_cpu_present_defconfig', 'device/configs/nabu_ufs_cpu_present_defconfig'),
        (device / 'configs/nabu_ufs_gpu_defconfig', 'device/configs/nabu_ufs_gpu_defconfig'),
        (device / 'configs/nabu_ufs_gpu_metal_defconfig', 'device/configs/nabu_ufs_gpu_metal_defconfig'),
        (device / 'scripts/build-nabu-adreno.py', 'device/scripts/build-nabu-adreno.py'),
        (device / 'scripts/nabu_adreno_bindings.py', 'device/scripts/nabu_adreno_bindings.py'),
        (device / 'scripts/build-nabu-gpu-userprobe.py', 'device/scripts/build-nabu-gpu-userprobe.py'),
        (device / 'scripts/nabu_gpu_userprobe_source.py', 'device/scripts/nabu_gpu_userprobe_source.py'),
        (device / 'scripts/nabu_ui_watch_source.py', 'device/scripts/nabu_ui_watch_source.py'),
        (device / 'platform/NabuGpuUserprobeAddon.h', 'device/platform/NabuGpuUserprobeAddon.h'),
        (device / 'userprobe/nabu_gpu_userprobe.cpp', 'device/userprobe/nabu_gpu_userprobe.cpp'),
        (device / 'LICENSE', 'device/LICENSE'),
        (device / 'scripts/build-nabu-platform.py', 'device/scripts/build-nabu-platform.py'),
        (device / 'scripts/nabu_armcpu_source.py', 'device/scripts/nabu_armcpu_source.py'),
        (device / 'scripts/armdt_original_provider.py', 'device/scripts/armdt_original_provider.py'),
        (device / 'scripts/qemu_pmgr_build.py', 'device/scripts/qemu_pmgr_build.py'),
        (device / 'platform/QemuBootPMGR.cpp', 'device/platform/QemuBootPMGR.cpp'),
        (device / 'scripts/nabu_watchdog_build.py', 'device/scripts/nabu_watchdog_build.py'),
        (device / 'platform/NabuWatchdog.cpp', 'device/platform/NabuWatchdog.cpp'),
        (device / 'scripts/build-nabu-virtio.py', 'device/scripts/build-nabu-virtio.py'),
        (device / 'scripts/build-nabu-ram-block.py', 'device/scripts/build-nabu-ram-block.py'),
        (device / 'scripts/nabu_ram_source.py', 'device/scripts/nabu_ram_source.py'),
        (device / 'scripts/nabu_storage_bindings.py', 'device/scripts/nabu_storage_bindings.py'),
        (device / 'scripts/build-nabu-owner-root.py', 'device/scripts/build-nabu-owner-root.py'),
        (device / 'scripts/build-nabu-ufs.py', 'device/scripts/build-nabu-ufs.py'),
        (device / 'scripts/build-nabu-ufs-readonly.py', 'device/scripts/build-nabu-ufs-readonly.py'),
        (device / 'scripts/nabu_ufs_readonly.py', 'device/scripts/nabu_ufs_readonly.py'),
        (device / 'scripts/prepare_nabu_ufs_source.py', 'device/scripts/prepare_nabu_ufs_source.py'),
        (device / 'scripts/native_ufs_bindings.py', 'device/scripts/native_ufs_bindings.py'),
        (device / 'patches/nabu-nativeufs-board.patch', 'device/patches/nabu-nativeufs-board.patch'),
        (device / 'patches/nabu-ufs-inspect-console.patch', 'device/patches/nabu-ufs-inspect-console.patch'),
        (device / 'patches/nabu-ufs-readonly-commands.patch', 'device/patches/nabu-ufs-readonly-commands.patch'),
        (device / 'patches/nabu-ufs-smmu-revalidate.patch', 'device/patches/nabu-ufs-smmu-revalidate.patch'),
        (device / 'ufs/NabuUfsHostSafety.h', 'device/ufs/NabuUfsHostSafety.h'),
        (device / 'ufs/NabuUfsQueue.h', 'device/ufs/NabuUfsQueue.h'),
        (device / 'ufs/NabuUfsResources.h', 'device/ufs/NabuUfsResources.h'),
        (device / 'ufs/NabuUfsService.h', 'device/ufs/NabuUfsService.h'),
        (source_dir / 'prepare_source.py', 'source-ci/prepare_source.py'),
        (source_dir / 'collect_outputs.py', 'source-ci/collect_outputs.py'),
        (source_dir / 'nabu_data_skeleton.py', 'source-ci/nabu_data_skeleton.py'),
        (source_dir / 'nabu_cs_stream.py', 'source-ci/nabu_cs_stream.py'),
        (source_dir / 'nabu_display_ci.py', 'source-ci/nabu_display_ci.py'),
        (source_dir / 'nabu_gpu_ci.py', 'source-ci/nabu_gpu_ci.py'),
        (source_dir / 'nabu_ui_watch_qualification.py', 'source-ci/nabu_ui_watch_qualification.py'),
        (source_dir / 'nabu_graphics_startup.py', 'source-ci/nabu_graphics_startup.py'),
        (device / 'scripts/build-nabu-legacy-display.py', 'device/scripts/build-nabu-legacy-display.py'),
        (device / 'scripts/nabu_display_bindings.py', 'device/scripts/nabu_display_bindings.py'),
        (device / 'platform/NabuLegacyDiscovery.cpp', 'device/platform/NabuLegacyDiscovery.cpp'),
        (device / 'platform/NabuKeybagNotifications.cpp', 'device/platform/NabuKeybagNotifications.cpp'),
        (device / 'platform/NabuLegacyCpuPixels.h', 'device/platform/NabuLegacyCpuPixels.h'),
        (device / 'platform/NabuGpuScanoutHandoff.h', 'device/platform/NabuGpuScanoutHandoff.h'),
        (device / 'platform/NabuGpuScanoutWire.h', 'device/platform/NabuGpuScanoutWire.h'),
        (device / 'platform/NabuLegacyCpuPresent.cpp', 'device/platform/NabuLegacyCpuPresent.cpp'),
        (device / 'scripts/nabu_cpu_abi.py', 'device/scripts/nabu_cpu_abi.py'),
        (device / 'configs/nabu_qemu_cpu_present_defconfig', 'device/configs/nabu_qemu_cpu_present_defconfig'),
        (device / 'platform/NabuLegacyDisplayProbe.cpp', 'device/platform/NabuLegacyDisplayProbe.cpp'),
        (device / 'platform/NabuLegacyStubs.cpp', 'device/platform/NabuLegacyStubs.cpp'),
        (device / 'platform/NabuGraphicsStatus.cpp', 'device/platform/NabuGraphicsStatus.cpp'),
        (workflow_dir / 'unixnu-source.yml', '.github/workflows/unixnu-source.yml'),
    ]
    root = root.resolve()
    sources += [(p, 'device/ufs/' + p.name) for p in sorted((device / 'ufs').glob('NabuLog*.h'))]
    sources += [(device / 'scripts/nabu_capture_source.py', 'device/scripts/nabu_capture_source.py'),
                (device / 'platform/NabuUsbProbe.cpp', 'device/platform/NabuUsbProbe.cpp'),
                (device / 'platform/NabuHeartbeat.cpp', 'device/platform/NabuHeartbeat.cpp'),
                (source_dir / 'nabu_logging_build.py', 'source-ci/nabu_logging_build.py')]
    sources += [(p, 'device/usb/' + p.name) for p in sorted((device / 'usb').glob('*'))
                if p.is_file() and (p.suffix in ('.cpp', '.h') or p.name == 'LICENSE')]
    sources += [(p, 'device/' + p.relative_to(device).as_posix())
                for p in sorted((device / 'gpu').rglob('*'))
                if p.is_file() and public_source(p.relative_to(device).as_posix())]
    for path, _ in sources:
        if (path.is_symlink() or not path.is_file()
                or not path.resolve().is_relative_to(root)
                or any(parent.is_symlink() for parent in path.parents if parent != root)):
            raise ValueError(f'Refuse missing or linked source input: {path}')
    return sources


def derive_accelerator_bindings(upstream, device, candidate):
    """Derive the original-base bindings from the finished candidate.

    The GPU archive must exist before the kernel links, so it carries predicted
    addresses. Re-deriving them from the candidate that was actually produced is
    what lets the GPU qualifier refuse a candidate whose linked values disagree.
    """
    out = upstream / 'out/nabu/tree/build/native-adreno'
    built = json.loads((out / 'build-report.json').read_text(encoding='utf-8'))
    kernelcache = built.get('kernelcache')
    if not (isinstance(kernelcache, str) and kernelcache):
        raise ValueError('GPU build report does not name the kernelcache it was built against')
    result = subprocess.run([
        sys.executable, '-B', str(device / 'scripts/nabu_adreno_bindings.py'),
        '--kernelcache', kernelcache, '--candidate', str(candidate),
        '--report', str(candidate.with_suffix('.json')),
        '--native-prelink', str(upstream / 'out/nabu/tree/kits/NativePrelink'),
        '--output-dir', str(out),
    ], capture_output=True, text=True, check=False)
    (out / 'bindings-derivation.log').write_text(result.stdout + result.stderr, encoding='utf-8')
    if result.returncode:
        raise ValueError('Accelerator bindings were not derived from this candidate: ' +
                         result.stderr.strip()[-2000:])
    report = json.loads((out / 'adreno-bindings.json').read_text(encoding='utf-8'))
    return {**report, 'symbols': report.get('bindings')}


def check_ufs_candidate(upstream, device, candidate, report, read_only=False):
    """Qualify this object's inherited dispatch against this prelinked candidate."""
    out = upstream / 'out/nabu/tree/build/native-ufs'
    built = json.loads((out / 'build-report.json').read_text(encoding='utf-8'))
    if (built.get('source_commit') != 'af785c1777161a62931425c2faaa536ce0bebd5b'
            or built.get('passive_only') is not (not read_only)
            or (read_only and built.get('read_only') is not True)
            or built.get('verified_root_enabled') is not False
            or built.get('source_flags') != [('-DNABU_UFS_READONLY=1' if read_only else '-DNABU_UFS_PASSIVE_ONLY=1'),
                                             '-DNATIVE_VERIFIED_BLOCK=0']
            or built.get('object_sha256') != sha256(out / 'NativeUfs.o')
            or built.get('archive_sha256') != sha256(out / 'libNativeUfs.a')):
        raise ValueError('UFS object/archive is not bound to this selected build')
    builder = 'build-nabu-ufs-readonly.py' if read_only else 'build-nabu-ufs.py'
    result = subprocess.run([
        sys.executable, str(device / 'scripts' / builder),
        '--object', str(out / 'NativeUfs.o'), '--check-candidate', str(candidate),
        '--prelink-report', str(report), '--output-dir', str(out),
    ], capture_output=True, text=True)
    if result.returncode:
        raise ValueError('UFS candidate ABI check failed: ' + result.stderr[-2000:])
    return True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--upstream', type=Path, required=True)
    p.add_argument('--device', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--run-id', type=int, required=True)
    p.add_argument('--attempt', type=int, required=True)
    p.add_argument('--head-sha', required=True)
    p.add_argument('--build-outcome', required=True)
    p.add_argument('--input-sha256', default='')
    p.add_argument('--prepare-report', type=Path, required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    files = []
    prepared = json.loads(args.prepare_report.read_text()) if args.prepare_report.is_file() else {}
    identity = {'run_id': args.run_id, 'run_attempt': args.attempt, 'head_sha': args.head_sha,
                'upstream_commit': UPSTREAM, 'profile': prepared.get('profile', 'nabu_bootstrap_defconfig'),
                'inputs_release': 'unixnu-source-inputs', 'inputs_asset': 'ipsw-21h16-small.zip',
                'inputs_sha256': args.input_sha256 or None,
                'input_verified': args.input_sha256 == INPUT_SHA256,
                'build_step_outcome': args.build_outcome, 'runtime_qualified': False,
                'owner_policy': prepared.get('owner_policy'),
                'systemos_policy': prepared.get('systemos_policy'),
                'second_static_trust_cache': prepared.get('second_static_trust_cache', False),
                'owner_cache_carrier': prepared.get('owner_cache_carrier'),
                'owner_boot_manifest': prepared.get('owner_boot_manifest'),
                'ufs_passive_only': prepared.get('ufs_passive_only', False),
                'ufs_read_only': prepared.get('ufs_read_only', False),
                'qemu_data': prepared.get('qemu_data', False),
                'qemu_cpu_ui_reference': prepared.get('qemu_cpu_ui_reference', False),
                'qemu_legacy_discovery': prepared.get('qemu_legacy_discovery', False),
                'qemu_cpu_present': prepared.get('qemu_cpu_present', False),
                'ufs_cpu_present': prepared.get('ufs_cpu_present', False),
                'ufs_gpu': prepared.get('ufs_gpu', False),
                'ufs_gpu_metal': prepared.get('ufs_gpu_metal', False),
                'gpu_userprobe_boot': prepared.get('gpu_userprobe_boot', False),
                'ui_watch': prepared.get('ui_watch', False),
                'gpu': ({**gpu_contract(prepared.get('profile'))} if prepared.get('ufs_gpu') is True else None),
                'display_reference': prepared.get('display_reference'),
                'log_capture': prepared.get('log_capture'),
                'signature_scan_io': prepared.get('signature_scan_io'),
                'hardware_tested': False, 'apple_launchd_executed': False}
    summary = dict(identity, candidate_present=False, candidate_validated=False,
                   ufs_abi_validated=False)
    manifest = dict(identity)
    files.extend(selected_sources(args.device))
    if args.prepare_report.is_file():
        files.append((args.prepare_report, 'prepare-report.json'))
    if (args.upstream / '.git').exists():
        actual_head = subprocess.check_output(['git', '-C', str(args.upstream), 'rev-parse', 'HEAD'], text=True).strip()
        manifest['actual_upstream_commit'] = actual_head
        manifest['submodules'] = subprocess.check_output(['git', '-C', str(args.upstream), 'submodule', 'status', '--recursive'], text=True)
        manifest['upstream_diff'] = subprocess.check_output(['git', '-C', str(args.upstream), 'diff', '--no-ext-diff'], text=True)
    candidate = args.upstream / 'out/nabu/kernel/kernel.macho'
    report = candidate.with_suffix('.json')
    if candidate.is_file():
        summary.update(candidate_present=True, candidate_sha256=sha256(candidate), candidate_bytes=candidate.stat().st_size)
        try:
            parsed = json.loads(report.read_text(encoding='utf-8'))
            macho = macho_summary(candidate)
            required_images = {'com.apple.filesystems.apfs', 'com.apple.kec.corecrypto'}
            if identity['profile'] in ('nabu_qemu_cpu_ui_defconfig', *DISPLAY_PROFILES):
                required_images |= {
                    'com.apple.iokit.IOSurface',
                    'com.apple.iokit.IOMobileGraphicsFamily',
                }
            if accelerator_mode(identity['profile']):
                # Only the metal profile declares the original IOGPUFamily in its
                # prelink roots; the diagnostic profile keeps its closure free of it.
                required_images.add('com.apple.iokit.IOGPUFamily')
            valid = (parsed['candidate_sha256'] == summary['candidate_sha256']
                     and parsed['original_sha256'] == 'f7d1952c7a21633d212eccf288e77444fff0cc86976db5de292f6819c2ffa1b2'
                     and parsed['slide'] == -0x1360000
                     and required_images <= set(parsed['components'])
                     and not macho['undefined_names'] and macho['symbol_count'] > 0
                     and manifest.get('actual_upstream_commit') == UPSTREAM
                     and identity['input_verified'] and args.prepare_report.is_file())
            if identity['profile'] == 'nabu_ufs_passive_defconfig':
                summary['ufs_abi_validated'] = check_ufs_candidate(
                    args.upstream, args.device, candidate, report)
                valid = valid and identity['ufs_passive_only'] and summary['ufs_abi_validated']
            elif identity['profile'] == 'nabu_ufs_readonly_defconfig':
                summary['ufs_abi_validated'] = check_ufs_candidate(
                    args.upstream, args.device, candidate, report, read_only=True)
                valid = valid and identity['ufs_read_only'] and summary['ufs_abi_validated']
            if identity.get('log_capture'):
                manifest['logging_qualification'] = qualify_logging_candidate(
                    args.upstream, candidate, identity['log_capture'].get('source_identity'))
                summary['logging_qualified_statically'] = True
            manifest['data_skeleton_qualification'] = qualify_data_skeleton(
                args.upstream, prepared.get('data_skeleton'), capture_logs=bool(identity['log_capture']))
            summary['data_skeleton_qualified_statically'] = bool(
                manifest['data_skeleton_qualification'])
            manifest['signature_scan_qualification'] = qualify_signature_scan(
                args.upstream, prepared.get('signature_scan_io'))
            summary['signature_scan_qualified_statically'] = bool(manifest['signature_scan_qualification'])
            if identity['profile'] in DISPLAY_PROFILES:
                manifest['display_qualification'] = qualify_display_candidate(
                    args.upstream, args.device, candidate, expected_profile=identity['profile'])
                summary['display_qualified_statically'] = True
            if identity['profile'] in GPU_PROFILES:
                if accelerator_mode(identity['profile']):
                    # The archive carries predicted bindings; only the metal candidate
                    # can re-derive them, because only its closure has IOGPUFamily.
                    summary['accelerator_bindings'] = derive_accelerator_bindings(
                        args.upstream, args.device, candidate)['symbols']
                contract = gpu_contract(identity['profile'])
                if (identity['ufs_gpu'] is not True or identity['ufs_cpu_present'] is not False or
                        not identity.get('log_capture') or
                        not isinstance(prepared.get('gpu'), dict) or
                        any(prepared['gpu'].get(key) != value for key, value in contract.items()
                            if key != 'profile') or prepared.get('runtime_qualified') is not False):
                    raise ValueError('GPU candidate requires its explicit profile and persisted logging contract')
                manifest['gpu_qualification'] = qualify_gpu_candidate(
                    args.upstream, args.device, candidate, expected_profile=identity['profile'])
                if prepared.get('gpu_userprobe_boot') is True and not manifest['gpu_qualification'].get('userprobe_boot'):
                    raise ValueError('Requested GPU userprobe boot support was not qualified')
                ui = manifest['gpu_qualification'].get('userprobe_boot', {}).get('ui_watch', {})
                if bool(ui.get('compiled')) != identity['ui_watch']:
                    raise ValueError('Requested UI observer build differs from its actual qualification')
                summary['ui_watch_qualified_statically'] = bool(ui.get('compiled'))
                summary['gpu_qualified_statically'] = True
            elif identity['ufs_gpu'] or prepared.get('gpu'):
                raise ValueError('GPU contract is only valid for the explicit GPU profiles')
            summary['candidate_validated'] = valid
            summary['undefined_symbol_count'] = len(macho['undefined_names'])
            manifest['macho'] = macho
        except (KeyError, ValueError, OSError, struct.error, subprocess.CalledProcessError) as error:
            manifest['candidate_validation_error'] = str(error)
    files.extend(selected_files(args.upstream))
    manifest['files'] = {name: {'bytes': path.stat().st_size, 'sha256': sha256(path)} for path, name in files}
    manifest['summary'] = summary
    manifest_path = args.output / 'source-manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    tag = f'source-{args.run_id}-attempt-{args.attempt}'
    with tarfile.open(args.output / (tag + '.tar.gz'), 'w:gz') as archive:
        for path, name in files:
            archive.add(path, arcname=name, recursive=False)
        archive.add(manifest_path, arcname='source-manifest.json')
    summary['private_release'] = tag
    summary['private_asset'] = tag + '.tar.gz'
    summary['private_asset_sha256'] = sha256(args.output / (tag + '.tar.gz'))
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    if args.build_outcome == 'success' and not summary['candidate_validated']:
        raise SystemExit('Build succeeded without a valid bound candidate; private evidence was preserved')


if __name__ == '__main__':
    main()
