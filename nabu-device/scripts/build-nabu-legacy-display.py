#!/usr/bin/env python3
"""Build the CPU-only Legacy display archive against the generated 21H16 ABI.

The builder runs inside the assembled UniXNU tree.  It copies the vendored
GopFramebuffer source and the nabu probe into the tree, regenerates the ABI
from the 21H16 kernelcache and an explicit pass-1 reference candidate, then
compiles and archives the objects expected by the pinned Legacy link gate.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tomllib


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
        raise SystemExit('XNU recipe lacks the expected source/output arguments')
    return command


def check_object(data):
    if struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 1):
        raise SystemExit('Expected ordinary ARM64 relocatable Mach-O')


def run(command, cwd, log):
    result = subprocess.run([str(x) for x in command], cwd=cwd, capture_output=True)
    log.write_bytes(result.stdout + result.stderr)
    if result.returncode:
        sys.stderr.write(result.stderr.decode('utf-8', errors='replace')[-4000:])
        raise SystemExit('command failed: ' + ' '.join(str(x) for x in command))


def object_vtable(macho, obj, slots=358):
    raw = Path(obj).read_bytes()
    image = macho(raw)
    table = next(p for c, p, _ in image['commands'] if c == 2)
    symoff, count, stroff, _ = struct.unpack_from('<4I', raw, table + 8)
    symbols = []
    for index in range(count):
        strx, kind, _, _, va = struct.unpack_from('<IBBHQ', raw, symoff + index * 16)
        name = raw[stroff + strx:raw.index(b'\0', stroff + strx)].decode()
        symbols.append((name, va, kind))
    vtable = next(va for name, va, _ in symbols if name == '__ZTV19NativeLegacyDisplay')
    relocations = {}
    for segment in image['segments']:
        for section in segment['sections']:
            if section['va'] <= vtable < section['va'] + section['size']:
                ro, rc = struct.unpack_from('<2I', raw, section['command_offset'] + 56)
                for index in range(rc):
                    offset, bits = struct.unpack_from('<2I', raw, ro + index * 8)
                    if bits >> 27 & 1 and bits >> 28 == 0 and bits >> 25 & 3 == 3:
                        relocations[section['va'] + offset] = symbols[bits & 0xffffff][0]
    compiled = [relocations.get(vtable + 16 + slot * 8) for slot in range(slots)]
    if not all(compiled):
        raise SystemExit('Compiled NativeLegacyDisplay vtable is incomplete')
    return symbols, compiled


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_cpu_profile(lines, profile, hardware_pmgr):
    modes = {'nabu_qemu_cpu_present_defconfig': False,
             'nabu_ufs_cpu_present_defconfig': True,
             'nabu_ufs_gpu_defconfig': True,
             'nabu_ufs_gpu_metal_defconfig': True}
    if profile not in modes:
        raise ValueError('CPU notifications require an explicit CPU presentation profile')
    hardware = modes[profile]
    if hardware_pmgr != hardware:
        raise ValueError('CPU presentation profile has the wrong boot PMGR backend')
    config = {}
    for line in lines:
        if not line.startswith('CONFIG_') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        if key in config:
            raise ValueError('Duplicate CPU profile assignment: ' + key)
        config[key] = value
    required = {'NATIVE_LEGACY_DISPLAY': 'y', 'NATIVE_RAM_BLOCK': 'y',
                'OWNER_DATA_MOUNT': 'y', 'OWNER_ROOT_TRUST': 'y',
                'OWNER_UNION_SYSTEMOS': 'y', 'NATIVE_VIRTIO_BLOCK': 'y',
                'NATIVE_UFS': 'y' if hardware else 'n'}
    if any(config.get('CONFIG_XNU_' + name) != value for name, value in required.items()):
        raise ValueError('CPU notifications require the selected owner root and volatile RAM Data dependencies')
    return {'profile': profile, 'data_backend': 'volatile_ram',
            'system_transport': 'ufs' if hardware else 'virtio',
            'boot_pmgr': 'nabu' if hardware else 'qemu'}


def main():
    root = Path(__file__).resolve().parents[1]
    device = Path(os.environ['UNIXNU_DEVICE'])
    profile = tomllib.loads((device / 'board.toml').read_text())['kernel']['defconfig']
    kernelcache = Path(os.environ['UNIXNU_KERNELCACHE'])
    reference = os.environ.get('UNIXNU_DISPLAY_REFERENCE')
    if not reference:
        raise SystemExit('UNIXNU_DISPLAY_REFERENCE must point at the pass-1 candidate')
    reference = Path(reference)
    if not reference.is_file():
        raise SystemExit(f'pass-1 reference candidate not found: {reference}')

    out = root / 'build/native-legacy-display'
    source = out / 'source'
    abi = out / 'abi'
    source.mkdir(parents=True, exist_ok=True)
    abi.mkdir(parents=True, exist_ok=True)
    discovery = os.environ.get('NABU_LEGACY_DISCOVERY_ONLY') == '1'
    cpu = os.environ.get('NABU_LEGACY_CPU_PRESENT') == '1'
    scanout = cpu and profile == 'nabu_ufs_gpu_metal_defconfig'
    notification_scope = None
    if discovery and cpu:
        raise SystemExit('Discovery and CPU presentation modes are mutually exclusive')
    if discovery:
        shutil.copy2(device / 'platform/NabuLegacyDiscovery.cpp', source / 'NativeLegacyDisplay.cpp')
    elif cpu:
        shutil.copy2(device / 'platform/NabuLegacyCpuPresent.cpp', source / 'NativeLegacyDisplay.cpp')
        shutil.copy2(device / 'platform/NabuLegacyCpuPixels.h', source / 'NabuLegacyCpuPixels.h')
        if scanout:
            for name in ('NabuGpuScanoutHandoff.h', 'NabuGpuScanoutWire.h'):
                shutil.copy2(device / 'platform' / name, source / name)
        shutil.copy2(device / 'platform/NabuKeybagNotifications.cpp', source / 'NabuKeybagNotifications.cpp')
        try:
            notification_scope = validate_cpu_profile(
                (root.parent / '.config').read_text().splitlines(), profile,
                os.environ.get('NABU_BOOT_PMGR') == '1')
        except ValueError as error:
            raise SystemExit(str(error)) from error
    else:
        for name in ('NativeLegacyDisplay.cpp', 'NativeLegacyRequest.h'):
            shutil.copy2(device / 'vendor/GopFramebuffer-cf3b429' / name, source / name)
    shutil.copy2(device / 'platform/NabuLegacyDisplayProbe.cpp',
                 source / 'NabuLegacyDisplayProbe.cpp')
    shutil.copy2(device / 'platform/NabuLegacyStubs.cpp',
                 source / 'NabuLegacyStubs.cpp')
    shutil.copy2(device / 'platform/NabuGraphicsStatus.cpp',
                 source / 'NabuGraphicsStatus.cpp')

    run([sys.executable, root / 'scripts/nabu_display_bindings.py',
         '--kernelcache', kernelcache, '--native', reference, '--output-dir', abi] +
        (['--cpu-present'] if cpu else []),
        root, out / 'display-abi.log')

    recipe = root / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
    recipe_bytes = recipe.read_bytes()
    record = json.loads(recipe_bytes.decode('utf-8').strip().rstrip(','))
    includes = ['-I', str(abi), '-I', str(source),
                '-I', str(root / '.cache/xnu-work/osfmk')]
    if discovery:
        includes.append('-DNABU_LEGACY_DISCOVERY_ONLY=1')
    if cpu:
        contract = json.loads((abi / 'display-abi.json').read_text())['contracts'].get('cpu_present', {})
        if contract.get('status') != 'static_qualified':
            raise SystemExit('CPU presentation requires the original limited ABI contract')
        includes += ['-DNABU_LEGACY_CPU_PRESENT=1', '-DNABU_LEGACY_CPU_ABI_VERIFIED=1',
                     '-DNABU_KEYBAG_RAM_DATA_VERIFIED=1']
    if scanout:
        includes.append('-DNABU_LEGACY_GPU_SCANOUT=1')
    objects = []
    sources = ['NativeLegacyDisplay.cpp', 'NabuLegacyDisplayProbe.cpp',
               'NabuLegacyStubs.cpp', 'NabuGraphicsStatus.cpp']
    if cpu:
        sources.append('NabuKeybagNotifications.cpp')
    for name in sources:
        obj = out / (Path(name).stem + '.o')
        command = compile_command(record, source / name, obj) + includes
        (out / (Path(name).stem + '.command.json')).write_text(json.dumps(command, indent=2) + '\n')
        run(command, record['directory'], out / (Path(name).stem + '.log'))
        check_object(obj.read_bytes())
        objects.append(obj)

    late = out / 'NativeLegacyDisplay.late.o'
    run(['llvm-objcopy',
         '--remove-section=__DATA,__mod_init_func',
         '--globalize-symbol=__GLOBAL__sub_I_NativeLegacyDisplay.cpp',
         str(out / 'NativeLegacyDisplay.o'), str(late)],
        root, out / 'objcopy.log')
    check_object(late.read_bytes())
    objects = [late if obj.name == 'NativeLegacyDisplay.o' else obj for obj in objects]
    if cpu:
        notification = out / 'NabuKeybagNotifications.late.o'
        run(['llvm-objcopy', '--remove-section=__DATA,__mod_init_func',
             '--globalize-symbol=__GLOBAL__sub_I_NabuKeybagNotifications.cpp',
             str(out / 'NabuKeybagNotifications.o'), str(notification)],
            root, out / 'notification-objcopy.log')
        check_object(notification.read_bytes())
        objects = [notification if obj.name == 'NabuKeybagNotifications.o' else obj for obj in objects]

    sys.path.insert(0, str(root / 'kits/NativePrelink'))
    from native_prelink import macho
    symbols, compiled = object_vtable(macho, late)
    abi_report = json.loads((abi / 'display-abi.json').read_text())
    methods = [(int(row['candidate_va'], 16) if row['candidate_va'] else None)
               for row in abi_report['methods']]
    if len(methods) != 358:
        raise SystemExit('display-abi.json does not contain all 358 method slots')
    fixed = (abi / 'original-legacy-bindings.S').read_text()
    fixed_names = {line.split()[1].rstrip(',') for line in fixed.splitlines()
                   if line.startswith('.set ')}
    bindings = {}
    for slot, name in enumerate(compiled):
        if name.startswith(('__ZN19NativeLegacyDisplay', '__ZNK19NativeLegacyDisplay')):
            continue
        if '25IOMobileFramebufferLegacy' in name:
            if methods[slot] is None:
                raise SystemExit(f'No candidate address for original method slot {slot}')
            if name not in fixed_names:
                bindings[name] = methods[slot]
    undefined = {name for name, _, kind in symbols
                 if kind == 1 and 'IOMobileFramebufferLegacy' in name}
    missing = undefined - set(bindings) - fixed_names
    if missing:
        raise SystemExit('Unbound original Legacy symbols: ' + ', '.join(sorted(missing)))
    combined = out / 'original-legacy-bindings-all.S'
    combined.write_text(fixed + ''.join(
        f'.globl {name}\n.set {name}, {va:#x}\n' for name, va in sorted(bindings.items())))

    assembly = out / 'original-bindings.o'
    compiler = record['arguments'][0]
    run([compiler, '--target=arm64-apple-ios17.0', '-x', 'assembler-with-cpp',
         '-c', str(combined), '-o', str(assembly)],
        root, out / 'bindings.log')
    check_object(assembly.read_bytes())
    objects.append(assembly)

    archive = out / 'libNativeLegacyDisplay.late.a'
    archive.unlink(missing_ok=True)
    run(['llvm-ar', 'rcs', archive, *objects], root, out / 'ar.log')
    report = {
        'profile': profile,
        'archive_sha256': sha(archive),
        'source_sha256': {
            str(path.relative_to(root)): sha(path) for path in sorted(source.iterdir()) if path.is_file()
        },
        'abi_sha256': {
            'header': sha(abi / 'OriginalLegacyFramebufferABI.h'),
            'bindings': sha(abi / 'original-legacy-bindings.S'),
            'json': sha(abi / 'display-abi.json'),
        },
        'reference_candidate': str(reference),
        'reference_candidate_sha256': sha(reference),
        'discovery_only': discovery,
        'cpu_present': cpu,
        'gpu_scanout_handoff_compiled': scanout,
        'ephemeral_notification_transport_compiled': cpu,
        'notification_profile_qualification': notification_scope,
        'key_state_queries_supported': False,
        'key_operations_supported': False,
        'mode': 'cpu_present' if cpu else 'discovery_only' if discovery else 'vendor',
        'objects': {obj.name: sha(obj) for obj in objects},
        'vtable_symbols': compiled,
        'recipe_sha256': hashlib.sha256(recipe_bytes).hexdigest(),
        'kernelcache': str(kernelcache),
        'runtime_qualified': False,
    }
    (out / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'archive': str(archive), 'archive_sha256': report['archive_sha256'],
                      'sources': report['source_sha256']}, indent=2))


if __name__ == '__main__':
    main()
