"""Pinned private display reference and final-candidate binding checks."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tarfile
import tomllib

PROFILE = 'nabu_qemu_legacy_defconfig'
CPU_PROFILE = 'nabu_qemu_cpu_present_defconfig'
HARDWARE_CPU_PROFILE = 'nabu_ufs_cpu_present_defconfig'
HARDWARE_GPU_PROFILE = 'nabu_ufs_gpu_defconfig'
# The diagnostic profile keeps the accelerator out of the archive. This profile
# compiles and publishes it. Both are hardware UFS profiles with the CPU
# presentation backend, so both stay in the hardware, display and notification
# sets; the difference is the GPU archive's contract, not the display path.
HARDWARE_GPU_METAL_PROFILE = 'nabu_ufs_gpu_metal_defconfig'
HARDWARE_CPU_PROFILES = (HARDWARE_CPU_PROFILE, HARDWARE_GPU_PROFILE, HARDWARE_GPU_METAL_PROFILE)
CPU_PROFILES = (CPU_PROFILE, *HARDWARE_CPU_PROFILES)
DISPLAY_PROFILES = (PROFILE, *CPU_PROFILES)
REFERENCE = {
    'run_id': 40446350654,
    'head_sha': '85962d51b41d2b618ff1886715ac0c5f8a905758',
    'release': 'source-40446350654-attempt-1',
    'asset': 'source-40446350654-attempt-1.tar.gz',
    'sha256': 'eb304999b06edbfeee8ec6d4c866a52fff74c9b9cd279015efa5ee18ff2bde55',
    'candidate_sha256': '98b6f33210b5246eb6f5026942eafba957bbf564a6cd48ccfea95d4cf0f9a25c',
}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def extract_reference(archive, output, expected=REFERENCE):
    if sha(archive) != expected['sha256']:
        raise ValueError('Display reference archive hash mismatch')
    names = {'outputs/kernel/kernel.macho': 'kernel.macho',
             'outputs/kernel/kernel.json': 'kernel.json',
             'outputs/.config': 'reference.config',
             'prepare-report.json': 'prepare-report.json'}
    with tarfile.open(archive) as tf:
        members = {m.name: m for m in tf.getmembers()}
        if len(members) != len(tf.getmembers()):
            raise ValueError('Duplicate reference archive members')
        def read(name):
            member = members[name]
            if not member.isfile() or member.size > 160 * 1024 * 1024:
                raise ValueError('Invalid reference member: ' + name)
            return tf.extractfile(member).read()
        manifest = json.loads(read('source-manifest.json'))
        for key in ('run_id', 'head_sha'):
            if manifest[key] != expected[key]:
                raise ValueError('Reference source/run binding mismatch')
        payloads = {name: read(name) for name in names}
    for name, data in payloads.items():
        meta = manifest['files'][name]
        if len(data) != meta['bytes'] or hashlib.sha256(data).hexdigest() != meta['sha256']:
            raise ValueError('Reference member mismatch: ' + name)
    if hashlib.sha256(payloads['outputs/kernel/kernel.macho']).hexdigest() != expected['candidate_sha256']:
        raise ValueError('Reference candidate mismatch')
    report = json.loads(payloads['outputs/kernel/kernel.json'])
    if report['candidate_sha256'] != expected['candidate_sha256']:
        raise ValueError('Reference sidecar mismatch')
    config = payloads['outputs/.config'].decode().splitlines()
    if not {'CONFIG_XNU_NATIVE_LEGACY_DISPLAY=n', 'CONFIG_XNU_OWNER_DATA_MOUNT=y'} <= set(config):
        raise ValueError('Reference must be the disabled-Legacy Data candidate')
    if not json.loads(payloads['prepare-report.json']).get('data_skeleton'):
        raise ValueError('Reference lacks Data preparation')
    output.mkdir(parents=True, exist_ok=False)
    for name, relative in names.items():
        (output / relative).write_bytes(payloads[name])
    (output / 'reference-receipt.json').write_text(json.dumps(expected, indent=2) + '\n')


def symbols_and_segments(data):
    at, symbols, segments = 32, {}, []
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, at)
        if cmd == 0x19:
            segments.append(struct.unpack_from('<4Q', data, at + 24))
        if cmd == 2:
            offset, count, strings, extent = struct.unpack_from('<4I', data, at + 8)
            for index in range(count):
                name, kind, _, _, va = struct.unpack_from('<IBBHQ', data, offset + index * 16)
                if not kind & 0xe0 and kind & 0xe and va and name < extent:
                    end = data.index(b'\0', strings + name, strings + extent)
                    symbols[data[strings + name:end].decode()] = va
        at += size
    return symbols, segments


def compare_abi(reference, final):
    if reference['bindings'] != final['bindings']:
        raise ValueError('Original display aliases moved in the final candidate')
    if [m['candidate_va'] for m in reference['methods']] != [m['candidate_va'] for m in final['methods']]:
        raise ValueError('Original display vtable targets moved in the final candidate')


def qualify_display_candidate(upstream, device, candidate, expected_profile=None):
    tree = upstream / 'out/nabu/tree'
    out = tree / 'build/native-legacy-display'
    report = json.loads((out / 'build-report.json').read_text())
    cpu = report.get('cpu_present') is True
    discovery = report.get('discovery_only') is True
    profile = tomllib.loads((device / 'board.toml').read_text())['kernel']['defconfig']
    if (profile not in DISPLAY_PROFILES or report.get('profile') != profile or
            (expected_profile is not None and profile != expected_profile) or
            cpu != (profile in CPU_PROFILES) or discovery != (profile == PROFILE)):
        raise ValueError('Display archive has the wrong profile or implementation mode')
    if cpu == discovery or report['reference_candidate_sha256'] != REFERENCE['candidate_sha256']:
        raise ValueError('Display archive has the wrong mode or reference')
    if cpu:
        hardware = profile in HARDWARE_CPU_PROFILES
        expected_scope = {'profile': profile, 'data_backend': 'volatile_ram',
                          'system_transport': 'ufs' if hardware else 'virtio',
                          'boot_pmgr': 'nabu' if hardware else 'qemu'}
        if report.get('notification_profile_qualification') != expected_scope:
            raise ValueError('Notification dependencies do not match the selected CPU profile')
    if sha(out / 'libNativeLegacyDisplay.late.a') != report['archive_sha256']:
        raise ValueError('Display archive changed')
    implementation = 'NabuLegacyCpuPresent.cpp' if cpu else 'NabuLegacyDiscovery.cpp'
    if sha(out / 'source/NativeLegacyDisplay.cpp') != sha(device / 'platform' / implementation):
        raise ValueError('Display archive did not compile the selected implementation')
    if cpu and sha(out / 'source/NabuLegacyCpuPixels.h') != sha(device / 'platform/NabuLegacyCpuPixels.h'):
        raise ValueError('CPU pixel implementation changed')
    scanout = report.get('gpu_scanout_handoff_compiled') is True
    if 'gpu_scanout_handoff_compiled' in report and scanout != (cpu and profile == HARDWARE_GPU_METAL_PROFILE):
        raise ValueError('GPU scanout hand-off compiled in the wrong profile')
    if scanout:
        for name in ('NabuGpuScanoutHandoff.h', 'NabuGpuScanoutWire.h'):
            if sha(out / 'source' / name) != sha(device / 'platform' / name):
                raise ValueError('GPU scanout hand-off input changed: ' + name)
    if cpu and sha(out / 'source/NabuKeybagNotifications.cpp') != sha(device / 'platform/NabuKeybagNotifications.cpp'):
        raise ValueError('Ephemeral notification implementation changed')
    if cpu and (report.get('key_state_queries_supported') is not False or
                report.get('key_operations_supported') is not False):
        raise ValueError('Notification transport must not supply key or lock-state answers')
    compiled_sources = ['NativeLegacyDisplay', 'NabuLegacyDisplayProbe', 'NabuLegacyStubs', 'NabuGraphicsStatus']
    if cpu:
        compiled_sources.append('NabuKeybagNotifications')
    for name in compiled_sources:
        command = json.loads((out / (name + '.command.json')).read_text())
        required = (['-DNABU_LEGACY_CPU_PRESENT=1', '-DNABU_LEGACY_CPU_ABI_VERIFIED=1',
                     '-DNABU_KEYBAG_RAM_DATA_VERIFIED=1']
                    if cpu else ['-DNABU_LEGACY_DISCOVERY_ONLY=1'])
        forbidden = '-DNABU_LEGACY_DISCOVERY_ONLY=1' if cpu else '-DNABU_LEGACY_CPU_PRESENT=1'
        if any(flag not in command for flag in required) or forbidden in command:
            raise ValueError('Display object has the wrong implementation compile flags')
        if ('-DNABU_LEGACY_GPU_SCANOUT=1' in command) != scanout:
            raise ValueError('Display object has the wrong scanout compile flag')
    for name, digest in report['source_sha256'].items():
        if not (tree / name).resolve().is_relative_to(tree.resolve()) or sha(tree / name) != digest:
            raise ValueError('Display source mismatch')
    for name, digest in report['objects'].items():
        if sha(out / name) != digest:
            raise ValueError('Display object mismatch')
    final_dir = out / 'final-abi'
    subprocess.run([sys.executable, device / 'scripts/nabu_display_bindings.py',
                    '--kernelcache', report['kernelcache'], '--native', candidate,
                    '--native-prelink', tree / 'kits/NativePrelink', '--output-dir', final_dir] +
                   (['--cpu-present'] if cpu else []),
                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    reference = json.loads((out / 'abi/display-abi.json').read_text())
    final = json.loads((final_dir / 'display-abi.json').read_text())
    compare_abi(reference, final)
    if cpu and (reference['contracts'].get('cpu_present', {}).get('status') != 'static_qualified' or
                final['contracts'].get('cpu_present') != reference['contracts'].get('cpu_present')):
        raise ValueError('Final CPU limited ABI contract changed')
    raw = candidate.read_bytes()
    symbols, segments = symbols_and_segments(raw)
    if scanout:
        for name in ('_nabu_gpu_scanout_display_call', '_nabu_gpu_scanout_display_memory', '_nabu_gpu_scanout_display_close'):
            if name not in symbols:
                raise ValueError('Final kernel lacks GPU scanout callback: ' + name)
    aliases = re.findall(r'^\.set (\S+), (0x[0-9a-f]+)$',
                         (out / 'original-legacy-bindings-all.S').read_text(), re.M)
    for name, address in aliases:
        if symbols.get(name) != int(address, 16):
            raise ValueError('Final display alias mismatch: ' + name)
    vtable = symbols['__ZTV19NativeLegacyDisplay'] + 16
    matches = [(fo + vtable - va) for va, _, fo, fs in segments if va <= vtable and vtable + 358 * 8 <= va + fs]
    if len(matches) != 1 or len(report['vtable_symbols']) != 358:
        raise ValueError('Final display vtable is incomplete')
    slots = struct.unpack_from('<358Q', raw, matches[0])
    for index, name in enumerate(report['vtable_symbols']):
        if slots[index] != symbols.get(name):
            raise ValueError(f'Final display dispatch mismatch at slot {index}: {name}')
    return {'profile': profile, 'mode': 'cpu_present' if cpu else 'discovery_only', 'reference': REFERENCE,
            'archive_sha256': report['archive_sha256'], 'aliases_verified': len(aliases),
            'vtable_slots_verified': 358, 'candidate_sha256': sha(candidate),
            'pixel_transfer_enabled': cpu, 'pixel_transfer_runtime_observed': False,
            **({'gpu_scanout_handoff': {'trigger': 'nabu-gpu-scanout=1', 'wire_version': 1,
                'wire_sha256': sha(out / 'source/NabuGpuScanoutWire.h'),
                'zero_copy': True, 'hardware_tested': False}} if scanout else {}),
            'user_client_interposition': False,
            'ephemeral_notification_transport_compiled': cpu,
            'notification_profile_qualification': report.get('notification_profile_qualification'),
            'key_operations_supported': False, 'key_state_queries_supported': False,
            'runtime_qualified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    extract_reference(args.archive, args.output)
