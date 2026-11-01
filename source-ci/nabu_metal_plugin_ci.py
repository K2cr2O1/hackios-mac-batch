#!/usr/bin/env python3
"""Build UniXNU's NativeAdrenoMetal.bundle (metal2vulkan bridge + Turnip) for iOS 17 against the A640 ABI.

Called by nabu_turnip_ci.py after Turnip is built in the pinned UniXNU checkout. Initializes only the two
submodules the plugin build reads at their pinned gitlinks, fetches the pinned metal2vulkan translator, then
runs UniXNU's own scripts/build-adreno-metal-plugin.py with the A640 board options. A build only proves
compilation, linking and signing: no GPU is exercised and nothing is installed.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

# Gitlinks of UniXNU cd2dd1bd (checked against the checkout's tree before use).
SUBMODULES = {
    'drivers/AdrenoMetal': ('https://github.com/RigoLigoRLC/unixnu-adrenometal.git',
                            'baad47ca22b181bf0ef0d08412d3ed1f96945e16'),
    'kits/AdrenoPM4': ('https://github.com/UniXNU/AdrenoPM4.git', '282606b528b2595bc4274ea7490b62b323f35a5f'),
}
METAL2VULKAN = 'https://github.com/steelbrain/metal2vulkan.git'
RUST = '1.98.0'
# Nabu supplies the GOP wire; its scanout backend is opt-in at boot. QuartzCore addresses and replay remain A740-only.
BOARD_ARGUMENTS = ('--scanout-copy', 'on', '--quartzcore-display-state', 'off', '--turnip-replay', 'off')
# Built by build-adreno-metal-plugin.py but not deployed on nabu; listed in the report only.
# nabu patches to the pinned AdrenoMetal checkout (paths relative to the device tree), applied in order.
ADRENOMETAL_PATCHES = ('patches/adrenometal-shader-cache-optional.patch', 'patches/adrenometal-quartzcore-failures.patch',
                       'patches/adrenometal-nabu-scanout.patch')
UNDEPLOYED = ('adrenoprobed', 'adrenoprobed-entitlements.plist', 'org.blu-sharky.adrenoprobed.plist',
              'com.apple.iomfb_fdr_loader.plist', 'com.apple.bluetoothd.plist')


def run(command, **kwargs):
    print('+ ' + ' '.join(map(str, command)), flush=True)
    return subprocess.run([str(c) for c in command], check=True, **kwargs)


def read(command):
    return subprocess.check_output([str(c) for c in command], text=True).strip()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fetch(path, url, commit, *, blob_filter=False):
    run(['git', 'init', '-q', path])
    run(['git', '-C', path, 'remote', 'add', 'origin', url])
    run(['git', '-C', path, 'fetch', '-q', '--depth', '1', *(['--filter=blob:none'] if blob_filter else []),
         'origin', commit])
    run(['git', '-C', path, 'checkout', '-q', commit])
    if read(['git', '-C', path, 'rev-parse', 'HEAD']) != commit:
        raise SystemExit('Pinned checkout differs: ' + str(path))


def prepare(root, device):
    for path, (url, commit) in SUBMODULES.items():
        entry = read(['git', '-C', root, 'ls-tree', 'HEAD', path]).split()
        if entry[:3] != ['160000', 'commit', commit]:
            raise SystemExit('UniXNU gitlink differs from the recorded pin: ' + path)
        target = root / path
        if target.exists() and any(target.iterdir()):
            raise SystemExit('Submodule path is not empty: ' + path)
        fetch(target, url, commit)
    metal = root / 'drivers/AdrenoMetal'
    for patch in ADRENOMETAL_PATCHES:
        run(['git', '-C', metal, 'apply', '--check', device / patch])
        run(['git', '-C', metal, 'apply', device / patch])
    shutil.copyfile(device / 'platform/NabuGpuScanoutWire.h', metal / 'NabuGpuScanoutWire.h')
    pins = json.loads((root / 'scripts/data/gpu-metal-vulkan-inputs.json').read_text())
    translator = pins['translator']['commit']
    if pins['translator']['repository'].rstrip('/') + '.git' != METAL2VULKAN:
        raise SystemExit('Translator repository differs from the recorded pin')
    source = root / '.cache/gpu-reference/metal2vulkan'
    source.parent.mkdir(parents=True, exist_ok=True)
    fetch(source, METAL2VULKAN, translator, blob_filter=True)
    return translator


def bundle_files(bundle):
    files = []
    for path in sorted(bundle.rglob('*')):
        if path.is_symlink():
            raise SystemExit('Linked file in the plugin bundle: ' + str(path))
        if path.is_file():
            files.append({'path': path.relative_to(bundle.parent).as_posix(), 'bytes': path.stat().st_size,
                          'sha256': sha(path), 'mode': oct(path.stat().st_mode & 0o7777)})
    return files


def build(root, device, output, env):
    """Returns the report's plugin section; the build's own return code is plugin['plugin_returncode']."""
    root, device, output = Path(root), Path(device).resolve(), Path(output)
    abi = device / 'gpu/upstream/Adreno6xx'
    output.mkdir(parents=True)
    report = {'adrenometal_commit': SUBMODULES['drivers/AdrenoMetal'][1],
              'adrenopm4_commit': SUBMODULES['kits/AdrenoPM4'][1], 'rust_toolchain': RUST,
              'abi_header_sha256': sha(abi / 'NativeAdrenoABI.h'), 'gpu_exercised': False, 'runtime_qualified': False}
    report['metal2vulkan_commit'] = prepare(root, device)
    report['adrenometal_patches'] = {patch: sha(device / patch) for patch in ADRENOMETAL_PATCHES}
    report['scanout_wire_sha256'] = sha(device / 'platform/NabuGpuScanoutWire.h')
    report['rust_version'] = read(['rustc', '+' + RUST, '--version'])
    compiler = shutil.which('glslangValidator', path=env['PATH'])
    if not compiler:
        raise SystemExit('glslangValidator is required for the bundled shaders')
    arguments = ['--gpu-abi-dir', str(abi), *BOARD_ARGUMENTS, '--shader-compiler', compiler]
    report['arguments'] = arguments
    log = output / 'build-adreno-metal-plugin.log'
    with log.open('w') as stream:
        result = subprocess.run(['python3', root / 'scripts/build-adreno-metal-plugin.py', *arguments], cwd=root,
                                env=env, stdout=stream, stderr=subprocess.STDOUT)
    report['plugin_returncode'] = result.returncode
    bridge_log = root / 'build/adreno-metal-bridge/build-ios.log'
    if bridge_log.is_file():
        shutil.copyfile(bridge_log, output / 'bridge-build-ios.log')
    built = root / 'build/adreno-metal-plugin'
    bundle = built / 'NativeAdrenoMetal.bundle'
    report['bundle_built'] = result.returncode == 0 and (bundle / 'NativeAdrenoMetal').is_file()
    if report['bundle_built']:
        shutil.copytree(bundle, output / bundle.name, symlinks=True)
        shutil.copyfile(built / 'trust.json', output / 'trust.json')
        trust = json.loads((built / 'trust.json').read_text())
        report.update(bundle_files=bundle_files(output / bundle.name), cdhash=trust['cdhash'],
                      turnip_cdhash=trust['turnip_cdhash'], executable_bytes=trust['executable_bytes'],
                      executable_file=read(['file', bundle / 'NativeAdrenoMetal']),
                      undeployed={name: sha(built / name) for name in UNDEPLOYED if (built / name).is_file()})
    (output / 'plugin-report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report
