#!/usr/bin/env python3
"""Cross-build Turnip (Mesa freedreno Vulkan, darwin KMD) for iOS 17 against the A640 kernel ABI.

Runs only in macOS GitHub Actions. Pins the UniXNU revision that carries the recorded Mesa patch
series and the Mesa commit those patches name, applies the series in its recorded order, then runs
UniXNU's own scripts/build-turnip-darwin.py with --target ios and --abi-directory pointed at the
nabu A640 NativeAdrenoABI.h. A build only proves compilation and linking: no GPU is exercised.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

UNIXNU = 'https://github.com/UniXNU/UniXNU.git'
# The recorded 19-patch Turnip series (scripts/data/adreno-compiler-inputs.json) is at this revision;
# the kernel build's 245aca1a carries an older 9-patch series.
UNIXNU_COMMIT = 'cd2dd1bd0d79a441424f2bd014144bd719ba56f7'
MESA_COMMIT = '85fda3b36405bcaea8bffc64aa4f2651dc90770d'
MESA_TREE = 'b72ff1eb2138026ed6aba524770899faabf7d7c8'
# The AdrenoMetal revision UniXNU cd2dd1bd pins as drivers/AdrenoMetal: NativeTurnipSmoke.h and shaders/.
ADRENOMETAL = 'https://github.com/RigoLigoRLC/unixnu-adrenometal.git'
ADRENOMETAL_COMMIT = 'baad47ca22b181bf0ef0d08412d3ed1f96945e16'
# nabu patches applied after UniXNU's recorded-series identity check (paths relative to the device tree).
NABU_PATCHES = ('patches/mesa-turnip-a640-trace-guard.patch',)
PYTHON_PACKAGES = ('meson==1.6.1', 'mako==1.3.8', 'pyyaml==6.0.2', 'packaging==24.2')


def run(command, **kwargs):
    print('+ ' + ' '.join(map(str, command)), flush=True)
    return subprocess.run([str(c) for c in command], check=True, **kwargs)


def read(command, **kwargs):
    return subprocess.check_output([str(c) for c in command], text=True, **kwargs).strip()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(ok, message):
    if not ok:
        raise SystemExit(message)


def bison(root, pins):
    """Bison 3.8.2 from the pinned tarball: the macOS system bison is 2.3, which Mesa refuses."""
    tools = root / '.cache/mesa-tools'
    if (tools / 'bin/bison').is_file():
        return
    item = pins['bison']
    archive = root / '.cache' / Path(item['url']).name
    run(['curl', '-fsSL', '--retry', '3', '-o', archive, item['url']])
    require(archive.stat().st_size == item['bytes'] and sha(archive) == item['sha256'], 'Bison tarball identity differs')
    work = root / '.cache/bison-src'
    work.mkdir(parents=True, exist_ok=True)
    run(['tar', '-xf', archive, '-C', work, '--strip-components', '1'])
    run(['./configure', '--prefix=' + str(tools), '--disable-nls'], cwd=work, stdout=subprocess.DEVNULL)
    run(['make', '-j6', 'install'], cwd=work, stdout=subprocess.DEVNULL)


def mesa(root, pins):
    source = root / '.cache/mesa-work'
    require(pins['mesa']['commit'] == MESA_COMMIT and pins['mesa']['tree'] == MESA_TREE, 'Pinned Mesa identity changed')
    run(['git', 'init', '-q', source])
    run(['git', '-C', source, 'remote', 'add', 'origin', pins['mesa']['mirror']])
    run(['git', '-C', source, 'fetch', '-q', '--depth', '1', '--filter=blob:none', 'origin', MESA_COMMIT])
    run(['git', '-C', source, 'sparse-checkout', 'set', '--cone', *pins['mesa']['sparse_directories']])
    run(['git', '-C', source, 'checkout', '-q', MESA_COMMIT])
    require(read(['git', '-C', source, 'rev-parse', 'HEAD^{tree}']) == MESA_TREE, 'Mesa tree differs')
    for patch in pins['patches']:
        path = root / patch
        # git apply rejects the new-file headers of turnip-darwin-perfetto-capture; patch -p1 accepts them.
        if subprocess.run(['git', '-C', source, 'apply', '--check', path], capture_output=True).returncode == 0:
            run(['git', '-C', source, 'apply', path])
        else:
            run(['patch', '-p1', '--dry-run', '-s', '-f', '-i', path], cwd=source)
            run(['patch', '-p1', '-s', '-f', '-i', path], cwd=source)
    # UniXNU's own guard: the recorded series must reconstruct the pinned source exactly.
    sys.path.insert(0, str(root / 'scripts'))
    from mesa_patch_identity import validate_recorded_patches
    validate_recorded_patches(root, source, pins)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--plugin', action='store_true',
                        help='also build NativeAdrenoMetal.bundle (nabu_metal_plugin_ci.py) on the built Turnip')
    parser.add_argument('--fps-opt', action='store_true',
                        help='build the bounded scanout-source cache experiment on the four-patch plugin baseline')
    parser.add_argument('--async-fix', action='store_true',
                        help='qualify and build asynchronous Metal creation on the four-patch plugin baseline')
    args = parser.parse_args()
    require(not args.fps_opt or args.plugin, '--fps-opt requires --plugin')
    require(not args.async_fix or args.plugin, '--async-fix requires --plugin')
    require(not (args.async_fix and args.fps_opt), 'Keep async creation and FPS experiments separate')
    require(sys.platform == 'darwin' and os.environ.get('GITHUB_ACTIONS') == 'true', 'Run only in macOS GitHub Actions')
    device, root, output = args.device.resolve(), args.work.resolve(), args.output.resolve()
    abi = device / 'gpu/upstream/Adreno6xx'
    require((abi / 'NativeAdrenoABI.h').is_file(), 'A640 ABI header missing')
    require(not root.exists() and not output.exists(), 'Use new work and output directories')
    run(['git', 'init', '-q', root])
    run(['git', '-C', root, 'remote', 'add', 'origin', UNIXNU])
    run(['git', '-C', root, 'fetch', '-q', '--depth', '1', 'origin', UNIXNU_COMMIT])
    run(['git', '-C', root, 'checkout', '-q', UNIXNU_COMMIT])
    pins_path = root / 'scripts/data/adreno-compiler-inputs.json'
    pins = json.loads(pins_path.read_text())
    require(len(pins['patches']) == 19, 'Unexpected Mesa patch series length')
    upstream_pins_sha256 = sha(pins_path)
    # build-turnip-darwin.py re-runs the recorded-series identity check, so the nabu patches join the
    # recorded series (after the upstream 19) instead of being applied outside it.
    for patch in NABU_PATCHES:
        recorded = 'patches/mesa/' + Path(patch).name
        require(not (root / recorded).exists(), 'nabu patch name collides with an upstream patch')
        shutil.copyfile(device / patch, root / recorded)
        pins['patches'].append(recorded)
    pins_path.write_text(json.dumps(pins, indent=2) + '\n')
    (root / '.cache').mkdir()
    run([sys.executable, '-m', 'venv', root / '.cache/mesa-venv'])
    run([root / '.cache/mesa-venv/bin/pip', 'install', '-q', *PYTHON_PACKAGES])
    bison(root, pins)
    mesa(root, pins)
    env = dict(os.environ, PATH=str(root / '.cache/mesa-tools/bin') + ':' + os.environ['PATH'])
    require(shutil.which('glslangValidator', path=env['PATH']) and shutil.which('ninja', path=env['PATH']),
            'glslang and ninja are required')
    result = subprocess.run([sys.executable, root / 'scripts/build-turnip-darwin.py', '--target', 'ios',
                             '--abi-directory', abi], cwd=root, env=env)
    output.mkdir(parents=True)
    for log in ('mesa-tu-ios-configure.log', 'mesa-tu-ios-build.log'):
        if (root / '.cache' / log).is_file():
            shutil.copyfile(root / '.cache' / log, output / log)
    library = root / 'build/mesa-tu-ios/src/freedreno/vulkan/libvulkan_freedreno.dylib'
    report = dict(unixnu_commit=UNIXNU_COMMIT, mesa_commit=MESA_COMMIT, mesa_tree=MESA_TREE,
                  patches=pins['patches'], patch_sha256={p: sha(root / p) for p in pins['patches']},
                  nabu_patches={p: sha(device / p) for p in NABU_PATCHES},
                  upstream_pins_sha256=upstream_pins_sha256, recorded_pins_sha256=sha(pins_path),
                  abi_header_sha256=sha(abi / 'NativeAdrenoABI.h'), build_returncode=result.returncode,
                  library_built=library.is_file(), gpu_exercised=False, runtime_qualified=False)
    if library.is_file():
        shutil.copyfile(library, output / library.name)
        report.update(library_sha256=sha(library), library_bytes=library.stat().st_size,
                      library_file=read(['file', library]))
        profile = root / 'build/mesa-tu-ios/builtin-build-profile.json'
        if profile.is_file():
            shutil.copyfile(profile, output / profile.name)
        # The Turnip-enabled owner probe: the same probe plus the Vulkan known-image stage, built against this
        # exact library, its Mesa headers and the pinned AdrenoMetal smoke test.
        smoke = root / '.cache/adrenometal'
        run(['git', 'init', '-q', smoke])
        run(['git', '-C', smoke, 'remote', 'add', 'origin', ADRENOMETAL])
        run(['git', '-C', smoke, 'fetch', '-q', '--depth', '1', 'origin', ADRENOMETAL_COMMIT])
        run(['git', '-C', smoke, 'checkout', '-q', ADRENOMETAL_COMMIT])
        probe = subprocess.run([sys.executable, device / 'scripts/build-nabu-gpu-userprobe.py',
                                '--output', output / 'userprobe', '--turnip-library', library,
                                '--turnip-headers', root / '.cache/mesa-work/include', '--adrenometal', smoke], env=env)
        report.update(adrenometal_commit=ADRENOMETAL_COMMIT, probe_returncode=probe.returncode)
        if probe.returncode:
            result = probe
        # The Metal plugin (UniXNU step 4) on the same Turnip; its failure keeps the Turnip and probe outputs.
        if args.plugin:
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            import nabu_metal_plugin_ci
            try:
                plugin = nabu_metal_plugin_ci.build(root, device, output / 'plugin', env,
                                                   fps_opt=args.fps_opt, async_fix=args.async_fix)
            except (subprocess.CalledProcessError, SystemExit, OSError, ValueError, KeyError) as error:
                plugin = {'plugin_returncode': 1, 'bundle_built': False, 'error': str(error)[-2000:],
                          'gpu_exercised': False, 'runtime_qualified': False}
            report['plugin'] = plugin
            if plugin['plugin_returncode'] or not plugin['bundle_built']:
                result = subprocess.CompletedProcess(args=[], returncode=plugin['plugin_returncode'] or 1)
    (output / 'turnip-report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report.get(k) for k in ('build_returncode', 'library_built', 'library_bytes')}))
    if 'plugin' in report:
        print(json.dumps({k: report['plugin'].get(k) for k in ('plugin_returncode', 'bundle_built', 'cdhash')}))
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())
