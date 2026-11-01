"""Replay the A640 GPU build identity; never claim GPU runtime success.

Two contracts share this module.

* The diagnostic profile must NOT contain the publication objects or the
  publication symbols. It is the candidate that has actually run on the tablet,
  so its negative controls stay in place.
* The Metal profile must contain them, must stage the two late objects whose
  static initializers may only run after the original IOGPUFamily has
  registered, and must bind the three original IOAcceleratorES symbols to
  addresses derived from this candidate's own extents rather than from a fixed
  slide of another image's addresses.

Neither profile claims a runtime capability: ``runtime_qualified`` and
``hardware_tested`` stay false, and compiling the publication path is not
evidence that the service was published.
"""
import ast
import hashlib
import json
from pathlib import PurePosixPath
import re
import struct

from nabu_display_ci import (HARDWARE_GPU_PROFILE as PROFILE,
                             HARDWARE_GPU_METAL_PROFILE as METAL_PROFILE)

OUTPUT = 'outputs/tree/build/native-adreno/'
PMAP_SOURCE = 'outputs/tree/.cache/xnu-work/osfmk/arm/pmap/pmap.c'
# The audited accelerator ABI contract is a build input, not decoration: the
# bindings generator consumes it, so it must be manifest-bound like any source.
SOURCE_SUFFIXES = {'.c', '.cpp', '.h', '.json'}
SOURCE_NAMES = {'LICENSE', 'COPYING', 'PROVENANCE'}
REQUIRED_SYMBOLS = {'_native_adreno_a6xx_start', '_native_adreno_a6xx_resources',
                    '_native_adreno_checkpoint', '_native_adreno_poll_irqs', '_nabu_log_committed_end'}
FORBIDDEN_SYMBOLS = {'_native_adreno_accelerator_publish', '_native_adreno_publish',
                     '_native_adreno_control_publish', '_native_adreno_new_user_client'}
REQUIRED_OBJECTS = {name for name in (
    'NativeAdrenoMemory', 'NativeAdrenoVm', 'NativeAdrenoCpu', 'NativeAdrenoKernelTime',
    'NativeAdrenoRing', 'NativeAdrenoCpInit', 'NativeAdrenoIrq', 'NativeAdrenoSmmuMemory',
    'NativeAdrenoSmmuContext', 'NativeAdrenoGmuMemory', 'NativeAdrenoGmuContext',
    'NativeAdrenoGpuContext', 'NativeAdrenoA6xxPower', 'NativeAdrenoA6xxGmu',
    'NativeAdrenoA6xxHwInit', 'NativeAdrenoA6xxSmmu', 'NativeAdrenoA6xxZap',
    'NativeAdrenoService', 'NativeAdrenoSha256', 'NativeAdrenoGpuProfile', 'NabuGpuResources', 'NabuGpuStart',
    'ArmSmmu4K', 'ArmSmmu4KAudit', 'ArmSmmu4KContext', 'ArmSmmu4KLive',
    'ArmSmmu4KMmio', 'ArmSmmu4KProgram', 'ArmSmmu4KStreams', 'ArmSmmu4KTableMemory', 'AdrenoPM4')}
FORBIDDEN_OBJECTS = {'NativeAdrenoPublish', 'NativeAdrenoAccelerator', 'NativeAdrenoUserClient',
                     'NativeAdrenoClient', 'NativeAdrenoSubmit', 'NativeAdrenoScheduler'}
CONTRACT = {'profile': PROFILE, 'mode': 'a640_diagnostic', 'firmware_mode': 'adt',
            'trigger': 'nabu-gpu=1', 'metal_accelerator': False, 'runtime_qualified': False}

# Accelerator mode. NativeAdrenoTimer is not optional: NativeAdrenoUserClient
# reads the always-on counter through it, so omitting it leaves a link gap.
PUBLICATION_OBJECTS = ('NativeAdrenoPublish', 'NativeAdrenoAccelerator', 'NativeAdrenoUserClient',
                       'NativeAdrenoClient', 'NativeAdrenoSubmit', 'NativeAdrenoScheduler',
                       'NativeAdrenoTimer')
# Exactly these two defer their static initializer: their registration would run
# before the original parent metaclass exists. Their __text must not change.
LATE_OBJECTS = ('NativeAdrenoPublish', 'NativeAdrenoAccelerator')
PUBLICATION_SYMBOLS = {'_native_adreno_accelerator_publish', '_native_adreno_publish',
                       '_native_adreno_new_user_client'}
BINDING_SYMBOLS = ('__ZN15IOAcceleratorESC2EPK11OSMetaClass',
                   '__ZN15IOAcceleratorESD2Ev',
                   '__ZN15IOAcceleratorES10gMetaClassE')
BINDINGS_SOURCE = 'original-accelerator-bindings.S'
BINDINGS_OBJECT = 'original-accelerator-bindings.o'
BINDINGS_REPORT = 'adreno-bindings.json'
BINDINGS_GENERATOR = 'scripts/nabu_adreno_bindings.py'
IOGPU_MODULE = 'com.apple.iokit.IOGPUFamily'
METAL_REQUIRED_OBJECTS = REQUIRED_OBJECTS | set(PUBLICATION_OBJECTS)
METAL_REQUIRED_SYMBOLS = REQUIRED_SYMBOLS | PUBLICATION_SYMBOLS
METAL_CONTRACT = {'profile': METAL_PROFILE, 'mode': 'a640_metal', 'firmware_mode': 'adt',
                  'trigger': 'nabu-gpu=1', 'metal_accelerator': True, 'runtime_qualified': False}
GPU_PROFILES = (PROFILE, METAL_PROFILE)
CONTRACTS = {PROFILE: CONTRACT, METAL_PROFILE: METAL_CONTRACT}
ADDRESS = re.compile('0x[0-9a-f]{16}')
# A segment size is a byte count, not an address: the generator writes hex(size).
EXTENT = re.compile('0x[0-9a-f]{1,16}')


def gpu_contract(profile):
    try:
        return CONTRACTS[profile]
    except KeyError:
        raise ValueError('No GPU contract is declared for profile: ' + str(profile)) from None


def accelerator_mode(profile):
    return profile == METAL_PROFILE


def source_scripts(profile):
    builder = 'scripts/build-nabu-adreno.py'
    return (builder, BINDINGS_GENERATOR) if accelerator_mode(profile) else (builder,)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_object(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate GPU JSON key: ' + key)
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=unique)
    require(isinstance(value, dict), 'Expected GPU JSON object')
    return value


def relative(name):
    require(isinstance(name, str) and name and '\\' not in name and ':' not in name,
            'Invalid GPU relative path')
    path = PurePosixPath(name)
    require(bool(path.parts) and not path.is_absolute() and path.as_posix() == name and
            all(part not in ('.', '..') for part in path.parts), 'GPU path traversal')
    return path


def public_source(name):
    path = relative(name)
    return path.parts[0] == 'gpu' and (path.suffix in SOURCE_SUFFIXES or path.name in SOURCE_NAMES)


def source_identity(sources):
    return sha(json.dumps(sources, sort_keys=True, separators=(',', ':')).encode())


def archive_members(data):
    """Read ordinary BSD/GNU ar members without invoking a host toolchain."""
    require(data.startswith(b'!<arch>\n'), 'GPU archive is not an ordinary ar archive')
    at, result, names = 8, {}, b''
    while at < len(data):
        require(at + 60 <= len(data), 'Truncated GPU archive header')
        header = data[at:at + 60]
        require(header[58:60] == b'`\n', 'Invalid GPU archive header')
        try:
            size = int(header[48:58].strip())
            name = header[:16].decode('ascii').rstrip()
        except (ValueError, UnicodeDecodeError) as error:
            raise ValueError('Invalid GPU archive member metadata') from error
        at += 60
        require(0 <= size <= len(data) - at, 'Truncated GPU archive member')
        payload = data[at:at + size]
        at += size + (size & 1)
        require(at <= len(data), 'Missing GPU archive member padding')
        if name.startswith('#1/'):
            length = int(name[3:])
            require(0 < length <= len(payload), 'Invalid BSD archive member name')
            name, payload = payload[:length].rstrip(b'\0').decode(), payload[length:]
        elif name == '//':
            names = payload
            continue
        elif name.startswith('/') and name[1:].isdigit():
            offset = int(name[1:])
            require(offset < len(names), 'Invalid GNU archive member name')
            end = names.find(b'/\n', offset)
            require(end >= offset, 'Unterminated GNU archive member name')
            name = names[offset:end].decode()
        elif name not in ('/', '/SYM64/'):
            name = name.removesuffix('/')
        if name in ('/', '/SYM64/', '__.SYMDEF', '__.SYMDEF SORTED', '__.SYMDEF_64', '__.SYMDEF_64 SORTED'):
            continue
        require(relative(name).name == name and name not in result, 'Duplicate or nested GPU archive member')
        result[name] = payload
    return result


def candidate_definitions(data, profile=PROFILE, extra_required=()):
    """Return (section definitions, absolute original-base bindings)."""
    require(len(data) >= 32 and struct.unpack_from('<4I', data) == (0xfeedfacf, 0x100000c, 0, 2),
            'GPU candidate is not an ARM64 executable')
    count, extent = struct.unpack_from('<II', data, 16)
    require(count > 0 and extent <= len(data) - 32, 'Invalid GPU Mach-O commands')
    at, table = 32, None
    for _ in range(count):
        require(at + 8 <= 32 + extent, 'Truncated GPU Mach-O command')
        command, size = struct.unpack_from('<II', data, at)
        require(size >= 8 and size <= 32 + extent - at, 'Invalid GPU Mach-O command')
        if command == 2:
            require(size >= 24 and table is None, 'Invalid GPU symbol table command')
            table = struct.unpack_from('<4I', data, at + 8)
        at += size
    require(at == 32 + extent and table is not None, 'Missing GPU symbol table')
    offset, number, strings, length = table
    require(offset + number * 16 <= len(data) and strings + length <= len(data),
            'Invalid GPU symbol table bounds')
    metal = accelerator_mode(profile)
    required = set(METAL_REQUIRED_SYMBOLS if metal else REQUIRED_SYMBOLS) | set(extra_required)
    forbidden = set() if metal else FORBIDDEN_SYMBOLS
    found, bindings = {}, {}
    for index in range(number):
        name, kind, section, _, address = struct.unpack_from('<IBBHQ', data, offset + 16 * index)
        if kind & 0xe0:
            continue
        require(name < length, 'Invalid GPU symbol name')
        end = data.find(b'\0', strings + name, strings + length)
        require(end >= 0, 'Unterminated GPU symbol name')
        name = data[strings + name:end].decode()
        require(name not in forbidden, 'Diagnostic GPU candidate contains publication symbol: ' + name)
        if name in required:
            require(kind & 0xe == 0xe and section > 0 and address > 0 and name not in found,
                    'GPU entry is not a unique section definition: ' + name)
            found[name] = hex(address)
        elif metal and name in BINDING_SYMBOLS:
            # A linker .set alias is an absolute definition, not a section one.
            require(kind & 0xe == 0x2 and section == 0 and address > 0 and name not in bindings,
                    'Accelerator original-base binding is not a unique absolute definition: ' + name)
            bindings[name] = hex(address)
    missing = ', '.join(sorted(required - set(found)))
    require(set(found) == required,
            ('Missing GPU definitions: ' if metal else 'Missing GPU diagnostic definitions: ') + missing)
    return found, bindings


def qualify_userprobe_boot(read, candidate):
    """Bind the optional closed addon transport to compiled RAM and XNU inputs."""
    prefix = 'outputs/tree/build/native-ram-block/'
    ram_report = json_object(read(prefix + 'build-report.json'))
    support = ram_report.get('gpu_userprobe_addon')
    require(isinstance(support, dict) and ram_report.get('compiled') is True,
            'Missing compiled GPU userprobe RAM support')
    header = read('device/platform/NabuGpuUserprobeAddon.h')
    generator = read('device/scripts/nabu_gpu_userprobe_source.py')
    require(support.get('header_sha256') == sha(header) and
            support.get('generator_sha256') == sha(generator) and
            read(prefix + 'NabuGpuUserprobeAddon.h') == header,
            'GPU userprobe boot input identity mismatch')
    constants = {}
    cache_entries = None
    process_constants = {}
    exec_trace_constants = {}
    for item in ast.parse(generator.decode('utf-8')).body:
        if isinstance(item, ast.Assign) and len(item.targets) == 1 and isinstance(item.targets[0], ast.Name):
            if item.targets[0].id in ('RAM_HELPER', 'RAM_GATE', 'DATA_BRANCH', 'PARENTS_BEFORE', 'PARENTS_AFTER'):
                constants[item.targets[0].id] = ast.literal_eval(item.value).encode()
            elif item.targets[0].id == 'CACHE_ENTRY_COUNT':
                cache_entries = ast.literal_eval(item.value)
            elif item.targets[0].id in ('EXEC_HELPER', 'EXEC_LOCAL', 'EXEC_ENTER', 'EXEC_RETURN', 'EXIT_HOOK'):
                process_constants[item.targets[0].id] = ast.literal_eval(item.value).encode()
            elif item.targets[0].id in ('EXEC_TRACE_HELPER', 'EXEC_TRACE_DECL', 'EXEC_TRACE_PAIRS'):
                exec_trace_constants[item.targets[0].id] = ast.literal_eval(item.value)
    require({'RAM_HELPER', 'RAM_GATE', 'DATA_BRANCH'} <= set(constants) and
            all(constants.values()), 'GPU userprobe source generator contract changed')
    ram = read(prefix + 'NativeRamBlock.cpp')
    require(ram_report.get('actual_source_sha256') == sha(ram) and
            ram.count(constants['RAM_HELPER']) == 1 and ram.count(constants['RAM_GATE']) == 1,
            'Actual RAM source lacks the closed inline GPU userprobe transport')
    obj = read(prefix + 'NativeRamBlock.o')
    archive = read(prefix + 'libNativeRamBlock.a')
    members = archive_members(archive)
    require(ram_report.get('object_sha256') == sha(obj) and
            ram_report.get('archive_sha256') == sha(archive) and
            set(members) == {'NativeRamBlock.o'} and members['NativeRamBlock.o'] == obj,
            'GPU userprobe RAM object/archive binding mismatch')
    data_path = 'outputs/tree/.cache/xnu-work/bsd/kern/kern_exec.c'
    data = read(data_path)
    capture = json_object(read('outputs/tree/build/nabu-log/source-report.json'))
    require(data.count(constants['DATA_BRANCH']) == 1 and capture.get('gpu_userprobe_boot') is True and
            capture.get('hooks', {}).get('bsd/kern/kern_exec.c') == sha(data),
            'Actual XNU source lacks the opt-in owner probe job')
    parents_fixed = 'PARENTS_AFTER' in constants
    if parents_fixed:
        require(data.count(constants['PARENTS_AFTER']) == 1 and constants['PARENTS_BEFORE'] not in data,
                'Actual XNU addon installer still skips its missing ngpu root directory')
    if cache_entries is not None:
        require(cache_entries == 4 and (b'native_gpu_addon_files != 4' in constants['DATA_BRANCH'] or
                b'(native_gpu_addon_files != 4 && native_gpu_addon_files != 5)' in constants['DATA_BRANCH']) and
                b'cache_point[] = "/System/Library/xpc"' in constants['DATA_BRANCH'],
                'Owner job-cache source contract changed')
    # The NativeAdrenoMetal bundle over /System/Library/Extensions, only after the verified cache mount.
    plugin_bound = b'NABU_GPU_USERPROBE_PLUGIN_V1' in constants['DATA_BRANCH']
    if plugin_bound:
        branch = constants['DATA_BRANCH']
        require(cache_entries == 4 and b'native_gpu_addon_files != 8' in branch and b'native_gpu_addon_files != 9' in branch and
                b'plugin_point[] = "/System/Library/Extensions"' in branch and
                b'"/System/Library/Extensions/NativeAdrenoMetal.bundle/Info.plist"' in branch and
                branch.index(b'cache_point[] = "/System/Library/xpc"') < branch.index(b'plugin_point[]') and
                b'#define NABU_GPU_USERPROBE_PLUGIN_ADDON_MAX 15728640u' in header and
                b'"addons/NativeAdrenoMetal.bundle/NativeAdrenoMetal", 0755' in header,
                'Owner Metal plugin transport contract changed')
        require(b'NabuGPU: userprobe plugin_stage=' in candidate, 'Final kernel lacks the plugin mount record')
    # The ten-file form: the publish form plus an earlier boot's pipeline pack beside the bundle.
    pack_bound = plugin_bound and b'native_gpu_addon_files != 10' in constants['DATA_BRANCH']
    if pack_bound:
        require(b'const int publish = native_gpu_addon_files >= 9;' in constants['DATA_BRANCH'] and
                b'native_gpu_addon_files != 11' in constants['DATA_BRANCH'] and
                b'"addons/NativeAdrenoMetal.m2vpack", 0644, NABU_GPU_USERPROBE_PLUGIN_PACK_MAX' in header and
                b'#define NABU_GPU_USERPROBE_PLUGIN_PACK_MAX 8388608u' in header and
                b'case 10: expected = NABU_GPU_USERPROBE_SET_PACK;' in header,
                'Owner pipeline-pack transport contract changed')
    # The published forms with the client list (the processes besides backboardd that get a native device).
    clients_bound = pack_bound and b'"addons/NativeAdrenoMetal.clients", 0644, NABU_GPU_USERPROBE_PLUGIN_CLIENTS_MAX' in header
    if clients_bound:
        require(b'#define NABU_GPU_USERPROBE_PLUGIN_CLIENTS_MAX 256u' in header and
                b'case 11: expected = NABU_GPU_USERPROBE_SET_PACK | NABU_GPU_USERPROBE_SET_CLIENTS_BIT;' in header and
                b'(NABU_GPU_USERPROBE_SET_PUBLISH | NABU_GPU_USERPROBE_SET_CLIENTS_BIT)' in header,
                'Owner plugin client-list transport contract changed')
    process_bound = bool(process_constants)
    if process_bound:
        require(set(process_constants) == {'EXEC_HELPER', 'EXEC_LOCAL', 'EXEC_ENTER', 'EXEC_RETURN', 'EXIT_HOOK'} and
                all(data.count(process_constants[key]) == 1 for key in ('EXEC_HELPER', 'EXEC_LOCAL', 'EXEC_ENTER', 'EXEC_RETURN')),
                'Actual XNU source lacks the bounded probe exec observer')
        exit_path = 'outputs/tree/.cache/xnu-work/bsd/kern/kern_exit.c'
        exit_source = read(exit_path)
        require(exit_source.count(process_constants['EXIT_HOOK']) == 1 and
                capture.get('hooks', {}).get('bsd/kern/kern_exit.c') == sha(exit_source),
                'Actual XNU source lacks the bounded probe exit observer')
    if exec_trace_constants:
        require(set(exec_trace_constants) == {'EXEC_TRACE_HELPER', 'EXEC_TRACE_DECL', 'EXEC_TRACE_PAIRS'} and
                data.count(exec_trace_constants['EXEC_TRACE_HELPER'].encode()) == 1 and
                data.count(exec_trace_constants['EXEC_TRACE_DECL'].encode()) == 1 and
                all(data.count(after.encode()) == 1 for _, after in exec_trace_constants['EXEC_TRACE_PAIRS']),
                'Actual XNU source lacks the bounded probe exec-stage observations')
        require(b'NabuGPU: probe_exec_stage=' in candidate,
                'Final kernel lacks the probe exec-stage record format')
    extra_required = {'_native_ram_block_gpu_addon'}
    if process_bound:
        extra_required |= {'_nabu_gpu_userprobe_exit_note', '_nabu_gpu_userprobe_exec_snapshot',
                           '_nabu_log_probe_poll', '_nabu_log_probe_process_snapshot'}
    definitions, _ = candidate_definitions(candidate, METAL_PROFILE, extra_required)
    require(b'NabuGPU: userprobe addon' in candidate and b'nabu-gpu-userprobe-addon' in candidate,
            'Final kernel lacks GPU userprobe boot code')
    from nabu_ui_watch_qualification import qualify as qualify_ui_watch
    ui_watch = qualify_ui_watch(read, candidate)
    return {'mode': 'closed_inline_abi1_probe', 'trigger': 'nabu-gpu-userprobe=1',
            **({'parent_root_creation': True} if parents_fixed else {}),
            **({'owner_job_cache': True, 'addon_files': 4} if cache_entries == 4 else {}),
            **({'turnip_library_transport': True}
               if b'native_gpu_addon_files != 5' in constants['DATA_BRANCH'] else {}),
            **({'metal_plugin_transport': True, 'plugin_addon_files': [8, 9]} if plugin_bound else {}),
            **({'pipeline_pack_transport': True, 'pipeline_pack_addon_files': 10,
                'pipeline_pack_max': 8388608} if pack_bound else {}),
            **({'plugin_clients_transport': True, 'plugin_clients_addon_files': [10, 11],
                'plugin_clients_max': 256} if clients_bound else {}),
            **({'exec_stage_observer': True, 'exec_stage_records_maximum': 32} if exec_trace_constants else {}),
            **({'process_observer': True, 'exit_source_sha256': sha(exit_source),
                'process_symbols': {name: definitions[name] for name in sorted(extra_required)}} if process_bound else {}),
            'ui_watch': ui_watch,
            'header_sha256': sha(header), 'generator_sha256': sha(generator),
            'ram_source_sha256': sha(ram), 'ram_object_sha256': sha(obj),
            'ram_archive_sha256': sha(archive), 'data_source_sha256': sha(data),
            'ram_entry': definitions['_native_ram_block_gpu_addon'],
            'apple_jobs_replaced': False, 'compiled': True, 'runtime_qualified': False,
            'hardware_tested': False, 'rendering_qualified': False}


def accelerator_bindings(read, candidate, report):
    """Bind the generated original-base aliases to this candidate.

    The addresses come from this candidate's own IOGPUFamily extents, so the
    assembly source, the generator's plan and the candidate symbol table are
    checked against each other instead of trusting a recorded address. The plan
    must name this same candidate and this same original kernelcache, and every
    check the generator performed must have passed.
    """
    raw = read(OUTPUT + BINDINGS_REPORT)
    plan = json_object(raw)
    checks = plan.get('checks')
    require(plan.get('status') == 'ok' and plan.get('mode') == 'generate' and
            plan.get('module') == IOGPU_MODULE and plan.get('address_space') == 'candidate',
            'Accelerator bindings report has the wrong scope')
    require(isinstance(checks, dict) and checks and
            all(value == 'passed' for value in checks.values()) and
            plan.get('runtime_qualified') is False and plan.get('images_modified') is False,
            'Accelerator bindings report did not pass every check')
    require(plan.get('kernelcache_sha256') == report.get('kernelcache_sha256'),
            'Accelerator bindings were derived from a different original kernelcache')
    candidate_plan = plan.get('candidate')
    require(isinstance(candidate_plan, dict) and candidate_plan.get('candidate_sha256') == sha(candidate),
            'Accelerator bindings report is not bound to this candidate')
    symbols = plan.get('bindings')
    require(isinstance(symbols, dict) and set(symbols) == set(BINDING_SYMBOLS),
            'Accelerator bindings must define exactly the three original-base symbols')
    for name, address in symbols.items():
        require(isinstance(address, str) and ADDRESS.fullmatch(address),
                'Malformed accelerator binding address: ' + name)
    extents = candidate_plan.get('extents')
    require(isinstance(extents, dict) and extents, 'Accelerator bindings lack candidate extents')
    ranges = []
    for extent in extents.values():
        require(isinstance(extent, dict) and ADDRESS.fullmatch(str(extent.get('candidate_va'))) and
                EXTENT.fullmatch(str(extent.get('size'))) and extent.get('header_matches_report') is True,
                'Malformed accelerator candidate extent')
        low = int(extent['candidate_va'], 16)
        size = int(extent['size'], 16)
        require(size > 0 and low + size <= 1 << 64, 'Invalid accelerator candidate extent bounds')
        ranges.append((low, low + size))
    for name, address in symbols.items():
        value = int(address, 16)
        require(any(low <= value < high for low, high in ranges),
                'Accelerator binding is outside this candidate IOGPUFamily extents: ' + name)
    source = read(OUTPUT + BINDINGS_SOURCE)
    for name, address in sorted(symbols.items()):
        require(('.globl ' + name + '\n.set ' + name + ', ' + address + '\n').encode() in source,
                'Accelerator bindings source does not define ' + name)
    original = plan.get('original')
    require(isinstance(original, dict) and isinstance(original.get('metaclass'), dict) and
            ADDRESS.fullmatch(str(original['metaclass'].get('object'))),
            'Accelerator bindings lack the audited original metaclass object')
    # Pin the audited shape rather than re-deriving it here: a rebuilt accelerator
    # subclass is only ABI-compatible while the original base keeps this layout.
    require(original.get('reported_instance_bytes') == 136 and
            original.get('virtual_entries') == 168 and
            original.get('metadata_overrides') == [0, 1, 7],
            'Audited original IOAcceleratorES ABI shape changed')
    return {'symbols': symbols, 'source': OUTPUT + BINDINGS_SOURCE, 'source_sha256': sha(source),
            'report': OUTPUT + BINDINGS_REPORT, 'report_sha256': sha(raw),
            'original_metaclass': original['metaclass']['object'],
            'original_instance_bytes': original.get('reported_instance_bytes'),
            'original_virtual_entries': original.get('virtual_entries'),
            'original_metadata_overrides': original.get('metadata_overrides'),
            'candidate_extents': {name: extent['candidate_va'] for name, extent in extents.items()},
            'checks': checks, 'runtime_qualified': False}


def qualify_gpu_bundle(read, candidate, source_names, profile=PROFILE):
    """read(relative_name) returns manifest-bound bytes in the collector layout."""
    contract = gpu_contract(profile)
    metal = accelerator_mode(profile)
    required_objects = METAL_REQUIRED_OBJECTS if metal else REQUIRED_OBJECTS
    forbidden_objects = set() if metal else FORBIDDEN_OBJECTS
    raw_report = read(OUTPUT + 'build-report.json')
    report = json_object(raw_report)
    require(all(report.get(key) == contract[key] for key in
                ('profile', 'mode', 'firmware_mode', 'trigger', 'metal_accelerator')) and
            report.get('runtime_qualified') is False and report.get('hardware_tested') is False and
            report.get('requires_pmap_64bit') is True and
            report.get('pmap_sync_64bit_verified') is True,
            'GPU build report has the wrong scope')
    sources = report.get('sources')
    require(isinstance(sources, dict) and 0 < len(sources) <= 1024 and
            set(sources) == set(source_names), 'GPU source inventory mismatch')
    scripts = source_scripts(profile)
    require(set(scripts) <= set(sources), 'GPU source inventory lacks an actual build/bindings script')
    source_bytes = {}
    for name, digest in sources.items():
        require(public_source(name) or name in scripts, 'Unexpected GPU source input')
        require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'Invalid GPU source digest')
        data = read('device/' + name)
        require(sha(data) == digest, 'GPU source hash mismatch: ' + name)
        source_bytes[name] = data
    identity = source_identity(sources)
    require(identity == report.get('source_identity'), 'GPU source identity mismatch')
    generated = read(OUTPUT + 'source/NabuGpuBuild.h')
    require(generated == ('#define NABU_GPU_SOURCE_ID "' + identity + '"\n').encode(),
            'Generated GPU identity header mismatch')
    merged_headers = {}
    for name in sorted(sources):
        path = relative(name)
        if path.suffix != '.h':
            continue
        choices = ['gpu/' + prefix + '/' + path.name for prefix in
                   ('nabu', 'a640', 'upstream/AdrenoPM4', 'upstream/ArmSmmu4K', 'upstream/Adreno6xx')]
        selected = next((choice for choice in choices if choice in sources), None)
        require(selected is not None, 'GPU header outside merged source directories')
        require(read(OUTPUT + 'source/' + path.name) == source_bytes[selected],
                'Merged GPU header differs from selected overlay: ' + path.name)
        merged_headers[path.name] = {'source': selected, 'sha256': sources[selected]}
    commands = json_object(read(OUTPUT + 'compile-command.json'))
    require(set(commands) == required_objects and all(isinstance(command, list) and command
            for command in commands.values()), 'GPU compile command inventory mismatch')
    logging = report.get('logging_headers')
    require(isinstance(logging, dict) and {'ufs/NabuLogCore.h', 'ufs/NabuLogFormat.h'} <= set(logging),
            'GPU checkpoint logging header identities are absent')
    for name, digest in logging.items():
        path = relative(name)
        require(path.parent.as_posix() == 'ufs' and path.name.startswith('NabuLog') and path.suffix == '.h',
                'Unexpected GPU logging header')
        data = read('device/' + name)
        require(sha(data) == digest and read(OUTPUT + 'source/' + path.name) == data,
                'GPU logging header hash mismatch: ' + name)
    archive = read(OUTPUT + 'libNativeAdreno.a')
    require(sha(archive) == report.get('archive_sha256'), 'GPU archive hash mismatch')
    members = archive_members(archive)
    objects = report.get('objects')
    require(isinstance(objects, dict) and set(objects) == required_objects and
            not set(objects) & forbidden_objects, 'GPU object inventory mismatch')
    expected_members = {stem + ('.late.o' if metal and stem in LATE_OBJECTS else '.o') for stem in objects}
    if metal:
        expected_members.add(BINDINGS_OBJECT)
    require(set(members) == expected_members, 'GPU archive object inventory mismatch')
    objects_verified = {}
    for stem, metadata in objects.items():
        late = metal and stem in LATE_OBJECTS
        require(isinstance(metadata, dict) and
                metadata.get('object') == stem + ('.late.o' if late else '.o'),
                'Invalid GPU object record')
        if late:
            require(metadata.get('kind') == 'late' and metadata.get('init_section_removed') is True and
                    metadata.get('text_sha256') == metadata.get('late_text_sha256'),
                    'Deferred GPU object did not preserve its text and drop its initializer: ' + stem)
        else:
            require(metadata.get('kind') is None and metadata.get('late_text_sha256') is None,
                    'Unexpected GPU object mode: ' + stem)
        path = relative(metadata.get('source'))
        require(path.parent.as_posix() == 'source' and path.stem == stem and path.suffix in ('.c', '.cpp'),
                'Invalid merged GPU source path')
        choices = [prefix + path.name for prefix in ('gpu/nabu/', 'gpu/a640/',
                   'gpu/upstream/AdrenoPM4/', 'gpu/upstream/ArmSmmu4K/', 'gpu/upstream/Adreno6xx/')]
        selected = next((name for name in choices if name in sources), None)
        require(selected is not None, 'GPU object source is not inventoried: ' + stem)
        merged = read(OUTPUT + path.as_posix())
        require(merged == source_bytes[selected] and sha(merged) == metadata.get('source_sha256'),
                'Merged GPU source differs from selected overlay: ' + stem)
        obj = read(OUTPUT + metadata['object'])
        require(len(obj) >= 16 and struct.unpack_from('<4I', obj) == (0xfeedfacf, 0x100000c, 0, 1),
                'GPU object is not ARM64 Mach-O: ' + stem)
        require(sha(obj) == metadata.get('sha256') and obj == members[metadata['object']],
                'GPU object/archive identity mismatch: ' + stem)
        if stem == 'NabuGpuResources':
            require(identity.encode() + b'\0' in obj, 'GPU resource object lacks its source identity banner')
        objects_verified[stem] = {'object': metadata['object'], 'sha256': sha(obj),
                                  'source': selected, 'source_sha256': sha(merged),
                                  'kind': 'late' if late else 'direct'}
    if metal:
        binding_object = read(OUTPUT + BINDINGS_OBJECT)
        binding_record = report.get('bindings')
        require(isinstance(binding_record, dict) and
                binding_record.get('object') == BINDINGS_OBJECT and
                sha(binding_object) == binding_record.get('object_sha256') and
                binding_object == members[BINDINGS_OBJECT] and
                len(binding_object) >= 16 and
                struct.unpack_from('<4I', binding_object) == (0xfeedfacf, 0x100000c, 0, 1),
                'GPU bindings object/archive identity mismatch')
    require(identity.encode() + b'\0' in candidate, 'Final GPU candidate lacks its source identity banner')
    pmap = read(PMAP_SOURCE)
    require(sha(pmap) == report.get('pmap_source_sha256'), 'GPU pmap source hash mismatch')
    function = re.search(rb'pmap_sync_page_attributes_phys\s*\(\s*ppnum_t\s+pp\s*\)\s*\{([^}]+)\}', pmap)
    require(function is not None, 'GPU pmap cache-attribute function is absent')
    body = re.sub(rb'/\*.*?\*/|//[^\n]*', b'', function[1], flags=re.S)
    require(re.search(rb'flush_dcache\s*\(\s*\(vm_offset_t\)\s*ptoa\(pp\)\s*,\s*PAGE_SIZE\s*,\s*TRUE\s*\)', body),
            'GPU pmap cache-attribute source does not preserve 64-bit physical addresses')
    definitions, bound = candidate_definitions(candidate, profile)
    result = {**contract, 'hardware_tested': False, 'candidate_sha256': sha(candidate),
              'source_identity': identity, 'source_count': len(sources),
              'archive': OUTPUT + 'libNativeAdreno.a', 'archive_sha256': sha(archive),
              'build_report': OUTPUT + 'build-report.json', 'build_report_sha256': sha(raw_report),
              'generated_header_sha256': sha(generated),
              'compile_commands_sha256': sha(read(OUTPUT + 'compile-command.json')), 'sources': sources,
              'objects': objects_verified, 'merged_headers': merged_headers, 'logging_headers': logging,
              'pmap_source': PMAP_SOURCE, 'pmap_source_sha256': sha(pmap),
              'pmap_sync_64bit_verified': True, 'final_definitions': definitions}
    if metal:
        bindings = accelerator_bindings(read, candidate, report)
        require(bindings['symbols'] == bound,
                'Accelerator original-base bindings do not match the candidate symbol table')
        result['bindings'] = bindings
        result['final_bindings'] = bound
        if report.get('gpu_userprobe_boot_support') is True:
            result['userprobe_boot'] = qualify_userprobe_boot(read, candidate)
    else:
        require(not report.get('gpu_userprobe_boot_support'),
                'Diagnostic GPU profile contains userprobe boot support')
    return result


def qualify_gpu_candidate(upstream, device, candidate, expected_profile=PROFILE):
    require(expected_profile in GPU_PROFILES, 'GPU qualification requires its explicit profile')
    roots = {'device': device, 'outputs': upstream / 'out/nabu'}

    def read(name):
        path = relative(name)
        root = roots.get(path.parts[0])
        require(root is not None, 'Unknown GPU evidence root')
        target = root.joinpath(*path.parts[1:])
        require(target.is_file() and target.resolve().is_relative_to(root.resolve()) and
                not any(p.is_symlink() for p in (target, *target.parents)), 'Missing or linked GPU evidence: ' + name)
        return target.read_bytes()

    names = [p.relative_to(device).as_posix() for p in sorted((device / 'gpu').rglob('*'))
             if p.is_file() and public_source(p.relative_to(device).as_posix())]
    names.extend(source_scripts(expected_profile))
    return qualify_gpu_bundle(read, candidate.read_bytes(), names, expected_profile)
