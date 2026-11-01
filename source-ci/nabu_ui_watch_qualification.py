"""Qualify the separately enabled UI observer from real private build inputs."""
import ast
import hashlib
import struct


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def object_symbols(data):
    require(len(data) >= 32 and struct.unpack_from('<4I', data) == (0xfeedfacf, 0x100000c, 0, 1),
            'UI observer object must be ordinary ARM64 Mach-O')
    count, extent = struct.unpack_from('<II', data, 16)
    require(0 < count <= 65536 and extent <= len(data) - 32, 'UI object command bounds')
    at, table, sections = 32, None, []
    for _ in range(count):
        require(at + 8 <= 32 + extent, 'UI object command header bounds')
        command, size = struct.unpack_from('<II', data, at)
        require(size >= 8 and at + size <= 32 + extent, 'UI object load command bounds')
        if command == 0x19:
            require(size >= 72, 'UI object segment bounds')
            number = struct.unpack_from('<I', data, at + 64)[0]
            require(72 + number * 80 <= size, 'UI object section bounds')
            for i in range(number):
                pos = at + 72 + i * 80
                va, length, offset = struct.unpack_from('<QQI', data, pos + 32)
                flags = struct.unpack_from('<I', data, pos + 64)[0]
                sections.append((va, length, offset, flags))
        elif command == 2:
            require(size >= 24 and table is None, 'UI object symbol table bounds')
            table = struct.unpack_from('<4I', data, at + 8)
        at += size
    require(at == 32 + extent and table is not None, 'UI object lacks symbols')
    offset, number, strings, length = table
    require(offset + number * 16 <= len(data) and strings + length <= len(data),
            'UI object symbol extent')
    found = {}
    for i in range(number):
        name, kind, section, _, address = struct.unpack_from('<IBBHQ', data, offset + i * 16)
        if kind & 0xe0 or kind & 0xe != 0xe:
            continue
        require(name < length and 0 < section <= len(sections), 'UI object definition bounds')
        end = data.find(b'\0', strings + name, strings + length)
        require(end >= 0, 'UI object unterminated symbol')
        name = data[strings + name:end].decode()
        if not name.startswith('_nabu_ui_watch_'):
            continue
        va, backed, fileoff, flags = sections[section - 1]
        if not flags & 0x80000000:
            continue  # Private state symbols are not emitted function definitions.
        require(va <= address < va + backed and fileoff + backed <= len(data),
                'UI observer unbacked code')
        require(name not in found, 'UI observer entry must be unique instructions')
        pos = fileoff + address - va
        require(any(data[pos:min(pos + 16, fileoff + backed)]),
                'UI observer entry has no emitted code')
        found[name] = address
    return found


def qualify(read, candidate):
    from nabu_gpu_ci import candidate_definitions, json_object, METAL_PROFILE
    capture = json_object(read('outputs/tree/build/nabu-log/source-report.json'))
    exec_path = 'outputs/tree/.cache/xnu-work/bsd/kern/kern_exec.c'
    exit_path = 'outputs/tree/.cache/xnu-work/bsd/kern/kern_exit.c'
    thread_path = 'outputs/tree/.cache/xnu-work/osfmk/kern/thread.c'
    exec_source, exit_source = read(exec_path), read(exit_path)
    enabled = capture.get('ui_watch', False)
    require(type(enabled) is bool, 'UI watch build flag must be Boolean')
    if not enabled:
        try:
            thread_source = read(thread_path)
        except KeyError:
            # Evidence from a build that predates the osfmk sampler has no such hook.
            thread_source = b''
        require(b'NABU_UI_WATCH' not in exec_source and b'NABU_UI_WATCH' not in exit_source and
                b'NABU_UI_WATCH' not in thread_source and
                b'nabu-ui-watch' not in candidate and b'_nabu_ui_watch_' not in candidate,
                'Disabled kernel retains UI observer definitions or dependencies')
        return {'compiled': False, 'runtime_qualified': False}
    thread_source = read(thread_path)
    require(capture.get('gpu_userprobe_boot') is True, 'UI observer needs the original callback')
    generator = read('device/scripts/nabu_ui_watch_source.py')
    require(capture.get('ui_watch_generator_sha256') == sha(generator),
            'UI generator identity mismatch')
    constants = {}
    for item in ast.parse(generator.decode('utf-8')).body:
        if isinstance(item, ast.Assign) and len(item.targets) == 1 and isinstance(item.targets[0], ast.Name):
            if item.targets[0].id in ('CONTRACT', 'EXEC_HELPER', 'EXEC_PAIRS', 'EXIT_PAIRS',
                                      'THREAD_HELPER', 'THREAD_PAIRS'):
                constants[item.targets[0].id] = ast.literal_eval(item.value)
    require(set(constants) == {'CONTRACT', 'EXEC_HELPER', 'EXEC_PAIRS', 'EXIT_PAIRS',
                               'THREAD_HELPER', 'THREAD_PAIRS'}, 'UI source contract incomplete')
    contract = constants['CONTRACT']
    require(contract.get('max_samples') == 64 and contract.get('interval_us') == 10000000 and
            contract.get('max_threads') == 3 and contract.get('targets') ==
            ['SpringBoard', 'backboardd', 'runningboardd'], 'UI scope or budget changed')
    version = contract.get('version', 1)
    require(type(version) is int and version in (1, 2), 'Unknown UI observer contract version')
    if version == 2:
        require(contract.get('target_association') == 'activation-call-output' and
                contract.get('max_exec_contexts') == 0 and
                '_nabu_ui_watch_activate_image_v2' in contract.get('symbols', []) and
                b'nabu_ui_context' not in exec_source,
                'UI v2 requires direct activation target association without a context table')
    require(exec_source.count(constants['EXEC_HELPER'].encode()) == 1 and
            all(exec_source.count(after.encode()) == 1 for _, after in constants['EXEC_PAIRS']) and
            all(exit_source.count(after.encode()) == 1 for _, after in constants['EXIT_PAIRS']) and
            thread_source.count(constants['THREAD_HELPER'].encode()) == 1 and
            all(thread_source.count(after.encode()) == 1 for _, after in constants['THREAD_PAIRS']),
            'Actual XNU sources lack the exact UI hooks')
    require(capture.get('hooks', {}).get('bsd/kern/kern_exec.c') == sha(exec_source) and
            capture.get('hooks', {}).get('bsd/kern/kern_exit.c') == sha(exit_source) and
            capture.get('hooks', {}).get('osfmk/kern/thread.c') == sha(thread_source),
            'UI XNU sources differ from the capture report')
    symbols = contract.get('symbols')
    require(isinstance(symbols, list) and symbols and len(set(symbols)) == len(symbols) and
            all(name.startswith('_nabu_ui_watch_') for name in symbols),
            'UI exported symbol contract malformed')
    mapping = contract.get('symbols_by_object')
    require(isinstance(mapping, dict) and set(mapping) == {'kern_exec.c', 'thread.c'} and
            sorted(sum(mapping.values(), [])) == sorted(symbols), 'UI per-object symbol map malformed')
    objects = {}
    for name, wanted in mapping.items():
        relative = ('osfmk/DEVELOPMENT/thread.o' if name == 'thread.c'
                    else 'bsd/DEVELOPMENT/kern_exec.o')
        object_path = ('outputs/tree/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/' + relative)
        obj = read(object_path)
        actual = object_symbols(obj)
        require(set(wanted) <= set(actual), 'Actual XNU object lacks UI emitted entries: ' + name)
        objects[name] = {'path': object_path, 'sha256': sha(obj),
                         'definitions': {symbol: actual[symbol] for symbol in wanted}}
    final, _ = candidate_definitions(candidate, METAL_PROFILE, symbols)
    return {'compiled': True, 'trigger': 'nabu-ui-watch=1', 'contract': contract,
            **({'target_association': contract['target_association']} if version == 2 else {}),
            'generator_sha256': sha(generator), 'exec_source_sha256': sha(exec_source),
            'exit_source_sha256': sha(exit_source), 'thread_source_sha256': sha(thread_source),
            'objects': objects,
            'final_definitions': {name: final[name] for name in symbols},
            'first_incarnation_only': True, 'runtime_qualified': False, 'hardware_tested': False}
