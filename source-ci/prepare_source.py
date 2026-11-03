#!/usr/bin/env python3
"""Apply the narrow G0 fix to an exact upstream checkout before tree assembly."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib
from nabu_graphics_startup import LEGACY_PATCH, retime_graphics_patches
from nabu_data_skeleton import prepare_data_skeleton
from nabu_logging_build import enable_logging
from nabu_cs_stream import prepare_signature_scan
from nabu_display_ci import (PROFILE as QEMU_LEGACY_PROFILE, CPU_PROFILE as QEMU_CPU_PRESENT_PROFILE,
                             HARDWARE_CPU_PROFILE as UFS_CPU_PRESENT_PROFILE,
                             HARDWARE_GPU_PROFILE as UFS_GPU_PROFILE,
                             HARDWARE_GPU_METAL_PROFILE as UFS_GPU_METAL_PROFILE,
                             DISPLAY_PROFILES, REFERENCE as DISPLAY_REFERENCE)

UPSTREAM = '245aca1a9ec5b730b1cad80fade295800d2981f1'
PATCH = 'patches/xnu/offline-component-load-probes.patch'
PATCH_SHA256 = '1f228c5c6d8387b13cd8e0964ddeb56c858a5dae16478f3ed2baae8a2e4da1e9'
INPUT_SHA256 = 'bfa03a528848fbfdbea96f0018eb0d68c94c1a9370cad9930006fbabb3bb599f'
CPU_UI_PROFILE = 'nabu_ufs_cpu_ui_defconfig'
QEMU_DATA_PROFILE = 'nabu_qemu_data_defconfig'
QEMU_CPU_UI_PROFILE = 'nabu_qemu_cpu_ui_defconfig'
PROFILES = ('nabu_bootstrap_defconfig', 'nabu_qemu_storage_defconfig', 'nabu_qemu_root_defconfig',
            QEMU_DATA_PROFILE, QEMU_CPU_UI_PROFILE, QEMU_LEGACY_PROFILE, QEMU_CPU_PRESENT_PROFILE,
            'nabu_ufs_passive_defconfig', 'nabu_ufs_readonly_defconfig',
            'nabu_ufs_root_defconfig', 'nabu_ufs_data_defconfig', CPU_UI_PROFILE, UFS_CPU_PRESENT_PROFILE,
            UFS_GPU_PROFILE, UFS_GPU_METAL_PROFILE)
OWNER_PROFILES = ('nabu_qemu_root_defconfig', 'nabu_ufs_root_defconfig',
                  'nabu_ufs_data_defconfig', CPU_UI_PROFILE, QEMU_DATA_PROFILE,
                  QEMU_CPU_UI_PROFILE, QEMU_LEGACY_PROFILE, QEMU_CPU_PRESENT_PROFILE,
                  UFS_CPU_PRESENT_PROFILE, UFS_GPU_PROFILE, UFS_GPU_METAL_PROFILE)
UFS_OWNER_PROFILES = ('nabu_ufs_root_defconfig', 'nabu_ufs_data_defconfig', CPU_UI_PROFILE,
                      UFS_CPU_PRESENT_PROFILE, UFS_GPU_PROFILE, UFS_GPU_METAL_PROFILE)
UFS_PROFILES = ('nabu_ufs_passive_defconfig', 'nabu_ufs_readonly_defconfig',
                'nabu_ufs_root_defconfig')
OWNER_POLICY = {'release': 'nabu-owner-os-21h16-v1', 'asset': 'os-policy.tar.gz',
                'sha256': '67dde04f5bdc5b2bba1929b046565a460b5f189c5d19a47e6b3ac857039a81e1'}
SYSTEMOS_POLICY = {'release': 'nabu-owner-systemos-21h16-v1', 'asset': 'systemos-policy.tar.gz',
                   'sha256': '04caae89b7b8f5d1b2c5c5ab195f531769083d5fd6266001bf867530d6994a18'}
ROOT_VOLUME_UUID = 'F577F6BD-3BB9-4864-BBDF-972FC2E94AE3'
CACHE_VOLUME_UUID = 'C374ACD3-75FE-4FAD-B02E-FC3C9A86DA11'
# Original j171ap/21H16 security initializer, before the declared prelink slide.
AMFI_INIT = 'com.apple.driver.AppleMobileFileIntegrity=0xfffffff005b70ae0'
ROOT_COMPONENTS = ['com.apple.filesystems.apfs',
                   'com.apple.AppleFSCompression.AppleFSCompressionTypeZlib',
                   'com.apple.driver.AppleMobileFileIntegrity',
                   'com.apple.security.sandbox']
# The CPU UI profile stages the original display family and IOSurface as
# prelink roots.  The first milestone keeps NATIVE_LEGACY_DISPLAY disabled so
# the closure and the pass-1 reference candidate can be audited before any
# display archive is linked.
GRAPHICS_ROOTS = ['com.apple.iokit.IOSurface',
                  'com.apple.iokit.IOMobileGraphicsFamily']
CPU_UI_ROOTS = ROOT_COMPONENTS + GRAPHICS_ROOTS
# The hardware CPU profile also publishes the NT36523 touch digitizer. On 21H16
# the generic digitizer IOHIDEventDriver personality is only in the codeless
# IOHIDEventDriverSafeBoot bundle; AppleMultitouchDriver stays out.
HID_ROOTS = ['com.apple.iokit.IOHIDFamily',
             'com.apple.iokit.IOHIDEventDriverSafeBoot']
UFS_CPU_PRESENT_ROOTS = CPU_UI_ROOTS + HID_ROOTS
# The Metal profile also prelinks the original IOGPUFamily, which supplies
# the IOAcceleratorES base class the published accelerator subclasses. The
# diagnostic profile keeps the closure it was already qualified against.
UFS_GPU_METAL_ROOTS = UFS_CPU_PRESENT_ROOTS + ['com.apple.iokit.IOGPUFamily']
# Opt-in native text console magnification (boot arg nabu-vc-scale=1..4).
# The patch is inert without the argument, so no profile gains a dependency.
VC_TEXT_SCALE = {'name': 'nabu-vc-text-scale.patch',
                 'argument': 'nabu-vc-scale', 'default': 1, 'maximum': 4,
                 'sha256': '8d3bc4d998c7e6e8eccd12c87e7425d6a08fbcf0e5b4a39acc2704e4ceb98799'}
# The pinned upstream 245aca1a predates the additional union lookup patches.
# Both files are byte-identical to the corresponding UniXNU patches and are
# only materialized for profiles that enable owner union composition.
UNION_LOWER_DIRECTORY = {'name': 'nabu-union-lower-directory.patch',
                         'target': 'patches/xnu/native-union-lower-directory.patch',
                         'sha256': 'b39e077b190134caae1842d07758795bf15b408eb637701a41b603825e5d563b'}
UNION_GETATTRLISTBULK = {'name': 'nabu-union-getattrlistbulk.patch',
                         'target': 'patches/xnu/native-union-getattrlistbulk.patch',
                         'sha256': 'f5d665fd7250717cfacced8408a0b94f282eb2764e514f61a378f7d085c7a03b'}
UNION_PATCHES = (UNION_LOWER_DIRECTORY, UNION_GETATTRLISTBULK)
# Metal profile only, inert without boot-arg t733-managed-rt-normal=1: managed-DRAM RT (IOSurface) pages map as
# Normal NC instead of Device-nGnRnE (this BCM2837 config lacks HAS_UCNORMAL_MEM), as UniXNU SM-T733's
# native-t733-managed-rt-memory.patch does. The A640 driver reads the same argument to accept RT imports.
MANAGED_RT_NORMAL = {'name': 'nabu-managed-rt-normal.patch',
                     'target': 'patches/xnu/nabu-managed-rt-normal.patch',
                     'argument': 't733-managed-rt-normal',
                     'sha256': '743064d5e0aebd0265c059758199cd35245f67f9b9c2357276dc6c0f4f2637e4'}

SECOND_STATIC_TRUST_CACHE_PATCH = '''--- a/config/MASTER.arm64
+++ b/config/MASTER.arm64
@@ -72,7 +72,7 @@
 #  VM_DEV =         [ VM_BASE dynamic_codesigning pgzalloc]
 #  VM_DEBUG =       [ VM_BASE dynamic_codesigning pgzalloc]
 #  VM_KASAN =       [ VM_BASE dynamic_codesigning kernel_tagging kernel_tbi config_kasan config_ubsan config_kcov config_ksancov ]
-#  SECURITY_BASE =    [ config_macf kernel_integrity config_secure_bsd_root ]
+#  SECURITY_BASE =    [ config_macf kernel_integrity config_secure_bsd_root second_static_trust_cache ]
 #  SECURITY_RELEASE = [ SECURITY_BASE ]
 #  SECURITY_DEV =     [ SECURITY_BASE config_setuid config_kas_info ]
 #  SECURITY_DEBUG =   [ SECURITY_BASE config_setuid config_kas_info ]
'''

# Native console only: no BootProgress archives or system policy changes.
NABU_TEXT_PATCH = (
    '--- a/pexpert/arm/pe_init.c\n'
    '+++ b/pexpert/arm/pe_init.c\n'
    '@@ -525,7 +525,9 @@\n'
    ' \t */\n'
    ' \tcheck_for_panic_log();\n'
    ' \n'
    '-\tif (PE_state.video.v_display) {\n'
    '+\tint nabu_source_text = 0;\n'
    '+\tPE_parse_boot_argn("nabu-source-text", &nabu_source_text, sizeof(nabu_source_text));\n'
    '+\tif (PE_state.video.v_display && !nabu_source_text) {\n'
    ' \t\tPE_initialize_console(&PE_state.video, kPEGraphicsMode);\n'
    ' \t} else {\n'
    ' \t\tPE_initialize_console(&PE_state.video, kPETextMode);\n'
    '--- a/iokit/bsddev/IOKitBSDInit.cpp\n'
    '+++ b/iokit/bsddev/IOKitBSDInit.cpp\n'
    '@@ -43,6 +43,11 @@\n'
    ' #include <vm/pmap.h>\n'
    ' #include <vm/vm_map.h>\n'
    ' #include <pexpert/pexpert.h>\n'
    '+\n'
    '+extern "C" {\n'
    '+extern volatile uint32_t armdt_platform_configured, armcpu_gic_ready;\n'
    '+extern volatile uint64_t armcpu_timer_interrupts;\n'
    '+}\n'
    ' #include <kern/clock.h>\n'
    ' #if CONFIG_KDP_INTERACTIVE_DEBUGGING\n'
    ' #include <kern/debug.h>\n'
    '@@ -690,6 +695,15 @@\n'
    ' \tstatic int          mountAttempts = 0;\n'
    ' \n'
    ' \tint xchar, dchar;\n'
    '+\tint nabu_source_text = 0;\n'
    '+\tPE_parse_boot_argn("nabu-source-text", &nabu_source_text, sizeof(nabu_source_text));\n'
    '+\tif (nabu_source_text) {\n'
    '+\t\tPE_initialize_console(NULL, kPETextScreen);\n'
    '+\t\tPE_initialize_console(NULL, kPEEnableScreen);\n'
    '+\t\tIOLog("NABU SOURCE V2 ROOT_SEARCH platform=%u gic=%u timer=%llu\\n",\n'
    '+\t\t    armdt_platform_configured, armcpu_gic_ready,\n'
    '+\t\t    (unsigned long long)armcpu_timer_interrupts);\n'
    '+\t}\n'
    ' \n'
    ' \t// stall here for anyone matching on the IOBSD resource to finish (filesystems)\n'
    ' \tmatching = IOService::serviceMatching(gIOResourcesKey);\n'
    '@@ -897,6 +911,10 @@\n'
    ' #if !XNU_TARGET_OS_OSX || !defined(__arm64__)\n'
    ' \t\t\tPE_display_icon( 0, "noroot");\n'
    ' \t\t\tIOLog( "Still waiting for root device\\n" );\n'
    '+\t\t\tif (nabu_source_text) {\n'
    '+\t\t\t\tIOLog("NABU SOURCE V2 ROOT_WAIT timer=%llu\\n",\n'
    '+\t\t\t\t    (unsigned long long)armcpu_timer_interrupts);\n'
    '+\t\t\t}\n'
    ' #endif\n'
    ' \n'
    ' \t\t\tif (!debugInfoPrintedOnce) {\n'
)


def owner_ufs_archives(data=False):
    """Archive producers shared by the hardware UFS owner profiles."""
    archives = ['build-nabu-owner-root.py', 'build-nabu-virtio.py',
                'build-nabu-ufs-root.py']
    if data:
        archives.append('build-nabu-ram-block.py')
    return archives


def _select_owner_ufs_board(device, profile, roots, data, archives=None):
    """Rewrite the bootstrap board for a UFS owner profile."""
    path = device / 'board.toml'
    text = path.read_text(encoding='utf-8')
    old = 'defconfig = "nabu_bootstrap_defconfig"'
    archive = '  "build-libpthread-kernel.py",'
    root_line = 'roots = ["com.apple.filesystems.apfs"]'
    if any(text.count(marker) != 1 for marker in (old, archive, root_line)):
        raise ValueError('Expected unmodified bootstrap board for UFS owner selection')
    builders = ''.join(f'\n  "{name}",' for name in
                       (owner_ufs_archives(data) if archives is None else archives))
    text = text.replace(old, f'defconfig = "{profile}"', 1)
    text = text.replace(archive, archive + builders, 1)
    text = text.replace(root_line,
                        f'roots = {json.dumps(roots)}\n'
                        f'early_security_init = "{AMFI_INIT}"', 1)
    path.write_text(text, encoding='utf-8')


def _apply_owner_ufs_build(upstream, data=False, nabu_pmgr=False):
    """Apply the pinned hardware-owner build gates to the upstream tree."""
    build = upstream / 'scripts/build-xnu-4k-baseline.sh'
    text = build.read_text(encoding='utf-8')
    replacements = [
        ('if [ "${XNU_NATIVE_AES:-0}" != 1 ]; then\n'
         "    echo 'NativeVirtioBlock currently requires the qualified NativeAES/original-storage prelink baseline' >&2",
         'if [ "$CRYPTO_BOOTSTRAP_MODE" != prelinked ] || [ "${XNU_SOURCE_CORECRYPTO14:-0}" != 1 ]; then\n'
         "    echo 'NativeVirtioBlock requires the original crypto/storage prelink closure' >&2"),
        ('if [ "$OWNER_ROOT_AUDIT" = 1 ] && [ "$OWNER_ROOT_PROBE" != 1 ]; then',
         'if [ "$OWNER_ROOT_AUDIT" = 1 ] && [ "${XNU_NATIVE_VIRTIO_BLOCK:-0}" != 1 ]; then'),
        ('if [ "$OWNER_ROOT_PROBE" = 1 ] && {',
         'if { [ "$OWNER_ROOT_PROBE" = 1 ] || [ "${XNU_OWNER_ROOT_AUDIT:-0}" = 1 ]; } && {'),
        ('  if [ "$OWNER_ROOT_PROBE" = 1 ]; then\n    VERIFIED_ROOT_ARCHIVE=',
         '  if [ "$OWNER_ROOT_PROBE" = 1 ] || [ "$OWNER_ROOT_AUDIT" = 1 ]; then\n    VERIFIED_ROOT_ARCHIVE='),
        ('  "$OWNER_ROOT_PROBE" "${XNU_VERIFIED_ROOT_ARCHIVE:',
         '  "$((OWNER_ROOT_PROBE | OWNER_ROOT_AUDIT))" "${XNU_VERIFIED_ROOT_ARCHIVE:'),
    ]
    if data:
        # NativeRamBlock only uses libkern SHA-256; this board has the original
        # prelinked crypto closure, not the optional NativeAES diagnostic.
        replacements.append((
            'if [ "${XNU_NATIVE_AES:-0}" != 1 ]; then\n'
            "    echo 'NativeRamBlock requires the qualified original storage/AES prelink closure' >&2",
            'if [ "$CRYPTO_BOOTSTRAP_MODE" != prelinked ] || [ "${XNU_SOURCE_CORECRYPTO14:-0}" != 1 ]; then\n'
            "    echo 'NativeRamBlock requires the original crypto/storage prelink closure' >&2"))
    for old, new in replacements:
        if text.count(old) != 1:
            raise ValueError(f'Expected one pinned build anchor: {old.splitlines()[0]}')
        text = text.replace(old, new, 1)
    build.write_text(text, encoding='utf-8')
    # Decode the original PMGR kext for the hardware boot-session provider and
    # expose the selected kernelcache to archive builders.
    kernel = upstream / 'scripts/unixnu/kernel.py'
    text = kernel.read_text(encoding='utf-8')
    anchor = '    build_archives(ctx, env)\n'
    if text.count(anchor) != 1:
        raise ValueError('Expected one build_archives anchor in kernel.py')
    env = "    env['UNIXNU_KERNELCACHE'] = str(ipsw.kernelcache(ctx, ipsw.Ipsw(ctx)))\n"
    if nabu_pmgr:
        env += "    env['NABU_BOOT_PMGR'] = '1'\n"
    kernel.write_text(text.replace(anchor, env + anchor, 1), encoding='utf-8')


def select_qemu_data_profile(device, upstream):
    """Use the same owner/Data contracts with virtual storage and boot PMGR."""
    _select_owner_ufs_board(device, QEMU_DATA_PROFILE, ROOT_COMPONENTS, data=True,
                            archives=['build-nabu-owner-root.py', 'build-nabu-virtio.py',
                                      'build-nabu-ram-block.py'])
    # No UFS producer or NABU_BOOT_PMGR: ArmDTPlatform selects QemuBootPMGR.
    _apply_owner_ufs_build(upstream, data=True, nabu_pmgr=False)


def select_qemu_cpu_ui_profile(device, upstream):
    """Build the QEMU graphics-closure reference without a display backend."""
    _select_owner_ufs_board(device, QEMU_CPU_UI_PROFILE, CPU_UI_ROOTS, data=True,
                            archives=['build-nabu-owner-root.py', 'build-nabu-virtio.py',
                                      'build-nabu-ram-block.py'])
    _apply_owner_ufs_build(upstream, data=True, nabu_pmgr=False)


def select_qemu_legacy_profile(device, upstream, cpu_present=False):
    """Add the disabled-scanout Legacy discovery backend to the QEMU baseline."""
    _select_owner_ufs_board(device, QEMU_CPU_PRESENT_PROFILE if cpu_present else QEMU_LEGACY_PROFILE, CPU_UI_ROOTS, data=True,
                            archives=['build-nabu-owner-root.py', 'build-nabu-virtio.py',
                                      'build-nabu-ram-block.py', 'build-nabu-legacy-display.py'])
    _apply_owner_ufs_build(upstream, data=True, nabu_pmgr=False)
    select_legacy_build_mode(upstream, cpu_present)


def select_legacy_build_mode(upstream, cpu_present):
    kernel = upstream / 'scripts/unixnu/kernel.py'
    text = kernel.read_text(encoding='utf-8')
    anchor = '    build_archives(ctx, env)\n'
    if text.count(anchor) != 1:
        raise ValueError('Expected one archive build entry')
    flag = "NABU_LEGACY_CPU_PRESENT" if cpu_present else "NABU_LEGACY_DISCOVERY_ONLY"
    kernel.write_text(text.replace(anchor, f"    env['{flag}'] = '1'\n" + anchor), encoding='utf-8')


def select_ufs_cpu_present_profile(device, upstream):
    """Keep the hardware owner/Data closure and add the qualified CPU backend."""
    _select_owner_ufs_board(device, UFS_CPU_PRESENT_PROFILE, UFS_CPU_PRESENT_ROOTS, data=True,
                            archives=owner_ufs_archives(data=True) + ['build-nabu-legacy-display.py'])
    _apply_owner_ufs_build(upstream, data=True, nabu_pmgr=True)
    select_legacy_build_mode(upstream, cpu_present=True)
    select_touch_build(upstream)


def select_ufs_gpu_profile(device, upstream):
    """Add the gated A640 diagnostic archive while retaining CPU presentation."""
    _select_owner_ufs_board(device, UFS_GPU_PROFILE, UFS_CPU_PRESENT_ROOTS, data=True,
                            archives=owner_ufs_archives(data=True) +
                            ['build-nabu-legacy-display.py', 'build-nabu-adreno.py'])
    _apply_owner_ufs_build(upstream, data=True, nabu_pmgr=True)
    select_legacy_build_mode(upstream, cpu_present=True)
    select_touch_build(upstream)


def select_ufs_gpu_metal_profile(device, upstream):
    """Publish the A640 accelerator from the qualified CPU presentation.

    The closure adds the original IOGPUFamily so the accelerator binds the real
    IOAcceleratorES base class, and the archive producer is told to compile and
    stage the publication objects with their original-base bindings.
    """
    _select_owner_ufs_board(device, UFS_GPU_METAL_PROFILE, UFS_GPU_METAL_ROOTS, data=True,
                            archives=owner_ufs_archives(data=True) +
                            ['build-nabu-legacy-display.py', 'build-nabu-adreno.py'])
    _apply_owner_ufs_build(upstream, data=True, nabu_pmgr=True)
    select_legacy_build_mode(upstream, cpu_present=True)
    select_touch_build(upstream)
    select_gpu_metal_build(upstream)


def select_gpu_metal_build(upstream):
    kernel = upstream / 'scripts/unixnu/kernel.py'
    text = kernel.read_text(encoding='utf-8')
    anchor = '    build_archives(ctx, env)\n'
    if text.count(anchor) != 1:
        raise ValueError('Expected one archive build entry')
    kernel.write_text(text.replace(anchor, "    env['NABU_GPU_METAL'] = '1'\n" + anchor, 1),
                      encoding='utf-8')


def select_touch_build(upstream):
    kernel = upstream / 'scripts/unixnu/kernel.py'
    text = kernel.read_text(encoding='utf-8')
    anchor = '    build_archives(ctx, env)\n'
    if text.count(anchor) != 1:
        raise ValueError('Expected one archive build entry')
    kernel.write_text(text.replace(anchor, "    env['NABU_TOUCH'] = '1'\n" + anchor), encoding='utf-8')


def select_storage_profile(device, upstream, owner_root=False, data=False):
    if data:
        # The Data profile boots on hardware; it needs the original ApplePMGR
        # backend, the same as the UFS root/CPU-UI profiles. QemuBootPMGR is
        # only for the QEMU storage/root profiles below.
        _select_owner_ufs_board(device, 'nabu_ufs_data_defconfig',
                                ROOT_COMPONENTS, data=True)
        _apply_owner_ufs_build(upstream, data=True, nabu_pmgr=True)
        return
    path = device / 'board.toml'
    text = path.read_text(encoding='utf-8')
    profile = 'nabu_qemu_root_defconfig' if owner_root else 'nabu_qemu_storage_defconfig'
    old = 'defconfig = "nabu_bootstrap_defconfig"'
    archive = '  "build-libpthread-kernel.py",'
    root_line = 'roots = ["com.apple.filesystems.apfs"]'
    if any(text.count(marker) != 1 for marker in (old, archive, root_line)):
        raise ValueError('Expected unmodified bootstrap board for storage selection')
    builders = (['build-nabu-owner-root.py'] if owner_root else []) + ['build-nabu-virtio.py']
    text = text.replace(old, f'defconfig = "{profile}"', 1)
    text = text.replace(archive,
                        archive + ''.join(f'\n  "{name}",' for name in builders), 1)
    if owner_root:
        text = text.replace(root_line,
                            f'roots = {json.dumps(ROOT_COMPONENTS)}\n'
                            f'early_security_init = "{AMFI_INIT}"', 1)
    path.write_text(text, encoding='utf-8')
    build = upstream / 'scripts/build-xnu-4k-baseline.sh'
    text = build.read_text(encoding='utf-8')
    old = ('if [ "${XNU_NATIVE_AES:-0}" != 1 ]; then\n'
           "    echo 'NativeVirtioBlock currently requires the qualified NativeAES/original-storage prelink baseline' >&2")
    if text.count(old) != 1:
        raise ValueError('Expected one NativeVirtioBlock crypto gate')
    text = text.replace(
        old,
        'if [ "$CRYPTO_BOOTSTRAP_MODE" != prelinked ] || [ "${XNU_SOURCE_CORECRYPTO14:-0}" != 1 ]; then\n'
        "    echo 'NativeVirtioBlock requires the original crypto/storage prelink closure' >&2", 1)
    build.write_text(text, encoding='utf-8')
    if owner_root:
        # Root binding consumes the real verifier/transport, not the optional
        # crypto diagnostic and its four sample blocks.
        text = build.read_text(encoding='utf-8')
        for old, new in (
            ('if [ "$OWNER_ROOT_AUDIT" = 1 ] && [ "$OWNER_ROOT_PROBE" != 1 ]; then',
             'if [ "$OWNER_ROOT_AUDIT" = 1 ] && [ "${XNU_NATIVE_VIRTIO_BLOCK:-0}" != 1 ]; then'),
            ('if [ "$OWNER_ROOT_PROBE" = 1 ] && {',
             'if { [ "$OWNER_ROOT_PROBE" = 1 ] || [ "${XNU_OWNER_ROOT_AUDIT:-0}" = 1 ]; } && {'),
            ('  if [ "$OWNER_ROOT_PROBE" = 1 ]; then\n    VERIFIED_ROOT_ARCHIVE=',
             '  if [ "$OWNER_ROOT_PROBE" = 1 ] || [ "$OWNER_ROOT_AUDIT" = 1 ]; then\n    VERIFIED_ROOT_ARCHIVE='),
            ('  "$OWNER_ROOT_PROBE" "${XNU_VERIFIED_ROOT_ARCHIVE:',
             '  "$((OWNER_ROOT_PROBE | OWNER_ROOT_AUDIT))" "${XNU_VERIFIED_ROOT_ARCHIVE:'),
        ):
            if text.count(old) != 1:
                raise ValueError('Expected one pinned owner-root build anchor')
            text = text.replace(old, new, 1)
        build.write_text(text, encoding='utf-8')
        # The native PMGR subclass binds to this exact original kext. Decode the
        # same private input before archive compilation; prelink reuses it.
        kernel = upstream / 'scripts/unixnu/kernel.py'
        text = kernel.read_text(encoding='utf-8')
        anchor = '    build_archives(ctx, env)\n'
        if text.count(anchor) != 1:
            raise ValueError('Expected one build_archives anchor in kernel.py')
        kernel.write_text(text.replace(
            anchor,
            "    env['UNIXNU_KERNELCACHE'] = str(ipsw.kernelcache(ctx, ipsw.Ipsw(ctx)))\n" + anchor,
            1), encoding='utf-8')


def select_ufs_profile(device, read_only=False):
    path = device / 'board.toml'
    text = path.read_text(encoding='utf-8')
    old = 'defconfig = "nabu_bootstrap_defconfig"'
    archive = '  "build-libpthread-kernel.py",'
    if text.count(old) != 1 or text.count(archive) != 1:
        raise ValueError('Expected unmodified bootstrap board for UFS selection')
    profile = 'nabu_ufs_readonly_defconfig' if read_only else 'nabu_ufs_passive_defconfig'
    builder = 'build-nabu-ufs-readonly.py' if read_only else 'build-nabu-ufs.py'
    text = text.replace(old, f'defconfig = "{profile}"', 1)
    text = text.replace(archive, archive + f'\n  "{builder}",', 1)
    path.write_text(text, encoding='utf-8')


def select_ufs_root_profile(device, upstream):
    """Hardware UFS windows plus the full owner-verified userland closure."""
    _select_owner_ufs_board(device, 'nabu_ufs_root_defconfig',
                            ROOT_COMPONENTS, data=False)
    _apply_owner_ufs_build(upstream, data=False, nabu_pmgr=True)


def select_ufs_cpu_ui_profile(device, upstream):
    """Owner UFS/Data plus the staged original graphics closure.

    NATIVE_LEGACY_DISPLAY stays disabled in this profile until the 21H16 ABI
    generator has produced and qualified the display archive.
    """
    _select_owner_ufs_board(device, CPU_UI_PROFILE, CPU_UI_ROOTS, data=True)
    _apply_owner_ufs_build(upstream, data=True, nabu_pmgr=True)


def select_ufs_personality(upstream):
    path = upstream / 'patches/xnu/native-aes-personality.patch'
    text = path.read_text(encoding='utf-8')
    before = '+    "     \'IOClass\'         = NativeUfs;"\n+    "     \'IOProviderClass\' = IOPlatformDevice;"'
    after = '+    "     \'IOClass\'         = NativeUfs;"\n+    "     \'IOMatchCategory\' = NativeUfsNub;"\n+    "     \'IOProviderClass\' = IOPlatformDevice;"'
    if text.count(before) != 1:
        raise ValueError('Pinned UFS nub personality changed')
    text = text.replace(before, after, 1)
    lines = text.splitlines(keepends=True)
    for at, line in enumerate(lines):
        match = re.match(r'@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)', line)
        if not match:
            continue
        body = []
        for item in lines[at + 1:]:
            if item.startswith(('@@ ', 'diff --git ', '--- a/')):
                break
            body.append(item)
        old_count = sum(item.startswith((' ', '-')) for item in body)
        new_count = sum(item.startswith((' ', '+')) for item in body)
        lines[at] = f'@@ -{match[1]},{old_count} +{match[2]},{new_count} @@{match[3]}\n'
    path.write_text(''.join(lines), encoding='utf-8')


def fixed_patch(data):
    if hashlib.sha256(data).hexdigest() != PATCH_SHA256:
        raise ValueError('Unexpected upstream display patch; refuse fuzzy rewriting')
    text = data.decode('utf-8')
    start = '+\tint legacy_register = 0;\n'
    end = '+\tint client_probe = 0;\n'
    hunk = '@@ -478,5 +478,88 @@'
    if any(text.count(marker) != 1 for marker in (start, end, hunk)):
        raise ValueError('Expected unique display-hook block and hunk')
    text = text.replace(hunk, '@@ -478,5 +478,90 @@', 1)
    text = text.replace(start, '+#if defined(XNU_NATIVE_LEGACY_DISPLAY) && XNU_NATIVE_LEGACY_DISPLAY\n' + start, 1)
    return text.replace(end, '+#endif\n' + end, 1).encode('utf-8')


def apply_vc_text_scale(result):
    """Append the pinned native-text-console magnification patch exactly once."""
    patch = (Path(__file__).resolve().parent / VC_TEXT_SCALE['name']).read_bytes()
    if hashlib.sha256(patch).hexdigest() != VC_TEXT_SCALE['sha256']:
        raise SystemExit('Unexpected video-console scale patch')
    if b'nabu-vc-scale' in result:
        return result
    return result + patch


def _apply_owner_union_patch(upstream, patch):
    source = (Path(__file__).resolve().parent / patch['name']).read_bytes()
    if hashlib.sha256(source).hexdigest() != patch['sha256']:
        raise SystemExit('Unexpected native union patch: ' + patch['name'])
    target = upstream / patch['target']
    if target.exists():
        if target.read_bytes() != source:
            raise SystemExit('Upstream native union patch differs from the pinned backport: ' +
                             patch['target'])
        return {'patch': patch['target'], 'sha256': patch['sha256']}
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(source)
    return {'patch': patch['target'], 'sha256': patch['sha256']}


def apply_owner_union_patches(upstream):
    """Backport the two union lookup/composition patches missing from the pin."""
    return [_apply_owner_union_patch(upstream, patch) for patch in UNION_PATCHES]


def apply_managed_rt_normal(upstream):
    """Materialize the pinned managed-RT Normal NC pmap patch into the upstream XNU series."""
    source = (Path(__file__).resolve().parent / MANAGED_RT_NORMAL['name']).read_bytes()
    if hashlib.sha256(source).hexdigest() != MANAGED_RT_NORMAL['sha256']:
        raise SystemExit('Unexpected managed-RT Normal NC patch')
    target = upstream / MANAGED_RT_NORMAL['target']
    if target.exists():
        raise SystemExit('Upstream already carries ' + MANAGED_RT_NORMAL['target'])
    target.write_bytes(source)
    return {'patch': MANAGED_RT_NORMAL['target'], 'sha256': MANAGED_RT_NORMAL['sha256'],
            'argument': MANAGED_RT_NORMAL['argument'], 'runtime_qualified': False}


def validate_profile(device):
    board = tomllib.loads((device / 'board.toml').read_text(encoding='utf-8'))
    name = board['kernel']['defconfig']
    if name not in PROFILES or board['ipsw']['build'] != '21H16':
        raise ValueError('Only the explicit nabu/21H16 profiles are supported')
    owner_root = name in OWNER_PROFILES
    ufs_profile = name in UFS_PROFILES
    ufs_root = name == 'nabu_ufs_root_defconfig'
    ufs_data = name == 'nabu_ufs_data_defconfig'
    ufs_cpu_ui = name == CPU_UI_PROFILE
    ufs_gpu = name in (UFS_GPU_PROFILE, UFS_GPU_METAL_PROFILE)
    ufs_gpu_metal = name == UFS_GPU_METAL_PROFILE
    ufs_cpu_present = name in (UFS_CPU_PRESENT_PROFILE, UFS_GPU_PROFILE, UFS_GPU_METAL_PROFILE)
    qemu_data = name == QEMU_DATA_PROFILE
    qemu_cpu_ui = name == QEMU_CPU_UI_PROFILE
    qemu_legacy = name in (QEMU_LEGACY_PROFILE, QEMU_CPU_PRESENT_PROFILE)
    qemu_owner = qemu_data or qemu_cpu_ui or qemu_legacy
    ufs_owner = name in UFS_OWNER_PROFILES
    roots = (UFS_GPU_METAL_ROOTS if ufs_gpu_metal else
             UFS_CPU_PRESENT_ROOTS if ufs_cpu_present else
             CPU_UI_ROOTS if ufs_cpu_ui or qemu_cpu_ui or qemu_legacy else
             ROOT_COMPONENTS if owner_root else ['com.apple.filesystems.apfs'])
    if board['kernel']['prelink']['roots'] != roots:
        raise ValueError('Profile requires its declared original-component closure')
    if board['kernel']['prelink'].get('early_security_init') != (AMFI_INIT if owner_root else None):
        raise ValueError('Profile requires its declared original security initializer')
    config = (device / 'configs' / name).read_text(encoding='utf-8')
    lines = config.splitlines()
    assignments = [line.split('=', 1)[0] for line in lines if line.startswith('CONFIG_')]
    if len(assignments) != len(set(assignments)):
        raise ValueError('Profile config has duplicate assignments')
    disabled_features = ['BOOT_PROGRESS', 'NATIVE_AES',
                         'SOURCE_MOCKFS', 'SHENG_PMGR', 'NATIVE_MOBILE_DISPLAY']
    if ufs_gpu:
        if 'CONFIG_XNU_NATIVE_ADRENO=y' not in lines:
            raise ValueError('A640 GPU profile must enable its actual GPU archive')
    else:
        disabled_features.append('NATIVE_ADRENO')
    if qemu_legacy or ufs_cpu_present:
        if 'CONFIG_XNU_NATIVE_LEGACY_DISPLAY=y' not in lines:
            raise ValueError('Legacy display profile must enable its actual backend')
    else:
        disabled_features.append('NATIVE_LEGACY_DISPLAY')
    if ufs_owner or qemu_owner:
        # The hardware profile is the union of the verified owner closure and
        # both storage symbols; it must not silently lose either side.
        required = ['CONFIG_XNU_NATIVE_VIRTIO_BLOCK=y',
                    'CONFIG_XNU_OWNER_ROOT_AUDIT=y', 'CONFIG_XNU_OWNER_ROOT_TRUST=y',
                    'CONFIG_XNU_TRUST_CACHE_RUNTIME=y', 'CONFIG_XNU_SECOND_STATIC_TRUST_CACHE=y',
                    'CONFIG_XNU_NATIVE_CS_HASH_CACHE=y', 'CONFIG_XNU_NATIVE_PAN=y',
                    'CONFIG_XNU_OWNER_CACHE_MOUNT=y', 'CONFIG_XNU_OWNER_CACHE_STARTUP=y',
                    'CONFIG_XNU_OWNER_BOOT_MANIFEST=y', 'CONFIG_XNU_OWNER_CACHE_CARRIER=y',
                    'CONFIG_XNU_SOURCE_CORECRYPTO14=y', 'CONFIG_XNU_BUILD_ARCHIVES=y',
                    'CONFIG_XNU_SOURCE_PTHREAD=y', 'CONFIG_XNU_ARM_DT_PLATFORM=y',
                    'CONFIG_XNU_ARMCPU=y', 'CONFIG_XNU_NATIVE_ARCH_TIMER=y',
                    'CONFIG_XNU_DT_PANIC_REGION=y', 'CONFIG_XNU_CRYPTO_BOOTSTRAP="prelinked"']
        required += ['CONFIG_XNU_NATIVE_UFS=n' if qemu_owner else 'CONFIG_XNU_NATIVE_UFS=y']
        if qemu_owner or ufs_cpu_present:
            required += ['CONFIG_XNU_OWNER_UNION_SYSTEMOS=y']
        if ufs_data or ufs_cpu_ui or ufs_cpu_present or qemu_owner:
            required += ['CONFIG_XNU_NATIVE_RAM_BLOCK=y', 'CONFIG_XNU_OWNER_DATA_MOUNT=y']
            uuids = [line for line in lines if line.startswith('CONFIG_XNU_OWNER_DATA_VOLUME_UUID="')]
            if len(uuids) != 1 or uuids[0] in ('CONFIG_XNU_OWNER_DATA_VOLUME_UUID=""',
                                               'CONFIG_XNU_OWNER_DATA_VOLUME_UUID="0"'):
                raise ValueError('UFS Data requires the actual seed APFS volume UUID')
        if any(line not in lines for line in required):
            raise ValueError('UFS root requires the full owner closure and both transports')
        if ufs_root:
            disabled_features.append('NATIVE_RAM_BLOCK')
    elif ufs_profile:
        required = ['CONFIG_XNU_NATIVE_UFS=y', 'CONFIG_XNU_SOURCE_CORECRYPTO14=y',
                    'CONFIG_XNU_BUILD_ARCHIVES=y', 'CONFIG_XNU_SOURCE_PTHREAD=y',
                    'CONFIG_XNU_ARM_DT_PLATFORM=y', 'CONFIG_XNU_ARMCPU=y',
                    'CONFIG_XNU_NATIVE_ARCH_TIMER=y', 'CONFIG_XNU_DT_PANIC_REGION=y',
                    'CONFIG_XNU_CRYPTO_BOOTSTRAP="prelinked"']
        if any(line not in lines for line in required):
            raise ValueError('Passive UFS requires its enabled class and original crypto closure')
        disabled_features += ['OWNER_ROOT_AUDIT', 'OWNER_ROOT_TRUST', 'VERIFIED_ROOT_PROBE',
                              'NATIVE_RAM_BLOCK']
    else:
        disabled_features.append('NATIVE_UFS')
    if name in ('nabu_bootstrap_defconfig', 'nabu_ufs_passive_defconfig', 'nabu_ufs_readonly_defconfig'):
        disabled_features.append('NATIVE_VIRTIO_BLOCK')
    for disabled in disabled_features:
        if f'CONFIG_XNU_{disabled}=n' not in lines:
            raise ValueError(f'G0 must leave {disabled} disabled')
    expected = ['build-corecrypto-14.py', 'build-corecrypto-14.py --namespace',
                'build-nabu-platform.py ArmDTPlatform', 'build-nabu-platform.py ArmCpu',
                'build-libpthread-kernel.py']
    if owner_root:
        expected.append('build-nabu-owner-root.py')
    if qemu_owner:
        expected += ['build-nabu-virtio.py', 'build-nabu-ram-block.py']
        if qemu_legacy:
            expected.append('build-nabu-legacy-display.py')
    elif ufs_data or ufs_cpu_ui or ufs_cpu_present:
        expected += ['build-nabu-virtio.py', 'build-nabu-ufs-root.py', 'build-nabu-ram-block.py']
        if ufs_cpu_present:
            expected.append('build-nabu-legacy-display.py')
        if ufs_gpu:
            expected.append('build-nabu-adreno.py')
    elif ufs_root:
        expected += ['build-nabu-virtio.py', 'build-nabu-ufs-root.py']
    elif ufs_profile:
        expected.append('build-nabu-ufs-readonly.py' if name == 'nabu_ufs_readonly_defconfig' else 'build-nabu-ufs.py')
    elif name != 'nabu_bootstrap_defconfig':
        expected.append('build-nabu-virtio.py')
    if board['kernel']['archives'] != expected:
        raise ValueError('G0 archive producer list changed; re-audit the profile')
    return board


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--upstream', type=Path, required=True)
    p.add_argument('--device', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--profile', choices=PROFILES, default=PROFILES[0])
    p.add_argument('--capture-logs', action='store_true', help='Build the explicit RAM/ESP logging capability; writes remain opt-in')
    p.add_argument('--gpu-userprobe', action='store_true', help='Enable the closed ABI1 probe addon boot transport')
    p.add_argument('--ui-watch', action='store_true', help='Compile opt-in bounded UI exec/main-thread observations')
    args = p.parse_args()
    if args.ui_watch and (args.profile != UFS_GPU_METAL_PROFILE or not args.capture_logs or not args.gpu_userprobe):
        raise SystemExit('UI watch requires the explicit captured Metal profile and GPU userprobe')
    if args.capture_logs and args.profile not in UFS_OWNER_PROFILES:
        raise SystemExit('Log persistence is only qualified for explicit hardware UFS owner profiles')
    if args.gpu_userprobe and (args.profile != UFS_GPU_METAL_PROFILE or not args.capture_logs):
        raise SystemExit('GPU userprobe boot support requires the explicit captured Metal profile')
    if args.profile == 'nabu_ufs_root_defconfig':
        select_ufs_root_profile(args.device, args.upstream)
    elif args.profile == 'nabu_ufs_data_defconfig':
        select_storage_profile(args.device, args.upstream, owner_root=True, data=True)
    elif args.profile == QEMU_DATA_PROFILE:
        select_qemu_data_profile(args.device, args.upstream)
    elif args.profile == QEMU_CPU_UI_PROFILE:
        select_qemu_cpu_ui_profile(args.device, args.upstream)
    elif args.profile in (QEMU_LEGACY_PROFILE, QEMU_CPU_PRESENT_PROFILE):
        select_qemu_legacy_profile(args.device, args.upstream, args.profile == QEMU_CPU_PRESENT_PROFILE)
    elif args.profile == CPU_UI_PROFILE:
        select_ufs_cpu_ui_profile(args.device, args.upstream)
    elif args.profile == UFS_CPU_PRESENT_PROFILE:
        select_ufs_cpu_present_profile(args.device, args.upstream)
    elif args.profile == UFS_GPU_PROFILE:
        select_ufs_gpu_profile(args.device, args.upstream)
    elif args.profile == UFS_GPU_METAL_PROFILE:
        select_ufs_gpu_metal_profile(args.device, args.upstream)
    elif args.profile in ('nabu_ufs_passive_defconfig', 'nabu_ufs_readonly_defconfig'):
        select_ufs_profile(args.device, args.profile == 'nabu_ufs_readonly_defconfig')
    elif args.profile != 'nabu_bootstrap_defconfig':
        select_storage_profile(args.device, args.upstream, args.profile == 'nabu_qemu_root_defconfig')
    if args.gpu_userprobe:
        kernel = args.upstream / 'scripts/unixnu/kernel.py'
        text = kernel.read_text(encoding='utf-8')
        anchor = '    build_archives(ctx, env)\n'
        if text.count(anchor) != 1:
            raise ValueError('Expected one archive entry for GPU userprobe support')
        ui_env = "    env['NABU_UI_WATCH'] = '1'\n" if args.ui_watch else ''
        kernel.write_text(text.replace(anchor, "    env['NABU_GPU_USERPROBE'] = '1'\n" + ui_env + anchor, 1),
                          encoding='utf-8')
    board = validate_profile(args.device)
    head = subprocess.check_output(['git', '-C', str(args.upstream), 'rev-parse', 'HEAD'], text=True).strip()
    if head != UPSTREAM:
        raise SystemExit('Unexpected UniXNU source revision')
    if args.profile == 'nabu_ufs_readonly_defconfig':
        select_ufs_personality(args.upstream)
    path = args.upstream / PATCH
    result = fixed_patch(path.read_bytes()) + NABU_TEXT_PATCH.encode()
    graphics_startup = None
    if args.profile in (CPU_UI_PROFILE, *DISPLAY_PROFILES):
        legacy_path = args.upstream / LEGACY_PATCH
        result, legacy_patch = retime_graphics_patches(result, legacy_path.read_bytes())
        legacy_path.write_bytes(legacy_patch)
        graphics_startup = {
            'trigger': 'verified_SystemOS_Data_prepare', 'execution': 'independent_kernel_thread',
            'before_root_load': False, 'runtime_qualified': False,
            'late_patch_sha256': hashlib.sha256(legacy_patch).hexdigest(),
        }
    options = (args.device / 'configs' / args.profile).read_text().splitlines()
    owner_root = args.profile in OWNER_PROFILES
    second_static = owner_root and 'CONFIG_XNU_SECOND_STATIC_TRUST_CACHE=y' in options
    if second_static:
        result += SECOND_STATIC_TRUST_CACHE_PATCH.encode()
    owner_carrier = owner_root and 'CONFIG_XNU_OWNER_CACHE_CARRIER=y' in options
    if owner_carrier:
        # Keep the upstream volume/parent checks, bound to these signed 21H16 inputs.
        carrier = args.upstream / 'patches/xnu/offline-owner-cache-carrier.patch'
        text = carrier.read_text().replace('04769D26-2CA0-4825-B443-E2E5F88300F2', ROOT_VOLUME_UUID)
        text = text.replace('8846FE78-2910-4297-AF97-D59BB6F8FC16', CACHE_VOLUME_UUID)
        text = text.replace('9846FE78-2910-4297-AF97-D59BB6F8FC16',
                            'D374ACD3-75FE-4FAD-B02E-FC3C9A86DA11')
        carrier.write_text(text, encoding='utf-8')
    owner_manifest = owner_root and 'CONFIG_XNU_OWNER_BOOT_MANIFEST=y' in options
    if owner_manifest:
        # The existing publisher authenticates these actual mounted devices.
        mount = args.upstream / 'patches/xnu/offline-owner-systemos-mount.patch'
        text = mount.read_text(encoding='utf-8').replace(
            '04769D26-2CA0-4825-B443-E2E5F88300F2', ROOT_VOLUME_UUID)
        mount.write_text(text, encoding='utf-8')
    owner_union = owner_root and 'CONFIG_XNU_OWNER_UNION_SYSTEMOS=y' in options
    union_patches = apply_owner_union_patches(args.upstream) if owner_union else None
    result = apply_vc_text_scale(result)
    managed_rt = apply_managed_rt_normal(args.upstream) if args.profile == UFS_GPU_METAL_PROFILE else None
    path.write_bytes(result)
    data_skeleton = None
    if 'CONFIG_XNU_OWNER_DATA_MOUNT=y' in options:
        data_skeleton = prepare_data_skeleton(args.upstream)
    log_capture = enable_logging(args.upstream, args.device) if args.capture_logs else None
    signature_scan = (prepare_signature_scan(args.upstream)
                      if 'CONFIG_XNU_NATIVE_CS_HASH_CACHE=y' in options else None)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({
        'upstream_commit': head, 'profile': board['kernel']['defconfig'],
        'patch': PATCH, 'before_sha256': PATCH_SHA256,
        'after_sha256': hashlib.sha256(result).hexdigest(),
        'input_release': 'unixnu-source-inputs', 'input_asset': 'ipsw-21h16-small.zip',
        'input_sha256': INPUT_SHA256, 'runtime_qualified': False,
        'ufs_passive_only': args.profile == 'nabu_ufs_passive_defconfig',
        'ufs_read_only': args.profile == 'nabu_ufs_readonly_defconfig',
        'ufs_root': args.profile == 'nabu_ufs_root_defconfig',
        'ufs_cpu_ui': args.profile == CPU_UI_PROFILE,
        'ufs_cpu_present': args.profile == UFS_CPU_PRESENT_PROFILE,
        'ufs_gpu': args.profile in (UFS_GPU_PROFILE, UFS_GPU_METAL_PROFILE),
        'ufs_gpu_metal': args.profile == UFS_GPU_METAL_PROFILE,
        'gpu_userprobe_boot': args.gpu_userprobe, 'ui_watch': args.ui_watch,
        'gpu': ({'mode': 'a640_metal', 'firmware_mode': 'adt', 'trigger': 'nabu-gpu=1',
                 'metal_accelerator': True, 'runtime_qualified': False}
                if args.profile == UFS_GPU_METAL_PROFILE else
                {'mode': 'a640_diagnostic', 'firmware_mode': 'adt',
                 'trigger': 'nabu-gpu=1', 'metal_accelerator': False,
                 'runtime_qualified': False} if args.profile == UFS_GPU_PROFILE else None),
        'qemu_data': args.profile == QEMU_DATA_PROFILE,
        'qemu_cpu_ui_reference': args.profile == QEMU_CPU_UI_PROFILE,
        'qemu_legacy_discovery': args.profile == QEMU_LEGACY_PROFILE,
        'qemu_cpu_present': args.profile == QEMU_CPU_PRESENT_PROFILE,
        'display_reference': DISPLAY_REFERENCE if args.profile in DISPLAY_PROFILES else None,
        'display_roots': GRAPHICS_ROOTS if args.profile in (CPU_UI_PROFILE, QEMU_CPU_UI_PROFILE, *DISPLAY_PROFILES) else [],
        'graphics_startup': graphics_startup,
        'data_skeleton': data_skeleton,
        'signature_scan_io': signature_scan,
        'log_capture': log_capture,
        'vc_text_scale': {'argument': VC_TEXT_SCALE['argument'],
                          'default': VC_TEXT_SCALE['default'],
                          'maximum': VC_TEXT_SCALE['maximum'],
                          'patch_sha256': VC_TEXT_SCALE['sha256']},
        'owner_policy': OWNER_POLICY if owner_root else None,
        'systemos_policy': SYSTEMOS_POLICY if owner_root else None,
        'second_static_trust_cache': second_static,
        'owner_boot_manifest': ({'domain': 'VerifiedRoot.OwnerBootSet.v1',
                                 'root_volume_uuid': ROOT_VOLUME_UUID,
                                 'cache_volume_uuid': CACHE_VOLUME_UUID} if owner_manifest else None),
        'owner_cache_carrier': ({'root_volume_uuid': ROOT_VOLUME_UUID,
                                 'cache_volume_uuid': CACHE_VOLUME_UUID} if owner_carrier else None),
        'owner_union_systemos': ({**union_patches[0], 'patches': union_patches}
                                 if union_patches else None),
        'managed_rt_normal': managed_rt,
    }, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
