"""Bind the board timer and preserve multi-instruction assembly on Darwin ARM64."""
import re
import struct

TIMER_HELPER = r'''static uint32_t gTimerIntid = 27;
static uint32_t kSgiPpiEnable = 0xffffU | (1U << 27);

static bool nabuTimerIntid(bool present, const void *data, unsigned size, uint32_t *out)
{
  if (!present) { *out = 27; return true; }
  if (!data || size != 4) { return false; }
  const uint8_t *bytes = static_cast<const uint8_t *>(data);
  uint32_t value = uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8) |
                   (uint32_t(bytes[2]) << 16) | (uint32_t(bytes[3]) << 24);
  if (value < 16 || value >= 32) { return false; }
  *out = value;
  return true;
}
'''

TIMER_PROPERTY = r'''  OSObject *timerObject = gic->getProperty ("virtual-timer-intid");
  OSData *timerData = OSDynamicCast (OSData, timerObject);
  uint32_t timerIntid = 27;
  valid = valid && nabuTimerIntid(timerObject != nullptr,
      timerData ? timerData->getBytesNoCopy() : nullptr,
      timerData ? timerData->getLength() : 0, &timerIntid);
  if (valid) {
    gTimerIntid = timerIntid;
    kSgiPpiEnable = 0xffffU | (1U << timerIntid);
    IOLog("ArmCpu: virtual timer INTID=%u\n", timerIntid);
  }
'''


def patch_timer_source(text):
    for old, new in (
            ('static const uint32_t kSgiPpiEnable = 0xffffU | (1U << 27);\n', TIMER_HELPER),
            ('  armcpu_gic_stride = static_cast<uint32_t> (gRedistStride);\n',
             TIMER_PROPERTY + '  armcpu_gic_stride = static_cast<uint32_t> (gRedistStride);\n'),
            ('    if ((id & 0xffffff) == 27) {\n', '    if ((id & 0xffffff) == gTimerIntid) {\n')):
        if text.count(old) != 1:
            raise ValueError('ArmCpu timer source drift: ' + old[:90])
        text = text.replace(old, new, 1)
    return text


# Darwin AArch64 treats ';' as a comment, so only the first instruction was
# emitted. Keep the pinned templates explicit to reject upstream source drift.
ASM_TEMPLATES = (
    (r'isb; mrs %0, cntvct_el0', 1),
    (r'msr icc_sre_el1, %0; isb', 1),
    (r'msr icc_igrpen1_el1, %0; dsb sy; isb', 2),
    (r'msr icc_eoir1_el1, %0; isb', 2),
    (r'dsb ishst; msr icc_sgi1r_el1, %0; isb', 2),
    (r'mrs %0, daif; msr daifset, #2; isb', 1),
    (r'dsb ishst; isb; mrs %0, cntvct_el0; isb', 1),
    (r'msr icc_sgi1r_el1, %0; isb; mrs %1, cntvct_el0', 1),
    (r'dsb ishst; msr icc_sgi0r_el1, %0; isb', 1),
    (r'msr icc_eoir0_el1, %0; isb', 1),
    (r'isb; mrs %0, cntvct_el0; isb; mrs %2, icc_pmr_el1; isb; mrs %1, cntvct_el0', 1),
    (r'msr daif, %0; isb', 1),
    (r'msr cntv_ctl_el0, %0; isb', 1),
    (r'dsb sy; isb', 1),
)


def patch_assembly(text):
    for template, count in ASM_TEMPLATES:
        old = '"' + template + '"'
        if text.count(old) != count:
            raise ValueError('ArmCpu assembly source drift: ' + template)
        fixed = template.replace('; ', r'\n\t')
        if template.startswith('msr icc_sgi1r_el1, %0;'):
            # tb is output %0; sgi is input %1. Match the upstream T733 fix.
            fixed = r'msr icc_sgi1r_el1, %1\n\tisb\n\tmrs %0, cntvct_el0'
        text = text.replace(old, '"' + fixed + '"')
    if re.search(r'__asm__\s+volatile\s*\(\s*"[^"\n]*;', text):
        raise ValueError('ArmCpu retains a Darwin assembly comment separator')
    return text


def patch_source(text):
    return patch_assembly(patch_timer_source(text))


def check_ipi_object(path):
    """Require the real SGI write, with its barriers, in both emitted senders."""
    from native_ufs_bindings import MachO
    image = MachO(path)
    if image.kind != 1:
        raise ValueError('IPI instruction check requires a relocatable ArmCpu object')
    checked = {}
    for name in ('__ZN6ArmCpu9signalCPUEP5IOCPU', '_armcpu_ipi_selftest'):
        start = image.names.get(name)
        if start is None:
            raise ValueError('ArmCpu IPI sender is missing: ' + name)
        section = next(s for s in image.sections if s[0] <= start < s[0] + s[1])
        end = min([value for value in image.names.values() if start < value < section[0] + section[1]]
                  + [section[0] + section[1]])
        code = image.data[section[2] + start - section[0]:section[2] + end - section[0]]
        words = struct.unpack('<%dI' % (len(code) // 4), code)
        positions = [i for i, word in enumerate(words) if word & 0xffffffe0 == 0xd518cba0]
        if not any(i > 0 and i + 1 < len(words) and words[i - 1] == 0xd5033a9f and
                   words[i + 1] == 0xd5033fdf for i in positions):
            raise ValueError('ArmCpu sender lacks DSB / ICC_SGI1R_EL1 / ISB: ' + name)
        checked[name] = [hex(start + 4 * i) for i in positions]
    return {'senders': checked, 'sgi1r_barriers_verified': True, 'runtime_qualified': False}
