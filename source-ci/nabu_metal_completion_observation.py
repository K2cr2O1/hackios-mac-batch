#!/usr/bin/env python3
"""Generate and bind an opt-in, source-only completion observer for AdrenoMetal."""
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile


FIELDS = ('finishEnter', 'finishReturn', 'queued', 'batchEnter', 'batchReturn', 'handlerEnter',
          'handlerReturn', 'waitCompletedEnter', 'waitCompletedRuntime', 'waitCompletedReturn',
          'pipelineScopeEnter', 'pipelineScopeExit', 'asyncAPIEnter', 'asyncHandlerEnter', 'asyncHandlerReturn',
          'scheduleEnter', 'scheduleReturn', 'scheduledEnter', 'scheduledReturn', 'waitScheduledEnter',
          'waitScheduledRuntime', 'waitScheduledReturn', 'commitEnter', 'commitPublished',
          'completedEnter', 'completedLock', 'functionScopeEnter', 'functionScopeExit')
ROW = 'H1 %s'
COUNTER_MAX = 36 ** 3 - 1
BASE36 = '0123456789abcdefghijklmnopqrstuvwxyz'


def encode_fields(values):
    """Encode fixed-width base36 values in FIELDS order for the compact H row."""
    if len(values) != len(FIELDS):
        raise ValueError('Counter field count differs from the H-row schema')
    output = []
    for value in values:
        number = min(max(int(value), 0), COUNTER_MAX)
        chars = ['0', '0', '0']
        for index in range(2, -1, -1):
            number, remainder = divmod(number, 36)
            chars[index] = BASE36[remainder]
        output.extend(chars)
    return ''.join(output)


def decode_fields(encoded):
    if len(encoded) != len(FIELDS) * 3:
        raise ValueError('H1 payload has an invalid length')
    decoded = {}
    for index, name in enumerate(FIELDS):
        value = 0
        for char in encoded[index * 3:index * 3 + 3].lower():
            if char not in BASE36:
                raise ValueError('H1 payload contains a non-base36 character')
            value = value * 36 + BASE36.index(char)
        decoded[name] = value
    return decoded


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def instrument(source):
    result = source

    def replace(old, new, expected=1):
        nonlocal result
        count = result.count(old)
        if count != expected:
            raise ValueError(f'Anchor count {count}, expected {expected}: {old[:100]!r}')
        result = result.replace(old, new)

    decls = '''namespace nabu_completion_observe {
static_assert(ATOMIC_LLONG_LOCK_FREE==2,"observer requires lock-free 64-bit counters");
''' + ''.join('static std::atomic<unsigned long long> ' + name + ';\n' for name in FIELDS) + '''
static unsigned shown(const std::atomic<unsigned long long> &v) {
 const unsigned long long n=v.load(std::memory_order_relaxed);return n>46655?46655:unsigned(n);
}
static void encode(char *out,const std::atomic<unsigned long long> &v) {
 static const char digits[]="0123456789abcdefghijklmnopqrstuvwxyz";
 unsigned n=shown(v);for(int i=2;i>=0;--i){out[i]=digits[n%36];n/=36;}
}
struct ScopeSpan {
 std::atomic<unsigned long long> &exit;
 ScopeSpan(std::atomic<unsigned long long> &enter,std::atomic<unsigned long long> &leave):exit(leave){enter.fetch_add(1,std::memory_order_relaxed);}
 ~ScopeSpan(){exit.fetch_add(1,std::memory_order_relaxed);}
};
}
'''
    replace('static std::atomic<uint64_t> gCommits,gCommitFailures,gPipelines,gProblems,gCompleted;\n',
            'static std::atomic<uint64_t> gCommits,gCommitFailures,gPipelines,gProblems,gCompleted;\n' + decls)

    def inc(name):
        return ' nabu_completion_observe::' + name + '.fetch_add(1,std::memory_order_relaxed);\n'

    def mark_scope_span(marker, entered, exited):
        nonlocal result
        starts = [match.start() for match in re.finditer(re.escape(marker), result)]
        if not starts:
            raise ValueError('Method anchor missing: ' + marker)
        for start in reversed(starts):
            opening = result.index('{', start) + 1
            span = ' nabu_completion_observe::ScopeSpan scopeSpan(nabu_completion_observe::' + entered + ',nabu_completion_observe::' + exited + ');\n'
            result = result[:opening] + span + result[opening:]

    replace('- (void)didSchedule {\n', '- (void)didSchedule {\n' + inc('scheduleEnter'))
    replace(''' void (^run)(void)=^{
  for(MTLCommandBufferHandler block in handlers)block((id<MTLCommandBuffer>)self);
  dispatch_group_leave(self->_schedulingHandlers);
 };''', ''' void (^run)(void)=^{
  for(MTLCommandBufferHandler block in handlers){
   nabu_completion_observe::scheduledEnter.fetch_add(1,std::memory_order_relaxed);
   block((id<MTLCommandBuffer>)self);
   nabu_completion_observe::scheduledReturn.fetch_add(1,std::memory_order_relaxed);
  }
  dispatch_group_leave(self->_schedulingHandlers);
 };''')
    replace(''' run();
}
// Completion releases retained resources''', ''' run();
 nabu_completion_observe::scheduleReturn.fetch_add(1,std::memory_order_relaxed);
}
// Completion releases retained resources''')
    replace('- (void)finish {\n', '- (void)finish {\n' + inc('finishEnter'))
    replace(''' void (^run)(void)=^{
  for(MTLCommandBufferHandler block in completedHandlers)block((id<MTLCommandBuffer>)self);
  dispatch_group_leave(self->_handlers);
 };''', ''' void (^run)(void)=^{
  nabu_completion_observe::batchEnter.fetch_add(1,std::memory_order_relaxed);
  for(MTLCommandBufferHandler block in completedHandlers){
   nabu_completion_observe::handlerEnter.fetch_add(1,std::memory_order_relaxed);
   block((id<MTLCommandBuffer>)self);
   nabu_completion_observe::handlerReturn.fetch_add(1,std::memory_order_relaxed);
  }
  dispatch_group_leave(self->_handlers);
  nabu_completion_observe::batchReturn.fetch_add(1,std::memory_order_relaxed);
 };''')
    replace(' if(queue)dispatch_async(queue,run);else run();\n',
            ' if(queue){nabu_completion_observe::queued.fetch_add(1,std::memory_order_relaxed);dispatch_async(queue,run);}else run();\n'
            + inc('finishReturn'))
    replace('- (void)commit {\n', '- (void)commit {\n' + inc('commitEnter'))
    replace('''  r={};r.index=index;r.committedUs=self.committedUs;r.ageUs=self.committedUs-createdUs;r.work=encodedWork;
 }
 dispatch_group_enter(_handlers);''', '''  r={};r.index=index;r.committedUs=self.committedUs;r.ageUs=self.committedUs-createdUs;r.work=encodedWork;
 }
 nabu_completion_observe::commitPublished.fetch_add(1,std::memory_order_relaxed);
 dispatch_group_enter(_handlers);''')
    replace('''   nmb_command_buffer_on_scheduled(_handle,scheduled,context) && nmb_command_buffer_commit(_handle))return;
  (void)CFBridgingRelease(context);''', '''   nmb_command_buffer_on_scheduled(_handle,scheduled,context) && nmb_command_buffer_commit(_handle))return;
  (void)CFBridgingRelease(context);''')
    replace('- (void)waitUntilCompleted {\n if(!self.committed)return;\n', '- (void)waitUntilCompleted {\n'
            + ' if(!self.committed)return;\n' + inc('waitCompletedEnter'))
    replace(' if(!self.failedLocally)nmb_command_buffer_wait(_handle,0);\n dispatch_group_wait(_handlers,DISPATCH_TIME_FOREVER);',
            ' if(!self.failedLocally)nmb_command_buffer_wait(_handle,0);\n' + inc('waitCompletedRuntime')
            + ' dispatch_group_wait(_handlers,DISPATCH_TIME_FOREVER);\n' + inc('waitCompletedReturn').rstrip())
    replace('- (void)waitUntilScheduled {\n if(!self.committed)return;\n', '- (void)waitUntilScheduled {\n'
            + ' if(!self.committed)return;\n' + inc('waitScheduledEnter'))
    replace(''' if(!self.failedLocally && !nmb_command_buffer_wait_scheduled(_handle)){
  NBLOG(@"native-metal: waitUntilScheduled refused: %@",lastError());return;
 }
 dispatch_group_wait(_schedulingHandlers,DISPATCH_TIME_FOREVER);
 gTimeWaitScheduled.add(began);''', ''' if(!self.failedLocally){
  const bool waitResult=nmb_command_buffer_wait_scheduled(_handle);
 nabu_completion_observe::waitScheduledRuntime.fetch_add(1,std::memory_order_relaxed);
  if(!waitResult){
   NBLOG(@"native-metal: waitUntilScheduled refused: %@",lastError());
   nabu_completion_observe::waitScheduledReturn.fetch_add(1,std::memory_order_relaxed);return;
  }
 }else{
  nabu_completion_observe::waitScheduledRuntime.fetch_add(1,std::memory_order_relaxed);
 }
 dispatch_group_wait(_schedulingHandlers,DISPATCH_TIME_FOREVER);
 nabu_completion_observe::waitScheduledReturn.fetch_add(1,std::memory_order_relaxed);
 gTimeWaitScheduled.add(began);''')
    replace('static void completed(void *context) {\n', 'static void completed(void *context) {\n'
            + inc('completedEnter'))
    replace('''  if(r.index==commandBuffer.commitIndex)r.callbackUs=took;
 }
 [commandBuffer finish];''', '''  if(r.index==commandBuffer.commitIndex)r.callbackUs=took;
 }
 nabu_completion_observe::completedLock.fetch_add(1,std::memory_order_relaxed);
 [commandBuffer finish];''')
    mark_scope_span('reflection:(MTLAutoreleasedComputePipelineReflection *)reflection error:(NSError **)error {',
                    'pipelineScopeEnter', 'pipelineScopeExit')
    mark_scope_span('reflection:(MTLAutoreleasedRenderPipelineReflection *)reflection error:(NSError **)error {',
                    'pipelineScopeEnter', 'pipelineScopeExit')
    mark_scope_span('- (id<MTLFunction>)newFunctionWithName:(NSString *)name constantValues:(MTLFunctionConstantValues *)values error:(NSError **)error {',
                    'functionScopeEnter', 'functionScopeExit')
    mark_scope_span('- (id<MTLFunction>)newFunctionWithName:(NSString *)name {',
                    'functionScopeEnter', 'functionScopeExit')
    async_pattern = re.compile(
        r'( NSError \*error=nil;id<MTL(?:Function|ComputePipelineState|RenderPipelineState)>[^\n]+\n)'
        r'( handler\([^\n]+\);\n)')
    def observe_async(match):
        return (inc('asyncAPIEnter') + match.group(1) + inc('asyncHandlerEnter') +
                match.group(2) + inc('asyncHandlerReturn'))
    result, async_count = async_pattern.subn(observe_async, result)
    if async_count != 5:
        raise ValueError(f'Async API callback anchors {async_count}, expected 5')
    rowline = ' row("T pipeline n=%llu total=%llums max=%llums",(unsigned long long)gTimePipeline.count.load(),ms(gTimePipeline.total.load()),ms(gTimePipeline.slowest.load()));\n'
    packed = ''.join(' nabu_completion_observe::encode(packed+' + str(i * 3) + ',nabu_completion_observe::' + field + ');\n'
                     for i, field in enumerate(FIELDS))
    replace(rowline, rowline + ' char packed[85]={};\n' + packed + ' row("H1 %s",packed);\n')
    worst = 'H1 ' + ('z' * (3 * len(FIELDS)))
    if len(worst) > 90:
        raise ValueError(f'Observer row exceeds 90-byte transport contract: {len(worst)}')
    return result


def qualify(applied_frontend, output, patch_path):
    """Recover the exact four-patch baseline from the applied source and save both forms."""
    applied_frontend, output, patch_path = Path(applied_frontend), Path(output), Path(patch_path)
    observed = applied_frontend.read_bytes()
    with tempfile.TemporaryDirectory(prefix='nabu-completion-observe-') as temporary:
        tree = Path(temporary)
        source = tree / 'NativeBridgeMetalFrontend.mm'
        source.write_bytes(observed)
        subprocess.run(['git', '-C', str(tree), 'init', '-q'], check=True)
        subprocess.run(['git', '-c', 'core.autocrlf=false', '-C', str(tree), 'apply', '--reverse', str(patch_path)], check=True)
        baseline = source.read_bytes()
    if instrument(baseline.decode('utf-8')).encode('utf-8') != observed:
        raise ValueError('Applied source does not match observer instrumentation from its baseline')
    output.mkdir(parents=True, exist_ok=True)
    baseline_path, observed_path = output / 'NativeBridgeMetalFrontend.baseline.mm', output / 'NativeBridgeMetalFrontend.mm'
    baseline_path.write_bytes(baseline)
    observed_path.write_bytes(observed)
    return {'baseline_sha256': sha(baseline_path), 'observed_sha256': sha(observed_path),
            'patch_sha256': sha(patch_path), 'telemetry_row_index': 2, 'telemetry_row_max_bytes': len('H1 ' + 'z' * (3 * len(FIELDS))),
            'telemetry_schema': 'H1', 'telemetry_fields': list(FIELDS), 'telemetry_encoding': 'three-character fixed-width base36 per field, in telemetry_fields order',
            'telemetry_counter_max': COUNTER_MAX,
            'observation_contract': 'first rows remain S, T pipeline, H1; fixed-order independent relaxed counters; no new locks or waiting semantics changes',
            'counter_semantics': {'waitCompletedRuntime': 'post-runtime-branch; increments even when failedLocally skips the runtime wait, so it is not success evidence',
                                 'waitScheduledRuntime': 'wait_scheduled returned, including refusal; failedLocally skip is counted as passing the branch',
                                 'commitEnter': 'counts attempted commit calls, including commit-twice refusal; compare commitPublished to identify publication progress',
                                 'pipelineScopeExit': 'C++ scope exit, including exception unwinding; not a successful return counter',
                                 'functionScopeExit': 'C++ scope exit, including exception unwinding; not a successful return counter'},
            'limitations': ['No buffer or thread identity; aggregate counters locate stages but cannot prove a deadlock.',
                            'Synchronous constant-value function compilation is observed; simple newFunctionWithName:error: is not counted.',
                            'Instrumentation can perturb scheduling; only a matching runtime observation can qualify actual behavior.'],
            'saved_frontend_baseline': baseline_path.name, 'saved_frontend_observed': observed_path.name,
            'apple_compiled': False, 'runtime_qualified': False, 'device_access': False}
