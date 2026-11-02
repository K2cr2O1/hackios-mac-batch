"""Exercise exact frontend async methods in macOS Actions, with stub compilation.

Foundation/Metal/ARC/dispatch are real. The shader compiler and GPU are not used.
The original methods must fail the same bounded caller-lock regression.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

METHODS = (
    '- (void)newFunctionWithName:(NSString *)name constantValues:',
    '- (void)newRenderPipelineStateWithDescriptor:(MTLRenderPipelineDescriptor *)d completionHandler:',
    '- (void)newRenderPipelineStateWithDescriptor:(MTLRenderPipelineDescriptor *)d options:',
    '- (void)newComputePipelineStateWithFunction:(id<MTLFunction>)function completionHandler:',
    '- (void)newComputePipelineStateWithFunction:(id<MTLFunction>)function options:',
)

HARNESS = r'''
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <dispatch/dispatch.h>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <pthread.h>

static void require(bool ok,const char *message) {
 if(!ok){fprintf(stderr,"FAIL %s\n",message);exit(2);}
}
static void waitFor(dispatch_semaphore_t semaphore) {
 require(dispatch_semaphore_wait(semaphore,dispatch_time(DISPATCH_TIME_NOW,3*NSEC_PER_SEC))==0,"bounded wait");
}
@interface NBTestConstants : NSObject<NSCopying>
@property(nonatomic,copy) NSString *label;
@end
@implementation NBTestConstants
- (id)copyWithZone:(NSZone *)zone {
 (void)zone;NBTestConstants *copy=[NBTestConstants new];copy.label=self.label;return copy;
}
@end
@interface NBTestProbe : NSObject {
@public
 pthread_t caller;
 std::atomic<unsigned> creations,callbacks;
 std::atomic<bool> inlineCreation;
 uintptr_t inputIdentity;
 unsigned kind;
 BOOL failing;
}
@property(nonatomic,strong) dispatch_semaphore_t entered,release,done;
@property(nonatomic,strong) NSLock *callerLock;
@property(nonatomic,strong) NSObject *result,*reflection;
@property(nonatomic,strong) NSError *failure;
- (id)compile:(id)input label:(NSString *(^)(void))label options:(MTLPipelineOption)options
        error:(NSError **)error reflection:(id __autoreleasing *)reflection;
- (void)received:(id)state reflection:(id)reflection error:(NSError *)error;
@end
@implementation NBTestProbe
- (id)compile:(id)input label:(NSString *(^)(void))label options:(MTLPipelineOption)options
        error:(NSError **)error reflection:(id __autoreleasing *)reflection {
 creations.fetch_add(1);
 bool onCaller=pthread_equal(caller,pthread_self());inlineCreation.store(onCaller);
 dispatch_semaphore_signal(self.entered);
 if(!onCaller)waitFor(self.release);
 if(!onCaller){
  if(kind<3){
   require((uintptr_t)(__bridge void *)input!=inputIdentity,"descriptor/constants snapshot");
   require([label() isEqualToString:@"before"],"snapshot survives caller mutation");
  }else require((uintptr_t)(__bridge void *)input==inputIdentity,"function identity retained");
  require(options==((kind==2||kind==4)?MTLPipelineOptionArgumentInfo:MTLPipelineOptionNone),"options forwarded");
 }
 if(error)*error=failing?self.failure:nil;
 if(reflection)*reflection=failing?nil:self.reflection;
 return failing?nil:self.result;
}
- (void)received:(id)state reflection:(id)reflection error:(NSError *)error {
 callbacks.fetch_add(1);
 if(!pthread_equal(caller,pthread_self())){
  [self.callerLock lock];
  require(state==(failing?nil:self.result),"result forwarded");
  require(error==(failing?self.failure:nil),"error forwarded");
  require(reflection==((!failing&&(kind==2||kind==4))?self.reflection:nil),"reflection forwarded");
  [self.callerLock unlock];
 }
 dispatch_semaphore_signal(self.done);
}
@end
@interface NBTestLibrary : NSObject
@property(nonatomic,strong) NBTestProbe *probe;
@end
@implementation NBTestLibrary
- (id<MTLFunction>)newFunctionWithName:(NSString *)name constantValues:(MTLFunctionConstantValues *)values error:(NSError **)error {
 return (id<MTLFunction>)[self.probe compile:values label:^{
  require([name isEqualToString:@"before"],"function name snapshot");
  return [(NBTestConstants *)(id)values label];
 } options:MTLPipelineOptionNone error:error reflection:nullptr];
}
__LIBRARY_METHOD__
@end
@interface NBTestDevice : NSObject
@property(nonatomic,strong) NBTestProbe *probe;
@end
@implementation NBTestDevice
- (id<MTLRenderPipelineState>)newRenderPipelineStateWithDescriptor:(MTLRenderPipelineDescriptor *)d error:(NSError **)error {
 return (id<MTLRenderPipelineState>)[self.probe compile:d label:^{return d.label;}
  options:MTLPipelineOptionNone error:error reflection:nullptr];
}
- (id<MTLRenderPipelineState>)newRenderPipelineStateWithDescriptor:(MTLRenderPipelineDescriptor *)d options:(MTLPipelineOption)options
 reflection:(MTLAutoreleasedRenderPipelineReflection *)reflection error:(NSError **)error {
 return (id<MTLRenderPipelineState>)[self.probe compile:d label:^{return d.label;}
  options:options error:error reflection:(id __autoreleasing *)reflection];
}
- (id<MTLComputePipelineState>)newComputePipelineStateWithFunction:(id<MTLFunction>)function error:(NSError **)error {
 return (id<MTLComputePipelineState>)[self.probe compile:function label:nil
  options:MTLPipelineOptionNone error:error reflection:nullptr];
}
- (id<MTLComputePipelineState>)newComputePipelineStateWithFunction:(id<MTLFunction>)function options:(MTLPipelineOption)options
 reflection:(MTLAutoreleasedComputePipelineReflection *)reflection error:(NSError **)error {
 return (id<MTLComputePipelineState>)[self.probe compile:function label:nil
  options:options error:error reflection:(id __autoreleasing *)reflection];
}
__DEVICE_METHODS__
@end
int main(int argc,char **argv) {
 @autoreleasepool {
  require(argc==3,"arguments");
  NBTestProbe *probe=[NBTestProbe new];probe->kind=unsigned(atoi(argv[1]));probe->failing=atoi(argv[2]);
  require(probe->kind<5,"kind");probe->caller=pthread_self();
  probe->creations.store(0);probe->callbacks.store(0);probe->inlineCreation.store(false);
  probe.entered=dispatch_semaphore_create(0);probe.release=dispatch_semaphore_create(0);probe.done=dispatch_semaphore_create(0);
  probe.callerLock=[NSLock new];probe.result=[NSObject new];probe.reflection=[NSObject new];
  probe.failure=[NSError errorWithDomain:@"stub-compiler" code:37 userInfo:nil];
  NSMutableString *name=[NSMutableString stringWithString:@"before"];
  NBTestConstants *constants=[NBTestConstants new];constants.label=@"before";
  MTLRenderPipelineDescriptor *descriptor=[MTLRenderPipelineDescriptor new];descriptor.label=@"before";
  NSObject *function=[NSObject new];__weak NSObject *weakFunction=function;
  probe->inputIdentity=(uintptr_t)(__bridge void *)(probe->kind==0?(id)constants:probe->kind<3?(id)descriptor:function);
  NBTestLibrary *library=[NBTestLibrary new];library.probe=probe;
  NBTestDevice *device=[NBTestDevice new];device.probe=probe;
  __weak id weakOwner=probe->kind==0?(id)library:device;
  [probe.callerLock lock];
  switch(probe->kind){
   case 0:[library newFunctionWithName:name constantValues:(MTLFunctionConstantValues *)(id)constants completionHandler:^(id<MTLFunction> state,NSError *error){[probe received:state reflection:nil error:error];}];break;
   case 1:[device newRenderPipelineStateWithDescriptor:descriptor completionHandler:^(id<MTLRenderPipelineState> state,NSError *error){[probe received:state reflection:nil error:error];}];break;
   case 2:[device newRenderPipelineStateWithDescriptor:descriptor options:MTLPipelineOptionArgumentInfo completionHandler:^(id<MTLRenderPipelineState> state,MTLRenderPipelineReflection *reflection,NSError *error){[probe received:state reflection:reflection error:error];}];break;
   case 3:[device newComputePipelineStateWithFunction:(id<MTLFunction>)function completionHandler:^(id<MTLComputePipelineState> state,NSError *error){[probe received:state reflection:nil error:error];}];break;
   case 4:[device newComputePipelineStateWithFunction:(id<MTLFunction>)function options:MTLPipelineOptionArgumentInfo completionHandler:^(id<MTLComputePipelineState> state,MTLComputePipelineReflection *reflection,NSError *error){[probe received:state reflection:reflection error:error];}];break;
  }
  require(!probe->inlineCreation.load(),"inline creation can reenter caller lock");
  waitFor(probe.entered);
  [name setString:@"after"];constants.label=@"after";descriptor.label=@"after";
  function=nil;library=nil;device=nil;
  require(weakOwner!=nil,"queued work retains receiver");
  if(probe->kind>=3)require(weakFunction!=nil,"queued work retains function");
  require(probe->callbacks.load()==0,"callback waits for compilation");
  dispatch_semaphore_signal(probe.release);[probe.callerLock unlock];waitFor(probe.done);
  require(probe->creations.load()==1&&probe->callbacks.load()==1,"exactly one creation and callback");
  printf("PASS async kind=%u failure=%d snapshot/lifetime/lock/result\n",probe->kind,probe->failing);
 }
}
'''


def extract_methods(source):
    methods = []
    for marker in METHODS:
        if source.count(marker) != 1:
            raise ValueError('Async frontend method missing or duplicated: ' + marker)
        start = source.index(marker)
        methods.append(source[start:source.index('\n}', start) + 2])
    return methods


def harness(source):
    methods = extract_methods(source)
    return HARNESS.replace('__LIBRARY_METHOD__', methods[0]).replace('__DEVICE_METHODS__', '\n'.join(methods[1:]))


def qualify(baseline, fixed, output, env):
    if sys.platform != 'darwin' or env.get('GITHUB_ACTIONS') != 'true':
        raise ValueError('Apple qualification runs only in macOS GitHub Actions')
    output = Path(output)
    output.mkdir()
    report = {'gpu_exercised': False, 'hardware_tested': False, 'runtime_qualified': False,
              'compiler_is_stub': True, 'cases': []}
    for variant, path in (('baseline', baseline), ('fixed', fixed)):
        source = Path(path).read_text(encoding='utf-8')
        report[variant + '_source_sha256'] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        report[variant + '_method_sha256'] = [hashlib.sha256(m.encode()).hexdigest() for m in extract_methods(source)]
        code = output / (variant + '.mm')
        code.write_text(harness(source), encoding='utf-8')
        executable = output / variant
        command = ['xcrun', 'clang++', '-std=c++17', '-fobjc-arc', '-O1', '-Wall', '-Wextra', '-Werror',
                   '-Wno-deprecated-declarations', str(code), '-framework', 'Foundation', '-framework', 'Metal',
                   '-o', str(executable)]
        compiled = subprocess.run(command, env=env, capture_output=True, text=True, timeout=120)
        (output / (variant + '-compile.log')).write_text(compiled.stdout + compiled.stderr)
        report[variant + '_compile_command'] = command
        if compiled.returncode:
            raise ValueError('Async qualification compilation failed: ' + str(output / (variant + '-compile.log')))
        for kind in range(5):
            for failing in (0, 1):
                result = subprocess.run([str(executable), str(kind), str(failing)], env=env,
                                        capture_output=True, text=True, timeout=10)
                (output / f'{variant}-{kind}-{failing}.log').write_text(result.stdout + result.stderr)
                passed = (result.returncode == 0 and result.stdout.startswith('PASS async')) if variant == 'fixed' else (
                    result.returncode == 2 and 'FAIL inline creation can reenter caller lock' in result.stderr)
                report['cases'].append(dict(variant=variant, kind=kind, compiler_failure=bool(failing),
                                            returncode=result.returncode, passed=passed))
    report['passed'] = all(case['passed'] for case in report['cases'])
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    if not report['passed']:
        raise ValueError('Async qualification failed: ' + str(output / 'report.json'))
    return report
