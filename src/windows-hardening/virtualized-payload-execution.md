# 가상화된 Payload 실행 및 커스텀 VM 회피

{{#include ../banners/hacktricks-training.md}}

Payload virtualization은 offensive logic을 guest instruction set으로 컴파일하고 native interpreter로 실행합니다. 원래 native instructions를 결국 메모리에 노출해야 하는 packer와 달리, virtualized payload는 보호된 logic을 전체 수명 동안 bytecode로 유지할 수 있습니다. 따라서 특정 unpacking window는 사라지지만, syscall, network activity, VM-to-native call 경계와 같이 host에서 관찰 가능한 동작까지 숨겨지는 것은 **아닙니다**.<sup>[[2]](#references)[[3]](#references)</sup>

## 실행 모델

간결한 virtualized loader는 실행을 다음 계층으로 나눌 수 있습니다.<sup>[[3]](#references)</sup>

1. LLVM을 통해 freestanding C, BOF source 또는 runtime libraries를 custom bytecode ISA로 컴파일합니다.
2. 작은 native interpreter를 시작하고 build별 opcode mapping을 초기화합니다.
3. PE linker-loader 자체를 bytecode로 실행합니다. 즉, headers를 파싱하고, sections를 매핑하고, relocations를 적용하고, imports를 resolve하고, IAT를 채웁니다.
4. guest-to-guest calls는 interpreter 내부에서 처리합니다. imported DLL functions처럼 bytecode 영역 외부의 targets는 native host-call thunk를 통해 전달합니다.
5. HTTP framing, TLS, C runtime 일부와 같은 지원 기능도 동일한 interpretation 경계 안으로 옮깁니다.

이 모델은 각 plugin마다 별도의 native code region을 할당할 필요가 없고, 원래 payload가 알아보기 쉬운 x86-64 instruction stream으로 나타나는 것도 방지합니다. 하지만 이는 보안 경계가 아니라 evasion/obfuscation 경계입니다. native interpreter와 모든 외부 효과는 여전히 관찰 가능합니다.<sup>[[2]](#references)[[3]](#references)</sup>

## 공유 메모리 host bridge

격리된 VM은 pointers를 guest buffer 내 offsets로 표현하므로, 모든 host API 호출 경계에서 pointer translation과 output parameters의 특수 처리가 필요합니다. 반면 shared-memory VM에서는 guest addresses가 host process의 유효한 주소가 됩니다. 따라서 `memcpy` 방식으로 읽고 쓸 수 있고, native allocation ECALL이 반환한 pointer를 bytecode에서 직접 역참조할 수 있습니다. RISC-Y Business는 이 설계가 PEB를 가져오고 임의의 host calls를 실행하는 수준으로 bridge를 단순화할 수 있음을 보여주었습니다.<sup>[[1]](#references)</sup>

Windows x64의 경우 virtual register file은 ABI를 미러링할 수 있습니다. 첫 네 개의 integer 또는 pointer arguments는 `RCX`, `RDX`, `R8`, `R9`에 두고, 이후 arguments와 shadow space는 stack에 둡니다. virtual `CALL`이 bytecode 범위 바깥의 주소로 해석되면 universal thunk가 해당 상태를 native call로 marshal하고 반환값을 VM에 복사합니다. 이 방식으로 pointer fixup 없이 IAT calls, heap allocation, socket operations를 수행할 수 있습니다.<sup>[[2]](#references)[[3]](#references)</sup>

단점은 격리가 완전히 사라진다는 것입니다. Guest memory corruption은 host에 직접 영향을 줄 수 있고, native callees는 guest pointers를 보관하거나 수정할 수 있으며, interpreter는 bytecode를 완전히 신뢰할 수 있는 것으로 취급해야 합니다. Native-to-VM callbacks에도 역방향 bridge가 필요합니다. outbound calls만 지원하는 VM은 `EnumWindows`와 같은 callback 기반 API를 직접 처리할 수 없습니다.<sup>[[1]](#references)[[3]](#references)</sup>

## Build별 ISA 다형성

고정 너비 custom ISA는 decoding, dispatch, relocation, virtual-register mapping을 단순화합니다. Centurion은 18바이트의 x86-64 기반 instruction format을 사용합니다. 이는 예측 가능한 parsing을 위해 code density를 희생하며, 기존 x86-64 artifacts를 bytecode로 변환할 가능성도 열어둡니다.<sup>[[3]](#references)</sup>

Build마다 opcode-to-handler mapping을 무작위화하면 동일한 guest logic도 서로 다른 byte sequences를 생성합니다. Mapping table을 암호화하고 runtime에만 복구하면 디스크에 안정적인 opcode dictionary가 남는 것도 방지할 수 있습니다. 이는 고정 signatures와 재사용 가능한 disassembly rules를 어렵게 하지만, native dispatcher, table-decryption routine, host-call 경계를 자동으로 polymorph하는 것은 아닙니다.<sup>[[3]](#references)</sup>

## 실행 환경을 VM 내부로 가져오기

Host process를 memory, syscall, socket primitives만 제공하도록 축소하고, freestanding libraries를 통해 더 높은 수준의 서비스를 VM 내부에서 제공할 수 있습니다. 예를 들어 FreeRTOS coreHTTP로 HTTP framing을 구현하고 mbedTLS로 TLS를 구현하면 WinHTTP나 운영체제 TLS API를 호출하지 않아도 됩니다. 그런 다음 `afd.sys` 또는 유사한 인터페이스를 통한 raw sockets가 좁은 native networking 경계가 됩니다.<sup>[[3]](#references)</sup>

이 **Bring Your Own Execution Environment (BYOEE)** 설계는 PE loading, runtime support, in-memory filesystem도 interpreter 안에 둘 수 있습니다. 이를 통해 telemetry를 없애는 대신 알아보기 쉬운 native implementations를 줄입니다. Raw socket operations는 계속 관찰 가능하며, 명시적 proxies나 TLS interception이 필요한 환경에서는 networking 설계가 작동하지 않을 수 있습니다.<sup>[[3]](#references)</sup>

## 선택적 native 가속

모든 instruction을 해석하는 방식은 public-key cryptography에서 특히 비용이 큽니다. 실용적인 분할 방식은 mbedTLS의 `MBEDTLS_ALT` hooks를 software-coprocessor 인터페이스로 사용하는 것입니다. TLS state, certificate parsing, negotiation, allocation, high-level bignum code는 bytecode에 두고, `bignum_core.c`의 자주 실행되는 arithmetic kernels만 native ECALLs를 통해 dispatch합니다. Centurion prototype에서는 `bignum.c`, `bignum_mod.c`, `bignum_mod_raw.c`를 virtualized 상태로 유지하고 내부 loops만 native로 실행하여 ECDHE handshake 시간을 수 분에서 수 초로 단축했습니다.<sup>[[3]](#references)</sup>

Accelerators는 선택 사항으로 만들어 TLS가 필요하지 않은 payload에서는 추가 native entry points를 제외할 수 있도록 합니다. 이 패턴은 어떤 interpreter workload에도 적용할 수 있습니다. 먼저 profile을 수행하고, subsystem 전체를 VM 외부로 옮기는 대신 가능한 한 작은 native primitive만 노출합니다.<sup>[[3]](#references)</sup>

Centurion은 TLS 1.2 bind shell로 전체 체인을 검증했습니다. Bytecode loader가 PE를 매핑하고, socket calls는 universal thunk를 통과하며, mbedTLS는 VM 내부에서 protocol을 처리하고, native ECALLs는 ECDHE arithmetic을 가속했습니다. 따라서 약 18 KB 크기의 native interpreter만으로 payload를 native x86-64 code로 구체화하지 않고 암호화된 command channel을 지원했습니다.<sup>[[3]](#references)</sup>

## 리버싱 및 탐지 기준점

다음은 아키텍처에서 추론한 실용적인 분석 기준점입니다. Virtualization은 분석가가 동작을 관찰하는 위치를 바꾸지만, 동작 자체를 없애지는 않습니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Fetch/decode/dispatch loop, virtual program counter, register file, 반복되는 고정 너비 instruction stepping을 식별합니다.
- Runtime decryption 이후 opcode table을 덤프하고, 디스크상의 암호화된 bytecode를 매칭하는 대신 handler addresses를 의미 있는 operations에 대응시킵니다.
- Universal thunk 또는 ECALL dispatcher에 breakpoint를 설정하여 native target, virtual argument registers, stack arguments, 반환값을 기록합니다.
- Loader 구현 자체가 bytecode여도 PEB access, export resolution, PE-header parsing, relocation writes, IAT population을 추적합니다.
- Socket creation 및 `afd.sys` traffic을 예상되는 WinHTTP 또는 native TLS calls의 부재와 연관 지어 분석합니다. High-level imports가 없다는 것은 단서이지, 무해하다는 증거는 아닙니다.
- Native arithmetic accelerators를 의미 분석의 chokepoints로 취급합니다. 주변 TLS state machine이 virtualized 상태로 유지되더라도, 호출자를 통해 key exchange 및 certificate-validation 활동을 파악할 수 있습니다.

원래 control-flow graph가 아닌 dispatcher에서 시작하는 분석 workflow는 [virtualizing packers에 대한 malware-analysis 안내](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation)를 참조하세요.

## 운영상 제약

Virtualization은 interpretation overhead를 발생시키고 toolchain 및 ABI의 복잡성을 높이며, behavioral detection 문제를 해결하지 못합니다. Shared memory는 설계상 안전하지 않고, raw-socket networking은 필수 proxies 뒤에서 실패할 수 있으며, callback을 많이 사용하는 Win32 APIs에는 native-to-VM trampolines가 필요합니다. Interpreter, syscall bridge, native accelerators도 일반적인 native footprint로 남아 있어 defenders가 signatures를 만들거나 instrument할 수 있습니다.<sup>[[2]](#references)[[3]](#references)</sup>

## 관련 페이지

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Payload Obfuscation을 위한 RISC-V Virtual Machine 구축](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: EDR 시대의 Red Teaming — Malware Virtualisation을 통한 Evasion](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — 자체 실행 환경 가져오기](https://praetorian.com/blog/virtualized-loader-centurion/)
{{#include ../banners/hacktricks-training.md}}
