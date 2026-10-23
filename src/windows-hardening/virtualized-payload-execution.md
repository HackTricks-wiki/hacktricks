# 가상화된 페이로드 실행 및 커스텀 VM 회피

{{#include ../banners/hacktricks-training.md}}

페이로드 가상화는 공격 로직을 게스트 명령어 집합으로 컴파일한 뒤 네이티브 인터프리터에서 실행합니다. 결국 메모리에 원래 네이티브 명령어를 노출해야 하는 packer와 달리, 가상화된 페이로드는 보호된 로직을 전체 실행 시간 동안 바이트코드로 유지할 수 있습니다. 이 방식은 특정 언패킹 노출 구간을 없애지만, syscall, 네트워크 활동, VM과 네이티브 코드 사이의 호출 경계처럼 호스트에서 관찰 가능한 동작까지 숨기지는 **않습니다**.<sup>[[2]](#references)[[3]](#references)</sup>

## 정적 분석 회피를 위한 WebAssembly 재호스팅

시그니처가 많이 등록된 Go 도구를 직접 수정하는 대신 `wasip1` 게스트로 컴파일하고 별도의 네이티브 로더에 포함할 수 있습니다. 게스트는 `net.Dial`, `net.Listen`, `os/exec`, `os.Pipe`처럼 지원되지 않는 연산을 `//go:wasmimport`를 통해 위임하도록 패치된 GOROOT를 대상으로 빌드합니다. 그러면 Wazero 호스트 모듈이 소켓, 프로세스 작업, Win32 호출 및 macOS 프레임워크 호출을 구현합니다. 이 방식은 원래 프로젝트의 Go API 사용을 유지하면서 로직 대부분을 암호화된 WASM 모듈로 옮겨, 정적 PE 도구가 분석하지 못하게 할 수 있습니다.<sup>[[4]](#references)</sup>

### 선형 메모리와 네이티브 API 연결

게스트 포인터는 호스트 가상 주소가 아니라 WASM 선형 메모리의 32비트 오프셋입니다. 네이티브 호출 전에 인수가 로컬 포인터로 표시되어 있고 `0x10000 <= value < wasmMemorySize` 범위에 있다면, 브리지는 이를 `wasmMemoryBase + value`로 변환할 수 있습니다. 하한값은 작은 핸들, 플래그, `nil`이 변환되는 것을 방지합니다. `win32metadata`에서 생성한 API별 마스크는 실제 포인터와 핸들, 크기, 원격 프로세스 주소를 구별하며, 부정확하거나 모호한 메타데이터는 별도로 재정의합니다.<sup>[[4]](#references)</sup>

네이티브 API는 게스트 출력 버퍼를 통해 호스트 포인터를 반환할 수도 있습니다. 미러 테이블은 이러한 객체에 게스트 메모리 표현을 할당하고 원래 호스트 주소로 역매핑할 수 있습니다. COM에서는 인터페이스와 vtable을 모두 미러링해야 합니다. 데이터 포인터는 따라가서 미러링할 수 있지만, `MEM_IMAGE` 영역의 실행 가능한 포인터는 불투명한 토큰으로 유지해야 합니다. WASM은 네이티브 명령어를 실행할 수 없기 때문입니다. 이 모델은 `EnumWindows` 또는 `SetWindowsHookEx`와 같은 호스트-게스트 콜백 API를 직접 지원하지 않습니다.<sup>[[4]](#references)</sup>

### 빌드별 WASM VM 다형성

런타임과 페이로드를 빌드마다 함께 변환할 수 있습니다. opcode-핸들러 테이블을 섞고, 모든 게스트 opcode를 새 매핑으로 다시 쓰며, 섹션 식별자를 무작위화하고, 표준 `\0asm` 매직을 빌드별 마커로 바꾸고, 런타임 캐시 매직도 변경합니다. 그러면 동일한 소스에서 바이트 단위로 다른 모듈이 생성되고, 분석가는 호스트 로더에서 커스텀 매핑과 프레이밍을 알아내기 전까지 일반 WASM 도구로 페이로드를 파싱할 수 없습니다.<sup>[[4]](#references)</sup>

리버스 엔지니어링을 할 때는 `\0asm`만 기준으로 페이로드를 추출하기보다 네이티브 호스트부터 살펴보세요. 컴파일된 마커, 모듈 복호화 경로, opcode 디스패치 테이블, `env` 호스트 함수 등록을 식별한 다음 표준 모듈을 재구성하거나 import 경계를 계측합니다. 임베디드 바이트코드가 빌드마다 달라져도 네트워킹, 프로세스 생성, 레지스트리 접근, 동적 로딩, 일반 Win32 디스패치 호출은 브리지를 통과하므로 브리지는 여전히 유용한 동작 관찰 지점입니다.<sup>[[4]](#references)</sup>

### 바깥쪽 Go 실행 파일 위장

게스트만 변경하면 식별하기 쉬운 로더가 남습니다. 시연된 바깥 바이너리 변환은 정상적인 Go 프로젝트에서 가져온 조밀한 심볼 프로필을 `gopclntab`에 삽입하고, 그럴듯한 소수의 DLL import를 순환시키며, PE `VERSIONINFO`와 Authenticode 식별 문자열을 바꿉니다. 이러한 변환은 컨테이너의 정적 분석 및 머신러닝 특징을 겨냥합니다. 호스트 shim이 드러내는 런타임 동작을 제거하지는 않습니다.<sup>[[4]](#references)</sup>

## 실행 모델

간결한 가상화 로더는 실행을 다음 계층으로 나눌 수 있습니다.<sup>[[3]](#references)</sup>

1. 독립형 C, BOF 소스 또는 런타임 라이브러리를 LLVM을 통해 커스텀 바이트코드 ISA로 컴파일합니다.
2. 소형 네이티브 인터프리터를 시작하고 빌드별 opcode 매핑을 초기화합니다.
3. PE 링커-로더 자체를 바이트코드로 실행합니다. 헤더를 파싱하고, 섹션을 매핑하며, 재배치를 적용하고, import를 확인하고, IAT를 채웁니다.
4. 게스트 간 호출은 인터프리터 내부에서 처리합니다. import된 DLL 함수처럼 바이트코드 영역 밖의 대상을 네이티브 호스트 호출 thunk로 전달합니다.
5. HTTP 프레이밍, TLS, C 런타임 일부와 같은 지원 기능도 동일한 인터프리터 경계 안으로 옮깁니다.

이 모델은 플러그인마다 별도의 네이티브 코드 영역을 할당하지 않아도 되며, 원래 페이로드가 식별 가능한 x86-64 명령어 스트림으로 나타나는 것을 방지합니다. 하지만 이는 보안 경계가 아니라 회피/난독화 경계입니다. 네이티브 인터프리터와 모든 외부 동작은 여전히 관찰할 수 있습니다.<sup>[[2]](#references)[[3]](#references)</sup>

## 공유 메모리 호스트 브리지

격리된 VM은 포인터를 게스트 버퍼의 오프셋으로 나타내므로, 호스트 API를 호출할 때마다 포인터 변환과 출력 매개변수의 특수 처리가 필요합니다. 반면 공유 메모리 VM에서는 게스트 주소를 호스트 프로세스 주소로 사용할 수 있습니다. 따라서 읽기와 쓰기는 `memcpy` 방식으로 처리할 수 있으며, 네이티브 할당 ECALL이 반환한 포인터를 바이트코드에서 직접 역참조할 수 있습니다. RISC-Y Business는 이 설계로 브리지를 PEB를 가져오고 임의의 호스트 호출을 수행하는 수준까지 줄일 수 있음을 보였습니다.<sup>[[1]](#references)</sup>

Windows x64의 경우 가상 레지스터 파일을 ABI에 맞출 수 있습니다. 처음 네 개의 정수 또는 포인터 인수를 `RCX`, `RDX`, `R8`, `R9`에 배치하고, 나머지 인수와 shadow space는 스택에 둡니다. 가상 `CALL`이 바이트코드 범위 밖의 대상으로 확인되면 범용 thunk가 해당 상태를 네이티브 호출에 맞게 전달하고 반환값을 VM에 복사합니다. 이로써 포인터 보정 없이 IAT 호출, 힙 할당, 소켓 작업을 수행할 수 있습니다.<sup>[[2]](#references)[[3]](#references)</sup>

단점은 격리가 완전히 사라진다는 것입니다. 게스트 메모리 손상이 호스트에 직접 영향을 줄 수 있고, 네이티브 호출 함수가 게스트 포인터를 보관하거나 수정할 수 있으며, 인터프리터는 바이트코드를 완전히 신뢰해야 합니다. 네이티브에서 VM으로 향하는 콜백에도 역방향 브리지가 필요합니다. 아웃바운드 호출만 지원하는 VM은 `EnumWindows`와 같은 콜백 기반 API를 직접 처리할 수 없습니다.<sup>[[1]](#references)[[3]](#references)</sup>

## 빌드별 ISA 다형성

고정 폭 커스텀 ISA는 디코딩, 디스패치, 재배치, 가상 레지스터 매핑을 단순화합니다. Centurion은 x86-64에서 영감을 얻은 18바이트 명령어 형식을 사용합니다. 이 형식은 예측 가능한 파싱을 위해 코드 밀도를 낮추는 대신 기존 x86-64 산출물을 바이트코드로 변환할 수 있는 가능성도 제공합니다.<sup>[[3]](#references)</sup>

빌드마다 opcode-핸들러 매핑을 무작위화하면 동일한 게스트 로직에서도 서로 다른 바이트 시퀀스가 생성됩니다. 매핑 테이블을 암호화하고 런타임에만 복구하면 디스크상의 일관된 opcode 사전도 제거할 수 있습니다. 이는 고정 시그니처와 재사용 가능한 디스어셈블리 규칙을 방해하지만, 네이티브 디스패처, 테이블 복호화 루틴, 호스트 호출 경계를 자동으로 다형화하지는 않습니다.<sup>[[3]](#references)</sup>

## 실행 환경을 VM 내부로 가져오기

호스트 프로세스는 메모리, syscall, 소켓 기본 기능만 남기고, 독립형 라이브러리가 VM 내부에서 더 높은 수준의 서비스를 제공하도록 구성할 수 있습니다. 예를 들어 FreeRTOS coreHTTP로 HTTP 프레이밍을 구현하고 mbedTLS로 TLS를 구현하면 WinHTTP나 운영체제 TLS API를 호출하지 않아도 됩니다. 그러면 `afd.sys` 또는 유사한 인터페이스를 통한 raw socket이 좁은 범위의 네이티브 네트워킹 경계가 됩니다.<sup>[[3]](#references)</sup>

이 **자체 실행 환경 제공(Bring Your Own Execution Environment, BYOEE)** 설계는 PE 로딩, 런타임 지원, 메모리 내 파일 시스템도 인터프리터 내부에 둘 수 있습니다. 이는 인식하기 쉬운 네이티브 구현을 줄일 뿐 텔레메트리를 없애지는 않습니다. raw socket 작업은 계속 관찰 가능하며, 명시적인 프록시나 TLS 가로채기가 필요한 환경에서는 네트워킹 설계가 작동하지 않을 수 있습니다.<sup>[[3]](#references)</sup>

## 선택적 네이티브 가속

모든 명령어를 인터프리트하면 공개 키 암호화에서 특히 비용이 큽니다. 실용적인 분할 방식은 mbedTLS의 `MBEDTLS_ALT` hook을 소프트웨어 보조 프로세서 인터페이스로 사용하는 것입니다. TLS 상태, 인증서 파싱, 협상, 할당, 상위 수준 bignum 코드는 바이트코드에 유지하되, `bignum_core.c`의 부하가 큰 산술 커널은 네이티브 ECALL을 통해 실행합니다. Centurion 프로토타입에서는 `bignum.c`, `bignum_mod.c`, `bignum_mod_raw.c`를 가상화된 상태로 두고 내부 루프는 네이티브로 실행해 ECDHE 핸드셰이크 시간을 몇 분에서 몇 초로 줄였습니다.<sup>[[3]](#references)</sup>

가속기는 선택 사항으로 만들어 TLS가 필요 없는 페이로드에서 추가 네이티브 진입점을 생략할 수 있게 하세요. 이 패턴은 모든 인터프리터 작업에 적용할 수 있습니다. 먼저 프로파일링한 다음, 전체 하위 시스템을 VM 밖으로 옮기기보다 가능한 한 작은 네이티브 기본 기능만 노출하세요.<sup>[[3]](#references)</sup>

Centurion은 TLS 1.2 bind shell을 통해 전체 흐름을 검증했습니다. 바이트코드 로더가 PE를 매핑하고, 소켓 호출은 범용 thunk를 통과하며, mbedTLS는 VM 내부에서 프로토콜을 처리하고, 네이티브 ECALL은 ECDHE 산술을 가속했습니다. 약 18 KB 크기의 네이티브 인터프리터는 페이로드를 네이티브 x86-64 코드로 구체화하지 않고도 암호화된 명령 채널을 지원했습니다.<sup>[[3]](#references)</sup>

## 리버싱 및 탐지 기준점

다음은 아키텍처에서 도출한 실용적인 분석 기준점입니다. 가상화는 분석가가 동작을 관찰하는 위치를 바꾸지만, 동작 자체를 제거하지는 않습니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- fetch/decode/dispatch 루프, 가상 프로그램 카운터, 레지스터 파일, 반복되는 고정 폭 명령어 처리를 식별합니다.
- 런타임 복호화 후 opcode 테이블을 덤프하고, 디스크상의 암호화된 바이트코드와 대조하는 대신 핸들러 주소를 의미 있는 연산에 매핑합니다.
- 범용 thunk 또는 ECALL 디스패처에서 중단점을 설정해 네이티브 대상, 가상 인수 레지스터, 스택 인수, 반환값을 기록합니다.
- 로더 구현 자체가 바이트코드인 경우에도 PEB 접근, export 확인, PE 헤더 파싱, 재배치 기록, IAT 채우기를 추적합니다.
- 소켓 생성과 `afd.sys` 트래픽을 예상되는 WinHTTP 또는 네이티브 TLS 호출의 부재와 연관 지어 살펴봅니다. 상위 수준 import가 없다는 점은 단서일 뿐, 악성 여부를 입증하지는 않습니다.
- 네이티브 산술 가속기를 의미 분석의 주요 지점으로 다룹니다. 주변 TLS 상태 머신은 가상화된 채로 있어도 호출자를 통해 키 교환 및 인증서 검증 활동을 파악할 수 있습니다.

원래 제어 흐름 그래프가 아니라 디스패처에서 시작하는 분석 워크플로에 대해서는 [packer 가상화에 관한 malware-analysis 안내](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation)를 참조하세요.

## 운영상 제약

가상화는 인터프리터 오버헤드를 발생시키고, 툴체인 및 ABI 복잡성을 높이며, 동작 기반 탐지를 해결하지 못합니다. 공유 메모리는 설계상 안전하지 않고, raw socket 네트워킹은 필수 프록시 환경에서 실패할 수 있으며, 콜백을 많이 사용하는 Win32 API에는 네이티브에서 VM으로 연결하는 trampoline이 필요합니다. 인터프리터, syscall 브리지, 네이티브 가속기 역시 방어자가 시그니처를 만들거나 계측할 수 있는 일반적인 네이티브 흔적으로 남습니다.<sup>[[2]](#references)[[3]](#references)</sup>

## 관련 페이지

VMProtect 3.x 패킹 분석은 [에뮬레이션 언패킹 및 import 복구](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#vmprotect-3x-emulated-unpacking-and-import-repair)를 참조하세요.

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: 페이로드 난독화를 위한 RISC-V 가상 머신 구축](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: EDR 시대의 레드팀 활동 — Malware 가상화를 통한 회피](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — 자체 실행 환경 제공](https://praetorian.com/blog/virtualized-loader-centurion/)
- [4] [Praetorian - WasmForge 시작하기: Sliver를 WebAssembly로 컴파일하기](https://praetorian.com/blog/wasmforge-sliver-webassembly)
{{#include ../banners/hacktricks-training.md}}
