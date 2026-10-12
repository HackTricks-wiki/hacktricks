# ARM64/ARM64e Call-Stack Spoofing

{{#include ../../../banners/hacktricks-training.md}}

## 메타데이터 기반 스택 언와인딩을 스푸핑할 수 있는 이유

일부 macOS 보안 도구는 스레드 스택 수집을 `/usr/sbin/spindump`에 맡기거나, 관례적인 메타데이터 기반 언와인더를 신뢰합니다. 임플란트는 스택에 ABI 규약에 맞는 합성 레코드를 배치해 이 신뢰 경계를 악용할 수 있습니다. 이렇게 하면 민감한 API가 이미지에 뒷받침되지 않는 임플란트 코드에서 직접 호출된 것이 아니라, dyld와 로드된 Apple 프레임워크의 공격자가 선택한 함수들을 거쳐 호출된 것처럼 보입니다. 이는 텔레메트리를 속이는 기법이지 실행 파일이나 언와인드 메타데이터를 바꾸는 기법은 아닙니다.<sup>[[1]](#references)</sup>

수집 측의 맥락은 [macOS 스택샷과 `spindump`](../macos-apps-inspecting-debugging-and-fuzzing/#stackshot--microstackshots)를 참조하세요.

언와인더는 컴파일러가 생성한 프롤로그가 레코드를 만들었다는 사실을 증명하지 않습니다. 언와인더는 현재 `PC`를 사용해 Mach-O 레시피를 선택하고, 해당 레시피를 `SP`, `x29`, `x30`, 스택 메모리 및 선언된 비휘발성 레지스터에 적용한 뒤, 복구된 호출자 `PC`로 다음 레시피를 선택하는 과정을 반복합니다. 공격자가 제어하는 메모리가 선택된 모든 레시피를 충족하면 실제로 해당 호출이 일어나지 않았더라도 구조적으로 유효하고 심볼을 확인할 수 있는 호출 체인이 만들어질 수 있습니다.<sup>[[1]](#references)</sup>

## ARM64 프레임 상태

[ARM64 어셈블리 개요](../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)에서 레지스터의 역할과 호출 규약을 다룹니다. `stp x29, x30, [sp, #-16]!` 다음에 `mov x29, sp`를 실행해 생성하는 일반적인 프레임에서, 호출자의 진입 시점 `SP`를 나타내는 Canonical Frame Address(CFA)는 `FP+0x10`입니다:<sup>[[1]](#references)[[4]](#references)</sup>

```text
higher addresses
FP + 0x10   caller SP / CFA
FP + 0x08   saved LR / caller PC
FP + 0x00   previous FP
FP - 0x08   saved x19 (when declared)
FP - 0x10   saved x20 (when declared)
lower addresses
```

Frame record는 `[FP]`를 통해 linked list를 이루지만, 이를 무작정 따라가는 것만으로는 충분하지 않습니다. leaf function에는 frame이 없을 수 있고, tail call은 논리적 전이를 제거할 수 있으며, 특이한 레이아웃에는 DWARF CFI가 사용됩니다. 현재 주소에 해당하는 recipe에 따라 unwinder가 FP chain을 읽을지 여부가 결정됩니다.<sup>[[1]](#references)[[4]](#references)</sup>

## Mach-O unwind recipe 선택

최종 linked image에는 compact unwind data가 `__TEXT,__unwind_info`에 저장됩니다. 섹션 헤더는 first-level function index를 가리키며, 각 index 범위는 regular (`kind=2`) 또는 compressed (`kind=3`) second-level page를 가리킵니다. compact unwind로 설명할 수 없는 레이아웃은 `__eh_frame`의 FDE와 call-frame instruction을 사용합니다.<sup>[[1]](#references)[[2]](#references)</sup>

각 후보 runtime PC에 대해:<sup>[[1]](#references)[[2]](#references)</sup>

1. 조회에 한해 ARM64e PAC bit를 제거하거나 정규화합니다.
2. 해당 주소를 포함하는 executable `__TEXT` 범위가 있는 loaded Mach-O를 찾습니다.
3. `functionOffset = normalizedPC - loadedImageBase`를 계산하고, 결과가 음수이거나 `UINT32_MAX`를 초과하면 거부합니다.
4. `index[i].functionOffset <= functionOffset < index[i+1].functionOffset`을 만족하는 first-level 범위를 선택합니다.
5. 참조된 second-level page를 파싱하고, 시작 offset이 해당 offset을 초과하지 않는 가장 가까운 entry를 선택한 다음, 주소가 다음 entry 또는 first-level 범위의 끝보다 낮은지 확인합니다.
6. 해당 entry를 디코딩하고 entry가 설명하는 정확한 state를 구성합니다.

주소가 저장된 LR에서 온 경우, call 직후의 주소가 caller의 커버 범위에 포함되도록 조회에 `PC-1`을 사용할 수 있습니다. 이는 recipe 선택만 변경하며, stack offset은 변경하지 않습니다.<sup>[[1]](#references)</sup>

Parser는 모든 header와 array에 대해 bounds check를 수행하고, 섹션 version이 `1`인지 확인하며, 마지막 first-level sentinel을 고려하고, second-level-page offset이 0인 경우를 거부하고, regular page와 compressed page를 구분해야 합니다. regular page에서 `entryPageOffset`은 해당 page의 시작을 기준으로 하며, first-level page offset은 `__unwind_info`의 시작을 기준으로 합니다.<sup>[[1]](#references)[[2]](#references)</sup>

상위 mode는 `encoding & 0x0F000000`입니다. 현재 LLVM 정의에는 다음 mode가 포함됩니다. parser는 DWARF가 아닌 모든 값을 classic frame으로 간주해서는 안 됩니다.<sup>[[1]](#references)[[2]](#references)</sup>

| Mode | Value | Caller 복구 |
| --- | --- | --- |
| Compact recipe 없음 | `0x00000000` | 중단하거나 독립적인 fallback을 사용합니다. |
| Frameless | `0x02000000` | 인코딩된 stack size를 현재 `SP`에 더합니다. caller PC는 live LR입니다. |
| DWARF | `0x03000000` | 하위 24비트로 식별되는 FDE/CFI를 실행합니다. |
| Frame | `0x04000000` | 일반적인 `x29` frame record를 읽습니다. |
| 인증된 LR 범위가 있는 arm64e frame | `0x05000000` | `UNWIND_ARM64_MODE_FRAME_PAUTH_LR`을 처리합니다. offset field는 커버 범위 내 `pacibsppc`의 위치를 지정합니다. |

Frameless mode에서 `stackSize = ((encoding & 0x00FFF000) >> 12) * 16`입니다. Frame mode에서는 하위 5비트가 연속된 저장 GPR pair `x19/x20`부터 `x27/x28`까지를 지정합니다. 비트 `0x100-0x800`은 마찬가지로 `d8-d15` pair를 지정합니다. 다음 PC를 찾는 데 이 저장된 register가 필요하지 않을 수 있지만, 그럴듯한 virtual caller state를 구성하려면 consumer가 복원하는 모든 field를 충족해야 합니다.<sup>[[1]](#references)[[2]](#references)</sup>

## Synthetic frame-mode record 구성

구성 과정에서는 stack에서 주소처럼 보이는 값을 검색하는 대신 unwinder의 동작을 역으로 따라갑니다.<sup>[[1]](#references)</sup>

1. 현재 loaded image에 있는 실제 executable PC를 선택합니다.
2. 해당 정확한 PC 또는 call-site address를 커버하는 recipe를 디코딩합니다.
3. 필요한 alignment와 CFA 관계를 만족하는 synthetic record를 할당합니다.
4. 다음 synthetic FP를 `[FP]`에, 해당 frame의 저장된 caller PC를 `[FP+8]`에 저장하고, 인코딩이 선언하는 모든 GPR/FPR save를 FP 아래에 저장합니다.
5. 여러 record를 연결하고 첫 번째 record를 live `x29`에 둡니다.
6. unwinding이 선택한 chain에 진입하면서도 실행을 안전하게 복원할 수 있도록 live LR과 API return path를 설정합니다.

예를 들어 `0x04000001`은 frame mode와 `x19/x20` pair를 의미합니다. 해당 state 변환과 필요한 memory는 다음과 같습니다.<sup>[[1]](#references)[[2]](#references)</sup>

```text
[FP - 0x10] = caller x20
[FP - 0x08] = caller x19
[FP + 0x00] = caller FP
[FP + 0x08] = caller PC
caller SP    = FP + 0x10
```

따라서 그럴듯해 보이는 주소만으로는 충분하지 않습니다. 복구된 각 PC가 다음 조회의 키가 되므로, 인코딩이 조작된 레이아웃과 일치하지 않는 주소가 하나라도 있으면 체인이 끊기거나 consumer가 일관되지 않은 레지스터 상태를 재구성하게 됩니다.<sup>[[1]](#references)</sup>

## ARM64e PAC 요구 사항

PAC는 주소를 암호화하지 않고, 사용되지 않는 포인터 비트에 키가 적용된 무결성 값을 저장합니다. Clang의 arm64e 반환 주소 스키마는 함수 진입 시의 스택 포인터를 판별자로 사용하며, instruction key B를 적용합니다. 일반적인 프레임에서 진입 시점의 `SP`는 CFA이므로, `[FP+8]`의 저장된 LR은 `FP+0x10`에 바인딩됩니다.<sup>[[1]](#references)[[3]](#references)</sup>

```text
modifier = syntheticFP + 0x10
signedLR = PACIB(rawReturnPC, modifier)

# Authentication must recover the original PC:
AUTIB(signedLR, modifier) == rawReturnPC
```

각 synthetic LR은 독립적으로 서명해야 합니다. 이미 서명된 LR을 CFA가 다른 프레임으로 옮기면 discriminator가 바뀌어 인증에 실패하기 때문입니다. `ptrauth_strip()`은 주소 정규화와 심볼 조회에는 적합하지만, 진위성을 입증하지는 **않습니다**. 실제 반환 또는 인증된 간접 분기에서는 해당 전환 지점에 필요한 키와 modifier를 사용해야 합니다.<sup>[[1]](#references)[[3]](#references)</sup>

일반적인 non-leaf arm64e 함수는 LR을 저장하기 전에 서명하고, 진입 시의 SP를 복원한 뒤 인증합니다.<sup>[[1]](#references)[[3]](#references)</sup>

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
; function body
ldp x29, x30, [sp], #16
retab
```

## Trampoline 및 restore bridge

Synthetic records는 unwinder를 만족시키기만 하면 되며, 완전한 execution context를 담고 있지는 않습니다. 민감한 API에서 조작된 callers로 직접 반환하면 일반적으로 crash가 발생합니다. 따라서 실용적인 설계에서는 API 바로 아래에 gadget frame을 배치합니다. API는 로드된 framework의 실행 가능한 코드로 반환하고, 해당 gadget은 제어된 callee-saved register를 통해 implant의 restore bridge로 분기합니다.<sup>[[1]](#references)</sup>

유용한 gadget은 LR을 보존하고, 예를 들어 적절한 `br`, `braa` 또는 `brab` 시퀀스를 사용해 제어된 register를 통해 실행을 전달합니다. restore bridge는 implant 실행을 재개하기 전에 원래 `x19-x30` 값과 `SP`를 복구해야 합니다. arm64e에서는 API-to-gadget, gadget-to-bridge, bridge-to-implant 경로에서 각 authenticated return 또는 branch에 해당 명령어가 사용하는 key와 discriminator로 서명된 pointer가 필요합니다.<sup>[[1]](#references)</sup>

```text
implant -> synthetic state -> sensitive API
                              |
                              v
                     signed gadget in image
                              |
                              v
                 restore x19-x30 and original SP
                              |
                              v
                           implant
```

그 결과는 stack 기반 탐지에서 중요한 trust-boundary 실패를 초래합니다. 체인에 매핑되어 심볼을 확인할 수 있는 Apple 프레임워크 PC만 포함되어 있어도 실제 control flow를 나타내지 않을 수 있습니다. 따라서 unwind 출력은 실행 추적으로 간주하지 말고, 스레드의 executable-memory 출처와 민감한 API 주변의 실제 전이를 보여 주는 독립적인 증거로 교차 검증해야 합니다.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Apple Silicon의 ARM64 stack 내부 구조와 난독화](https://mdsec.co.uk/2026/08/arm64-stack-internals-and-obfuscation-on-apple-silicon/)
- [2] [LLVM - Mach-O compact unwind 인코딩 정의](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
- [3] [Clang - Pointer Authentication](https://clang.llvm.org/docs/PointerAuthentication.html)
- [4] [Arm - Arm 64비트 아키텍처용 프로시저 호출 표준](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
{{#include ../../../banners/hacktricks-training.md}}
