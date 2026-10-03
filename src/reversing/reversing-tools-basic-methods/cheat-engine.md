# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)는 실행 중인 게임의 메모리 내부에서 중요한 값이 저장된 위치를 찾고 이를 변경하는 데 유용한 프로그램입니다.\
다운로드하여 실행하면 도구 사용 방법을 설명하는 **tutorial**이 **표시**됩니다. 도구 사용 방법을 배우고 싶다면 이를 완료하는 것을 적극 권장합니다.

## 무엇을 검색하시겠습니까?

![Cheat Engine - 무엇을 검색하시겠습니까?: 무엇을 검색하시겠습니까?](<../../images/image (762).png>)

이 도구는 프로그램의 메모리에서 **어떤 값**(일반적으로 숫자)이 **저장된 위치**를 찾는 데 매우 유용합니다.\
**일반적으로 숫자**는 **4bytes** 형식으로 저장되지만, **double** 또는 **float** 형식에서도 찾을 수 있으며, **숫자와 다른 값**을 찾고 싶을 수도 있습니다. 따라서 무엇을 **검색할지** **선택**해야 합니다.

![Cheat Engine - 무엇을 검색하시겠습니까?: 일반적으로 숫자는 4bytes 형식으로 저장되지만, double 또는 float 형식에서도 찾을 수 있으며, 다른 항목을 찾고 싶을 수도 있습니다...](<../../images/image (324).png>)

또한 **검색**의 **유형**을 **다르게** 지정할 수 있습니다.

![Cheat Engine - 무엇을 검색하시겠습니까?: 또한 다양한 검색 유형을 지정할 수 있습니다](<../../images/image (311).png>)

메모리를 스캔하는 동안 **게임을 중지**하도록 체크 박스를 선택할 수도 있습니다.

![Cheat Engine - 무엇을 검색하시겠습니까?: 메모리를 스캔하는 동안 게임을 중지하도록 체크 박스를 선택할 수도 있습니다](<../../images/image (1052).png>)

### Hotkeys

_**Edit --> Settings --> Hotkeys**_에서 **게임**을 **중지**하는 등의 다양한 용도에 사용할 **hotkeys**를 설정할 수 있습니다(어느 시점에 메모리를 스캔하려는 경우 매우 유용합니다). 다른 옵션도 사용할 수 있습니다.

![무엇을 검색하시겠습니까? - Hotkeys: Edit -- Settings -- Hotkeys에서 게임을 중지하는 등의 다양한 용도에 사용할 hotkeys를 설정할 수 있습니다(어느 시점에 메모리를 스캔하려는 경우 매우 유용합니다...](<../../images/image (864).png>)

## 값 수정하기

찾고 있는 **값**이 저장된 위치를 **찾은** 후(자세한 내용은 다음 단계에서 설명) 해당 값을 더블 클릭한 다음 값 자체를 더블 클릭하여 **수정**할 수 있습니다.

![Hotkeys - 값 수정하기: 찾고 있는 값이 저장된 위치를 찾은 후(자세한 내용은 다음 단계에서 설명) 해당 값을 더블 클릭한 다음 값 자체를 더블 클릭하여 수정할 수 있습니다](<../../images/image (563).png>)

마지막으로 **체크 표시**를 하여 메모리에 수정 사항을 적용합니다.

![Hotkeys - 값 수정하기: 마지막으로 체크 표시를 하여 메모리에 수정 사항을 적용합니다](<../../images/image (385).png>)

**메모리**에 대한 **변경 사항**은 즉시 **적용**됩니다(게임이 이 값을 다시 사용하기 전까지는 해당 값이 **게임에서 업데이트되지 않습니다**).

## 값 검색하기

이제 개선하고 싶은 중요한 값(예: 사용자 캐릭터의 생명력)이 있고, 이 값을 메모리에서 찾고 있다고 가정하겠습니다.

### 알려진 변경을 통한 검색

100이라는 값을 찾는다고 가정하면, 해당 값을 검색하여 **scan**을 수행하고 많은 일치 항목을 찾게 됩니다.

![값 검색하기 - 알려진 변경을 통한 검색: 100이라는 값을 찾는다고 가정하면, 해당 값을 검색하여 scan을 수행하고 많은 일치 항목을 찾게 됩니다](<../../images/image (108).png>)

그런 다음 **값이 변경**되도록 무언가를 수행하고, 게임을 **중지**한 뒤 **next scan**을 수행합니다.

![값 검색하기 - 알려진 변경을 통한 검색: 그런 다음 값이 변경되도록 무언가를 수행하고, 게임을 중지한 뒤 next scan을 수행합니다](<../../images/image (684).png>)

Cheat Engine은 **100에서 새로운 값으로 변경된 값**을 검색합니다. 이제 찾고 있던 값의 **주소**를 **찾은** 것입니다. 이를 수정할 수 있습니다.\
_여전히 여러 값이 남아 있다면 해당 값을 다시 변경한 뒤 또 다른 "next scan"을 수행하여 주소를 필터링합니다._

### 알 수 없는 값, 알려진 변경

**값 자체는 모르지만** 값을 **변경하는 방법**(변경량까지)을 알고 있는 상황에서도 해당 숫자를 찾을 수 있습니다.

먼저 "**Unknown initial value**" 유형으로 scan을 수행합니다.

![알려진 변경을 통한 검색 - 알 수 없는 값, 알려진 변경: 먼저 " Unknown initial value " 유형으로 scan을 수행합니다](<../../images/image (890).png>)

그런 다음 값을 변경하고 **값이 어떻게 변경되었는지** 지정합니다(이 경우에는 1만큼 감소했습니다). 그리고 **next scan**을 수행합니다.

![알려진 변경을 통한 검색 - 알 수 없는 값, 알려진 변경: 그런 다음 값을 변경하고 값이 어떻게 변경되었는지 지정합니다(이 경우에는 1만큼 감소했습니다). 그리고 next scan을 수행합니다](<../../images/image (371).png>)

선택한 방식으로 **변경된 모든 값**이 **표시**됩니다.

![알려진 변경을 통한 검색 - 알 수 없는 값, 알려진 변경: 선택한 방식으로 변경된 모든 값이 표시됩니다](<../../images/image (569).png>)

값을 찾았다면 이를 수정할 수 있습니다.

가능한 **변경 유형**은 **매우 많으며**, 결과를 필터링하기 위해 이 **단계**를 원하는 만큼 반복할 수 있습니다.

![알려진 변경을 통한 검색 - 알 수 없는 값, 알려진 변경: 가능한 변경 유형은 매우 많으며, 결과를 필터링하기 위해 이 단계를 원하는 만큼 반복할 수 있습니다](<../../images/image (574).png>)

### 무작위 메모리 주소 - 코드 찾기

지금까지는 값을 저장하는 주소를 찾는 방법을 배웠지만, **게임을 실행할 때마다 해당 주소가 메모리의 서로 다른 위치에 있을 가능성이 매우 높습니다**. 따라서 항상 해당 주소를 찾는 방법을 알아보겠습니다.

앞에서 언급한 방법 중 하나를 사용하여 현재 게임이 중요한 값을 저장하는 주소를 찾습니다. 그런 다음(원한다면 게임을 중지한 상태에서) 찾은 **주소**를 **마우스 오른쪽 버튼으로 클릭**하고 "**Find out what accesses this address**" 또는 "**Find out what writes to this address**"를 선택합니다.

![알 수 없는 값, 알려진 변경 - 무작위 메모리 주소 - 코드 찾기: 앞에서 언급한 방법 중 하나를 사용하여 현재 게임이 중요한 값을 저장하는 주소를 찾습니다. 그런 다음...](<../../images/image (1067).png>)

**첫 번째 옵션**은 어떤 **코드 부분**이 이 **주소**를 **사용하는지** 알아내는 데 유용합니다(게임의 **코드를 수정할 수 있는 위치를 파악하는 것**과 같은 다른 작업에도 유용합니다).\
**두 번째 옵션**은 더 **구체적**이며, 이 경우에는 **이 값이 어디에서 기록되는지** 알아내는 것이 목적이므로 더 유용합니다.

이 옵션 중 하나를 선택하면 **debugger**가 프로그램에 **연결**되고 새로운 **빈 창**이 나타납니다. 이제 **게임을 플레이**하면서 해당 **값을 변경**합니다(게임을 다시 시작하지 마십시오). 그러면 **값을 변경하는 주소**로 **창이 채워집니다**.

![알 수 없는 값, 알려진 변경 - 무작위 메모리 주소 - 코드 찾기: 이 옵션 중 하나를 선택하면 debugger가 프로그램에 연결되고 새로운 빈 창이 나타납니다. 이제...](<../../images/image (91).png>)

이제 값을 변경하는 주소를 찾았으므로 원하는 대로 **코드를 수정**할 수 있습니다(Cheat Engine을 사용하면 NOP로 매우 빠르게 수정할 수 있습니다).

![알 수 없는 값, 알려진 변경 - 무작위 메모리 주소 - 코드 찾기: 이제 값을 변경하는 주소를 찾았으므로 원하는 대로 코드를 수정할 수 있습니다(Cheat Engine...](<../../images/image (1057).png>)

이제 코드가 해당 숫자에 영향을 주지 않도록 하거나 항상 긍정적인 방향으로 영향을 주도록 수정할 수 있습니다.

### 무작위 메모리 주소 - 포인터 찾기

앞의 단계를 따라 관심 있는 값이 저장된 위치를 찾습니다. 그런 다음 "**Find out what writes to this address**"를 사용하여 이 값을 기록하는 주소를 찾고, 해당 주소를 더블 클릭하여 disassembly view를 엽니다.

![무작위 메모리 주소 - 코드 찾기 - 무작위 메모리 주소 - 포인터 찾기: 앞의 단계를 따라 관심 있는 값이 저장된 위치를 찾습니다. 그런 다음 " Find out...](<../../images/image (1039).png>)

그런 다음 **"\[]" 사이에 있는 hex 값**($edx의 값)을 **검색**하여 새로운 scan을 수행합니다.

![무작위 메모리 주소 - 코드 찾기 - 무작위 메모리 주소 - 포인터 찾기: 그런 다음 " ()" 사이에 있는 hex 값을 검색하여 새로운 scan을 수행합니다($edx의 값)](<../../images/image (994).png>)

(_여러 개가 나타나면 일반적으로 주소가 가장 작은 항목이 필요합니다_)\
이제 **관심 있는 값을 변경할 포인터를 찾았습니다**.

"**Add Address Manually**"를 클릭합니다.

![무작위 메모리 주소 - 코드 찾기 - 무작위 메모리 주소 - 포인터 찾기: " Add Address Manually "를 클릭합니다](<../../images/image (990).png>)

이제 "Pointer" 체크 박스를 클릭하고 텍스트 상자에 찾은 주소를 입력합니다(이 경우 이전 이미지에서 찾은 주소는 "Tutorial-i386.exe"+2426B0이었습니다).

![무작위 메모리 주소 - 코드 찾기 - 무작위 메모리 주소 - 포인터 찾기: "Pointer" 체크 박스를 클릭하고 텍스트 상자에 찾은 주소를 입력합니다(이 경우...](<../../images/image (392).png>)

(입력한 포인터 주소를 기반으로 첫 번째 "Address"가 자동으로 채워지는 것을 확인할 수 있습니다.)

OK를 클릭하면 새 포인터가 생성됩니다.

![무작위 메모리 주소 - 코드 찾기 - 무작위 메모리 주소 - 포인터 찾기: OK를 클릭하면 새 포인터가 생성됩니다](<../../images/image (308).png>)

이제부터는 값이 저장된 메모리 주소가 달라지더라도 해당 값을 수정할 때마다 **중요한 값을 수정**하게 됩니다.

### Code Injection

Code injection은 대상 프로세스에 코드 일부를 주입한 다음 코드의 실행 흐름을 우회하여 직접 작성한 코드를 거치게 하는 기법입니다(예: 생명력을 차감하는 대신 점수를 추가하는 경우).

플레이어의 생명력을 1만큼 감소시키는 주소를 찾았다고 가정해 보겠습니다.

![무작위 메모리 주소 - 포인터 찾기 - Code Injection: 플레이어의 생명력을 1만큼 감소시키는 주소를 찾았다고 가정해 보겠습니다](<../../images/image (203).png>)

Show disassembler를 클릭하여 **disassemble code**를 확인합니다.\
그런 다음 **CTRL+a**를 클릭하여 Auto assemble 창을 열고 _**Template --> Code Injection**_을 선택합니다.

![무작위 메모리 주소 - 포인터 찾기 - Code Injection: 그런 다음 CTRL+a를 클릭하여 Auto assemble 창을 열고 Template -- Code Injection을 선택합니다](<../../images/image (902).png>)

**수정하려는 instruction의 주소**를 입력합니다(일반적으로 자동으로 입력됩니다).

![무작위 메모리 주소 - 포인터 찾기 - Code Injection: 수정하려는 instruction의 주소를 입력합니다(일반적으로 자동으로 입력됩니다)](<../../images/image (744).png>)

template이 생성됩니다.

![무작위 메모리 주소 - 포인터 찾기 - Code Injection: template이 생성됩니다](<../../images/image (944).png>)

이제 "**newmem**" 섹션에 새로운 assembly code를 삽입하고, 원래 코드가 실행되는 것을 원하지 않는다면 "**originalcode**"에서 원래 코드를 제거합니다**.** 이 예제에서는 주입된 코드가 1을 빼는 대신 2점을 추가합니다.

![무작위 메모리 주소 - 포인터 찾기 - Code Injection: 이제 " newmem " 섹션에 새로운 assembly code를 삽입하고, 원래 코드가 실행되는 것을 원하지 않는다면 " originalcode "에서 원래 코드를 제거합니다...](<../../images/image (521).png>)

**execute 등을 클릭하면 프로그램에 코드가 주입되어 해당 기능의 동작이 변경됩니다!**

## Relocation-safe code injection with AOB signatures

`game.exe+123456`를 hook하는 script는 ASLR 또는 software update 이후에 중단될 수 있습니다. **Array of Bytes (AOB) signature**는 주변 machine code를 기반으로 instruction을 찾습니다. 검색을 하나의 module로 제한하려면 `aobscanmodule`을 사용합니다. 하나의 match만 반환하도록 signature를 충분히 길게 작성합니다. relocation bytes, addresses 및 변경될 수 있는 기타 bytes에는 wildcard를 사용합니다. 복원해야 하는 instruction 전체에 wildcard를 사용하지 마십시오.<sup>[[4]](#references)</sup>

Memory View에서 instruction을 선택하고 **Tools → Auto Assemble → Template → AOB Injection**을 사용합니다. 생성된 `[DISABLE]` block이 중요합니다. 덮어쓴 모든 byte를 복원하고 allocation을 해제해야 합니다.<sup>[[4]](#references)</sup>

<details>
<summary>Minimal x64 AOB injection skeleton</summary>
```asm
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 A0 00 00 00 48 8B)
alloc(newmem,1024,INJECT)
label(return)
registersymbol(INJECT)
newmem:
movss [rbx+000000A0],xmm0
jmp return
INJECT:
jmp newmem
nop
nop
nop
return:
[DISABLE]
INJECT:
db F3 0F 11 83 A0 00 00 00
unregistersymbol(INJECT)
dealloc(newmem)
```
</details>

스크립트를 활성화하기 전에 다음 사항을 확인하세요.

1. AOB가 **하나의** 주소를 반환하는지 확인하세요. 여러 주소를 반환하면 양쪽에 안정적인 instruction을 추가하세요.
2. 점프가 완전한 instruction을 대체하는지 확인하세요. instruction을 절대 분할하지 마세요.
3. 할당된 cave에 생성된 점프로 도달할 수 있는지 확인하세요. x64에서는 원거리 할당에 14바이트 점프가 필요할 수 있습니다.
4. 주입된 코드가 원래 함수가 요구하는 registers, flags 및 stack alignment를 보존하는지 확인하세요.
5. disable block이 정확한 원본 bytes를 복원하는지 확인하세요. 테이블을 저장하기 전에 enable과 disable을 여러 번 테스트하세요.

## 신뢰할 수 있는 pointer workflow

한 번의 실행에서 찾은 pointer는 후보일 뿐입니다. 여러 번의 새로운 실행에서 pointer map을 만들고, 모든 실행 결과를 대상으로 rescan하세요. 캡처 사이에 target을 재시작하여 ASLR과 heap 할당이 변경되도록 하세요. base가 module 또는 다른 안정적인 symbol인 경로를 우선하세요. 하나의 save, level 또는 object instance에서만 작동하는 경로는 제외하세요.

**pointer must end with specific offsets** filter와 해당 deviation 옵션을 사용하면 build 간에 인접한 field가 이동할 때 유용한 경로를 유지할 수 있습니다. 7.5 release에서도 이 deviation control이 추가되었습니다. 이것은 filter일 뿐이며 pointer chain이 안정적이라는 증거는 아닙니다.<sup>[[1]](#references)</sup>

pointer scanning을 수행하기에는 structure가 너무 자주 이동한다면 해당 structure에 액세스하는 instruction을 hook하세요. register의 live object pointer를 allocated symbol에 캡처하세요. 이는 entity list와 managed object에 특히 더 안정적인 경우가 많습니다.

## 값을 scanning하는 대신 code tracing하기

값이 직접 수정될 때는 **Find out what writes to this address**를 사용하세요. 소유 object가 필요하거나 write가 copied data를 통해 발생할 때는 **Find out what accesses this address**를 사용하세요. target에서 한 번에 하나의 action만 실행하세요. 그런 다음 hit count와 register state를 비교하세요.

**Ultimap 2**는 지원되는 Intel CPU에서 Intel Processor Trace를 사용합니다. 모든 instruction을 하나씩 stepping하는 것보다 적은 중단으로 실행된 control flow를 기록합니다. 관심 있는 action이 발생하는 동안 실행된 code를 filter하고, idle capture 중에도 실행된 code를 제거하세요. Intel PT는 stealth feature가 아닙니다. target은 tracing, timing changes 또는 Cheat Engine 자체를 여전히 감지할 수 있습니다.<sup>[[1]](#references)</sup>

Cheat Engine 7.5에는 Windows가 제공하는 Intel PT interface도 추가되었습니다. 이전의 DBVM 기반 Ultimap mode와 Intel PT mode는 hardware 및 OS 요구 사항이 서로 다릅니다. DBVM을 지원하는 CPU가 Intel PT도 지원한다고 가정하지 마세요.<sup>[[1]](#references)</sup>

## Debugger 및 breakpoint 선택

작동하는 것 중 가장 개입이 적은 debugger를 선택하세요.

- **Windows debugger**는 간단하지만 일반적인 debug event를 생성합니다. Anti-debugging check가 이를 감지할 수 있습니다.
- **VEH debugger**는 vectored exception handler를 통해 breakpoint를 처리합니다. 일부 기본적인 debugger check를 피할 수 있지만 보이지 않는 것은 아닙니다.
- **Hardware breakpoint**는 instruction bytes를 patch하지 않지만, x86/x64는 사용할 수 있는 debug-register slot 수가 적습니다.
- **Software breakpoint**는 한 바이트를 `INT3`로 대체합니다. 쉽게 감지될 수 있으며 integrity check와 충돌할 수 있습니다.
- **DBVM debugger**는 일부 작업을 guest OS보다 낮은 계층으로 이동합니다. 훨씬 더 높은 privilege를 가지며 잘못 구성하면 host가 crash할 수 있습니다.

Cheat Engine 7.5는 일반적인 relative jump를 사용할 공간이 충분하지 않을 때 exception handler와 `INT3`를 기반으로 하는 1바이트 jump를 사용할 수 있습니다. 이를 software breakpoint처럼 취급하세요. exception flow를 확인하고 이것이 anti-tamper check를 우회한다고 가정하지 마세요.<sup>[[1]](#references)</sup>

DBVM은 hypervisor이지 일반적인 invisibility switch가 아닙니다. 폐기 가능한 lab에서만 사용하세요. control interface를 신뢰할 수 없는 code에 노출하지 마세요. Kernel anti-cheat 및 endpoint product는 여전히 driver, hypervisor state 또는 수정된 memory를 감지할 수 있습니다.

## Managed runtime 및 최신 7.6/7.7 기능

Mono, IL2CPP, .NET 및 Java target에서는 사용 가능한 경우 blind scan보다 runtime metadata를 우선하세요. **Mono → Activate mono features** 또는 이에 해당하는 runtime information window를 여세요. 먼저 class, field 또는 method를 찾으세요. 그런 다음 managed method가 JIT-compiled될 때 native disassembly를 사용하세요.

7.6 line에는 executable-memory-only signature를 위한 `AOBSCANEX`, `gdbserver` debugger interface, Java metadata inspection, 더 빠른 IL2CPP enumeration 및 ARM memory tagging에서 사용되는 상위 pointer byte를 무시하는 pointer-scan 옵션이 추가되었습니다. 7.7 line에는 native Linux build, `HOOK`/`UNHOOK`, `aobscanfunction`, 향상된 generic Mono method lookup, 개선된 PDB structure support 및 기본적인 Unreal Engine structure dissection이 추가되었습니다.<sup>[[3]](#references)</sup>

이러한 추가 기능을 사용하면 다음과 같은 workflow가 가능합니다.

1. metadata에서 managed method 또는 static field를 resolve합니다.
2. 해당 method에서 생성된 native code를 trace하거나 disassemble합니다.
3. 안정적인 executable signature를 찾기 위해 `AOBSCANEX` 또는 `aobscanfunction`을 사용합니다.
4. 되돌릴 수 있는 hook을 생성합니다. 원본 instruction을 유지하고 disable path를 검증하세요.
5. target을 업데이트할 때마다 signature를 다시 확인하세요. 성공적인 match가 주변 logic도 여전히 같은 의미를 가진다는 것을 보장하지는 않습니다.

## `ceserver`를 사용하는 Remote target

`ceserver`는 Cheat Engine GUI에 process enumeration, memory access 및 debugging 기능을 제공합니다. 공식 build는 Linux와 Android를 지원합니다. target에서 일치하는 architecture를 실행하고 **Network** tab을 통해 연결하세요. Android에서는 기본 port를 forwarding하면 network에 이를 노출하지 않고 사용할 수 있습니다.<sup>[[3]](#references)</sup>
```bash
adb push ceserver_arm64 /data/local/tmp/ceserver
adb shell 'su -c "chmod 700 /data/local/tmp/ceserver && /data/local/tmp/ceserver"'
adb forward tcp:52736 tcp:52736
```
타사 `frida-ceserver` bridge는 iOS targets에 Cheat Engine 호환 interface를 제공할 수 있습니다. 이는 공식 `ceserver`가 아니며 지원되는 operations가 다를 수 있습니다.<sup>[[2]](#references)</sup>

protocol이 debugger-level access를 부여한다고 가정하세요. loopback에 bind하거나 SSH/ADB tunnel 뒤에 배치하세요. TCP 52736을 신뢰할 수 없는 network에 절대 노출하지 마세요. session이 끝나면 server를 중지하세요.

## Operational safety

소유하고 있거나 테스트 권한을 부여받은 software에만 attach하세요. online game 또는 production endpoint 옆에서 Cheat Engine을 실행하지 마세요. Memory writes, injected code, drivers 및 DBVM은 target을 crash시키거나 손상시킬 수 있습니다.<sup>[[3]](#references)</sup>

공식 site에서 builds를 download하거나 공개된 source를 compile하세요. Security products는 memory editors, debuggers 및 해당 drivers를 hack tools로 분류하는 경우가 많습니다. host protection을 전역적으로 비활성화하지 마세요. 전용 VM 또는 lab host를 사용하고 실행하기 전에 artifact를 검증하세요.<sup>[[3]](#references)</sup>



## References

- [1] [Cheat Engine 7.5 릴리스 노트](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [remote targets용 frida-ceserver bridge](https://github.com/gmh5225/frida-ceserver)
- [3] [Cheat Engine 공식 릴리스 소식](https://www.cheatengine.org/)
- [4] [Cheat Engine Wiki: Auto Assembler AOBs](https://wiki.cheatengine.org/index.php?title=Tutorials:AOBs)
{{#include ../../banners/hacktricks-training.md}}
