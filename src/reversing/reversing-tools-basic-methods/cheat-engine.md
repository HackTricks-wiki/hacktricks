# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)는 실행 중인 게임의 메모리 내부에서 중요한 값이 저장된 위치를 찾고 이를 변경하는 데 유용한 프로그램입니다.\
다운로드하고 실행하면 도구 사용법에 대한 **tutorial**이 **표시됩니다**. 도구 사용법을 배우고 싶다면 이를 완료하는 것이 매우 권장됩니다.<sup>[[3]](#references)</sup>

## 무엇을 검색하고 있나요?

![Cheat Engine - 무엇을 검색하고 있나요?: 무엇을 검색하고 있나요?](<../../images/image (762).png>)

이 도구는 프로그램의 메모리에 **특정 값**(일반적으로 숫자)이 **저장된 위치**를 찾는 데 매우 유용합니다.\
**일반적으로 숫자**는 **4bytes** 형식으로 저장되지만, **double** 또는 **float** 형식에서도 찾을 수 있으며, **숫자와 다른 값**을 찾고 싶을 수도 있습니다. 따라서 무엇을 **검색할지** 확실히 **선택**해야 합니다:

![Cheat Engine - 무엇을 검색하고 있나요?: 일반적으로 숫자는 4bytes 형식으로 저장되지만, double 또는 float 형식에서도 찾을 수 있으며, 숫자와 다른 것을 검색하고 싶을 수도 있습니다...](<../../images/image (324).png>)

또한 **검색**의 **유형**을 **다르게** 지정할 수 있습니다:

![Cheat Engine - 무엇을 검색하고 있나요?: 또한 검색 유형을 다르게 지정할 수 있습니다](<../../images/image (311).png>)

메모리를 스캔하는 동안 **게임을 일시 중지**하도록 확인란을 선택할 수도 있습니다:

![Cheat Engine - 무엇을 검색하고 있나요?: 메모리를 스캔하는 동안 게임을 일시 중지할 수도 있습니다](<../../images/image (1052).png>)

### Hotkeys

_**Edit --> Settings --> Hotkeys**_에서 **게임을 일시 중지**하는 등의 다양한 용도에 사용할 **hotkeys**를 설정할 수 있습니다. 이는 메모리를 스캔하려는 경우에 매우 유용합니다. 다른 옵션도 제공됩니다:

![무엇을 검색하고 있나요? - Hotkeys: Edit -- Settings -- Hotkeys에서 게임을 일시 중지하는 등의 다양한 용도에 사용할 hotkeys를 설정할 수 있습니다](<../../images/image (864).png>)

## 값 수정

찾고 있던 **값**이 저장된 위치를 **찾았다면**(자세한 내용은 다음 단계에서 설명) 해당 항목을 더블 클릭한 다음 값 자체를 더블 클릭하여 **수정**할 수 있습니다:

![Hotkeys - 값 수정: 찾고 있던 값이 저장된 위치를 찾았다면(자세한 내용은 다음 단계에서 설명) 해당 항목을 더블 클릭한 다음...](<../../images/image (563).png>)

마지막으로 **확인란을 선택**하면 메모리에 수정 사항이 적용됩니다:

![Hotkeys - 값 수정: 마지막으로 확인란을 선택하면 메모리에 수정 사항이 적용됩니다](<../../images/image (385).png>)

메모리에 대한 **변경 사항**은 즉시 **적용**됩니다(게임이 이 값을 다시 사용할 때까지는 게임 내 값이 **업데이트되지 않는다**는 점에 유의하세요).

## 값 검색

이제 개선하고 싶은 중요한 값(예: 사용자 캐릭터의 생명력)이 있고, 메모리에서 이 값을 찾고 있다고 가정하겠습니다.

### 알려진 변경을 통한 검색

100이라는 값을 찾는다고 가정하면 해당 값을 검색하여 **scan**을 수행하고 많은 일치 항목을 찾게 됩니다:

![값 검색 - 알려진 변경을 통한 검색: 100이라는 값을 찾는다고 가정하면 해당 값을 검색하여 scan을 수행하고 많은 일치 항목을 찾게 됩니다](<../../images/image (108).png>)

그런 다음 **값이 변경**되도록 동작을 수행하고, 게임을 **일시 중지**한 뒤 **next scan**을 수행합니다:

![값 검색 - 알려진 변경을 통한 검색: 그런 다음 값이 변경되도록 동작을 수행하고, 게임을 일시 중지한 뒤 next scan을 수행합니다](<../../images/image (684).png>)

Cheat Engine은 **100에서 새로운 값으로 변경된 값**을 검색합니다. 축하합니다. 찾고 있던 값의 **address**를 **찾았습니다**. 이제 이를 수정할 수 있습니다.\
_여전히 여러 값이 남아 있다면 해당 값을 다시 변경한 뒤 또 다른 "next scan"을 수행하여 주소를 필터링하세요._

### 알 수 없는 값, 알려진 변경

**값은 모르지만** **값을 어떻게 변경할지**(변경량까지) 알고 있는 상황에서도 해당 값을 검색할 수 있습니다.

먼저 "**Unknown initial value**" 유형으로 scan을 수행합니다:

![알려진 변경을 통한 검색 - 알 수 없는 값, 알려진 변경: 먼저 " Unknown initial value " 유형으로 scan을 수행합니다](<../../images/image (890).png>)

그런 다음 값을 변경하고 **값이 어떻게 변경되었는지** 지정합니다(이 경우에는 1만큼 감소했습니다). 그리고 **next scan**을 수행합니다:

![알려진 변경을 통한 검색 - 알 수 없는 값, 알려진 변경: 그런 다음 값을 변경하고 값이 어떻게 변경되었는지 지정한 뒤(이 경우에는 1만큼 감소했습니다) next scan을 수행합니다](<../../images/image (371).png>)

선택한 방식으로 **변경된 모든 값**이 **표시됩니다**:

![알려진 변경을 통한 검색 - 알 수 없는 값, 알려진 변경: 선택한 방식으로 변경된 모든 값이 표시됩니다](<../../images/image (569).png>)

값을 찾았다면 수정할 수 있습니다.

가능한 **변경 유형**은 매우 많으며, 결과를 필터링하기 위해 이 **단계들을 원하는 만큼 반복**할 수 있습니다:

![알려진 변경을 통한 검색 - 알 수 없는 값, 알려진 변경: 가능한 변경 유형은 매우 많으며 결과를 필터링하기 위해 이 단계들을 원하는 만큼 반복할 수 있습니다](<../../images/image (574).png>)

### Random Memory Address - Finding the code

지금까지는 값을 저장하는 address를 찾는 방법을 배웠지만, **게임을 실행할 때마다 해당 address가 메모리의 서로 다른 위치에 있을 가능성이 매우 높습니다**. 이제 항상 해당 address를 찾는 방법을 알아보겠습니다.

앞서 언급한 방법 중 하나를 사용하여 현재 게임이 중요한 값을 저장하는 address를 찾습니다. 그런 다음(원한다면 게임을 일시 중지한 상태에서) 찾은 **address**를 **right click**하고 "**Find out what accesses this address**" 또는 "**Find out what writes to this address**"를 선택합니다:

![알 수 없는 값, 알려진 변경 - Random Memory Address - Finding the code: 앞서 언급한 방법 중 하나를 사용하여 현재 게임이 중요한 값을 저장하는 address를 찾습니다. 그런 다음...](<../../images/image (1067).png>)

**첫 번째 옵션**은 이 **address**를 **사용하는** **code**의 **부분**을 파악하는 데 유용합니다(게임의 **code를 어디에서 수정할 수 있는지 파악**하는 등 다른 용도에도 유용합니다).\
**두 번째 옵션**은 더 **구체적**이며, 이 경우에는 **이 값이 어디에서 기록되는지** 파악하는 것이 목적이므로 더 유용합니다.

이 옵션 중 하나를 선택하면 **debugger**가 프로그램에 **연결**되고 새로운 **빈 창**이 나타납니다. 이제 **게임을 플레이**하면서 해당 **값을 변경**합니다(게임을 재시작하지 마세요). 그러면 **값을 변경하는 address**로 **창이 채워집니다**:

![알 수 없는 값, 알려진 변경 - Random Memory Address - Finding the code: 이 옵션 중 하나를 선택하면 debugger가 프로그램에 연결되고 새로운 빈 창이 나타납니다...](<../../images/image (91).png>)

이제 값을 변경하는 address를 찾았으므로 원하는 대로 **code를 수정**할 수 있습니다(Cheat Engine을 사용하면 NOPs로 매우 빠르게 수정할 수 있습니다):

![알 수 없는 값, 알려진 변경 - Random Memory Address - Finding the code: 이제 값을 변경하는 address를 찾았으므로 원하는 대로 code를 수정할 수 있습니다(Cheat Engine...](<../../images/image (1057).png>)

이제 code가 해당 숫자에 영향을 주지 않도록 수정하거나, 항상 긍정적인 방향으로 영향을 주도록 수정할 수 있습니다.

### Random Memory Address - Finding the pointer

이전 단계를 따라 관심 있는 값이 저장된 위치를 찾습니다. 그런 다음 "**Find out what writes to this address**"를 사용하여 이 값을 기록하는 address를 찾고, 이를 더블 클릭하여 disassembly view를 엽니다:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: 이전 단계를 따라 관심 있는 값이 저장된 위치를 찾습니다. 그런 다음 " Find out...](<../../images/image (1039).png>)

그런 다음 **"\[]" 사이에 있는 hex 값**을 **검색**하여 새로운 scan을 수행합니다(이 경우 $edx의 값):

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: 그런 다음 " ()" 사이에 있는 hex 값을 검색하여 새로운 scan을 수행합니다(이 경우 $edx의 값)](<../../images/image (994).png>)

(_여러 개가 나타나면 일반적으로 가장 작은 address를 사용해야 합니다_)\
이제 **관심 있는 값을 수정할 pointer를 찾았습니다**.

"**Add Address Manually**"를 클릭합니다:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: " Add Address Manually "를 클릭합니다](<../../images/image (990).png>)

이제 "Pointer" 확인란을 클릭하고 텍스트 상자에 찾은 address를 입력합니다(이 시나리오에서는 이전 이미지에서 찾은 address가 "Tutorial-i386.exe"+2426B0이었습니다):

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: 이제 "Pointer" 확인란을 클릭하고 텍스트 상자에 찾은 address를 입력합니다(이 시나리오에서는...](<../../images/image (392).png>)

(입력한 pointer address를 기준으로 첫 번째 "Address"가 자동으로 채워지는 것을 확인할 수 있습니다.)

OK를 클릭하면 새로운 pointer가 생성됩니다:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: OK를 클릭하면 새로운 pointer가 생성됩니다](<../../images/image (308).png>)

이제부터 해당 값을 수정할 때마다 **값이 저장된 memory address가 달라지더라도 중요한 값을 수정**하게 됩니다.

### Code Injection

Code injection은 target process에 code 일부를 주입한 다음 code 실행 흐름을 자신이 작성한 code를 거치도록 변경하는 technique입니다(생명을 차감하는 대신 점수를 추가하는 것과 같습니다).

플레이어의 생명력을 1만큼 차감하는 address를 찾았다고 가정해 보겠습니다:

![Random Memory Address - Finding the pointer - Code Injection: 플레이어의 생명력을 1만큼 차감하는 address를 찾았다고 가정해 보겠습니다](<../../images/image (203).png>)

Show disassembler를 클릭하여 **disassemble code**를 확인합니다.\
그런 다음 **CTRL+a**를 눌러 Auto assemble 창을 열고 _**Template --> Code Injection**_을 선택합니다.

![Random Memory Address - Finding the pointer - Code Injection: 그런 다음 CTRL+a를 눌러 Auto assemble 창을 열고 Template -- Code Injection을 선택합니다](<../../images/image (902).png>)

**수정하려는 instruction의 address**를 입력합니다(일반적으로 자동으로 입력됩니다):

![Random Memory Address - Finding the pointer - Code Injection: 수정하려는 instruction의 address를 입력합니다(일반적으로 자동으로 입력됩니다)](<../../images/image (744).png>)

template이 생성됩니다:

![Random Memory Address - Finding the pointer - Code Injection: template이 생성됩니다](<../../images/image (944).png>)

이제 "**newmem**" 섹션에 새로운 assembly code를 삽입하고, 원래 code를 실행하지 않으려면 "**originalcode**"에서 원래 code를 제거합니다**.** 이 예제에서는 주입된 code가 1을 차감하는 대신 2점을 추가합니다:

![Random Memory Address - Finding the pointer - Code Injection: 이제 " newmem " 섹션에 새로운 assembly code를 삽입하고, 원래 code를 실행하지 않으려면 " originalcode "에서 원래 code를 제거합니다...](<../../images/image (521).png>)

**execute 등을 클릭하면 code가 프로그램에 주입되어 해당 기능의 동작이 변경됩니다!**

## Cheat Engine 7.x의 Advanced features (2023-2025)

Cheat Engine은 version 7.0 이후에도 계속 발전했으며, modern software를 분석할 때(게임뿐만 아니라) 매우 유용한 여러 quality-of-life 및 *offensive-reversing* features가 추가되었습니다. 아래는 red-team/CTF 작업에서 가장 자주 사용하게 될 기능을 간단히 정리한 **field guide**입니다.<sup>[[1]](#references)</sup>

### Pointer Scanner 2 improvements
* `Pointers must end with specific offsets` 및 새로운 **Deviation** slider(≥7.4)는 update 후 rescan할 때 false positives를 크게 줄여 줍니다. 이를 multi-map comparison(`.PTR` → *Compare results with other saved pointer map*)과 함께 사용하면 단 몇 분 만에 **하나의 견고한 base-pointer**를 얻을 수 있습니다.
* Bulk-filter shortcut: 첫 번째 scan 후 `Ctrl+A → Space`를 눌러 모두 mark한 다음, `Ctrl+I`(invert)를 눌러 rescan에 실패한 address를 deselect합니다.

### Ultimap 3 – Intel PT tracing
*7.5부터 기존 Ultimap은 **Intel Processor-Trace (IPT)**를 기반으로 다시 구현되었습니다.* 따라서 이제 **single-stepping 없이** target이 수행하는 *모든 branch*를 기록할 수 있습니다(user-mode 전용이며 대부분의 anti-debug gadget을 발생시키지 않습니다).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
몇 초 후 capture를 중지하고 **right-click → Save execution list to file**을 선택합니다. branch address를 `Find out what addresses this instruction accesses` session과 결합하면 high-frequency game-logic hotspot을 매우 빠르게 찾을 수 있습니다.

### 1-byte `jmp` / auto-patch templates
Version 7.5에서는 SEH handler를 설치하고 원래 위치에 INT3을 배치하는 *one-byte* JMP stub (0xEB)이 도입되었습니다. 5-byte relative jump로 patch할 수 없는 instruction에서 **Auto Assembler → Template → Code Injection**을 사용하면 자동으로 생성됩니다. 이를 통해 packed 또는 size-constrained routine 내부에서도 “tight” hook을 사용할 수 있습니다.

### DBVM을 사용한 kernel-level stealth (AMD & Intel)
*DBVM*은 CE에 내장된 Type-2 hypervisor입니다. 최근 build에서는 마침내 **AMD-V/SVM support**가 추가되어 Ryzen/EPYC host에서 `Driver → Load DBVM`을 실행할 수 있습니다. DBVM을 사용하면 다음 작업이 가능합니다.

1. Ring-3/anti-debug check에서 보이지 않는 hardware breakpoint를 생성합니다.
2. user-mode driver가 비활성화된 경우에도 pageable 또는 protected kernel memory region을 읽고 씁니다.
3. VM-EXIT-less timing-attack bypass를 수행합니다(예: hypervisor에서 `rdtsc` query).

**Tip:** Windows 11에서 HVCI/Memory-Integrity가 활성화되어 있으면 DBVM은 load를 거부합니다 → 이를 끄거나 전용 VM-host로 boot합니다.

### **ceserver**를 사용한 Remote / cross-platform debugging
CE에는 이제 *ceserver*가 완전히 rewrite되어 포함되어 있으며, TCP를 통해 **Linux, Android, macOS & iOS** target에 attach할 수 있습니다. 한 인기 fork는 *Frida*를 통합하여 dynamic instrumentation과 CE의 GUI를 결합합니다. 따라서 phone에서 실행되는 Unity 또는 Unreal game을 patch해야 할 때 이상적입니다:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Frida bridge는 GitHub의 `bb33bb/frida-ceserver`를 참조하세요.<sup>[[2]](#references)</sup>

### 주목할 만한 기타 기능
* **Patch Scanner** (MemView → Tools) – 실행 가능한 섹션에서 예상치 못한 코드 변경을 탐지하며, malware analysis에 유용합니다.
* **Structure Dissector 2** – 주소를 드래그한 후 → `Ctrl+D`를 누르고, *Guess fields*를 선택하면 C-structures를 자동으로 평가합니다.
* **.NET & Mono Dissector** – Unity game 지원이 향상되었으며, CE Lua console에서 직접 메서드를 호출할 수 있습니다.
* **Big-Endian custom types** – 바이트 순서를 반전하여 scan/edit할 수 있습니다(console emulators 및 network packet buffers에 유용).
* AutoAssembler/Lua windows의 **Autosave & tabs**와 여러 줄 instruction을 다시 작성할 수 있는 `reassemble()`.

### Installation & OPSEC 참고 사항 (2024-2025)
* 공식 installer에는 InnoSetup **ad-offers** (`RAV` 등)가 포함되어 있습니다. PUPs를 피하려면 **항상 *Decline*을 클릭**하거나 *source에서 compile*하세요. AVs는 여전히 `cheatengine.exe`를 *HackTool*로 탐지하지만, 이는 예상된 동작입니다.
* 최신 anti-cheat drivers (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys)는 이름을 변경해도 CE의 window class를 탐지합니다. reversing copy는 **disposable VM 내부** 또는 network play를 비활성화한 후 실행하세요.
* user-mode access만 필요한 경우, Windows 11 24H2 Secure-Boot에서 BSOD를 일으킬 수 있는 CE의 unsigned driver가 로드되지 않도록 **`Settings → Extra → Kernel mode debug = off`**를 선택하세요.

---

## References

- [1] [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- [3] Cheat Engine tutorial, complete it to learn how to start with Cheat Engine

{{#include ../../banners/hacktricks-training.md}}
