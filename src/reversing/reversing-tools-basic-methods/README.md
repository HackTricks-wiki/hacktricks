# Reversing 도구 및 기본 방법

{{#include ../../banners/hacktricks-training.md}}

## ImGui 기반 Reversing 도구

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)을 사용하여 wasm (binary)에서 wat (clear text)로 **decompile**합니다.
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)을 사용하여 wat에서 wasm으로 **compile**합니다.
- decompilation에는 [web-wasmdec](https://wwwg.github.io/web-wasmdec/)도 사용해 볼 수 있습니다.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 cached bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek은 **libraries** (.dll), **Windows metadata file**s (.winmd), **executables** (.exe)를 포함한 여러 **formats**를 **decompile하고 검사**하는 decompiler입니다. decompile한 후 assembly를 Visual Studio project (.csproj)로 저장할 수 있습니다.

여기서의 장점은 손실된 source code를 legacy assembly에서 복원해야 하는 경우 이 작업으로 시간을 절약할 수 있다는 것입니다. 또한 dotPeek은 decompiled code 전체를 편리하게 탐색할 수 있도록 해 주므로 **Xamarin algorithm analysis**를 위한 완벽한 도구 중 하나입니다.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

도구를 정확한 요구 사항에 맞게 확장하는 comprehensive add-in model과 API를 갖춘 .NET reflector는 시간을 절약하고 development를 간소화합니다. 이 도구가 제공하는 다양한 reverse engineering services를 살펴보겠습니다.

- library 또는 component를 통해 data가 흐르는 방식을 파악할 수 있습니다.
- .NET languages 및 frameworks의 implementation과 usage를 파악할 수 있습니다.
- 사용 중인 APIs 및 technologies를 더 활용할 수 있도록 undocumented 및 unexposed functionality를 찾습니다.
- dependencies 및 서로 다른 assemblies를 찾습니다.
- code, third-party components 및 libraries에서 errors가 발생한 정확한 위치를 추적합니다.
- 작업 중인 모든 .NET code의 source를 debug합니다.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code용 ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode): 어떤 OS에서든 사용할 수 있습니다(VSCode에서 직접 설치할 수 있으므로 git을 다운로드할 필요가 없습니다. **Extensions**를 클릭하고 **ILSpy를 검색**하세요).\
**decompile**, **modify**한 후 다시 **recompile**해야 하는 경우 [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) 또는 현재 유지 관리되고 있는 fork인 [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)를 사용할 수 있습니다. (함수 내부의 내용을 변경하려면 **Right Click -> Modify Method**를 사용하세요.)

### DNSpy Logging

**DNSpy가 일부 정보를 파일에 log하도록** 하려면 다음 snippet을 사용할 수 있습니다.
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy 디버깅

DNSpy를 사용하여 code를 디버깅하려면 다음을 수행해야 합니다.

먼저 **Assembly attributes**에서 **debugging**과 관련된 항목을 변경합니다:

![DNSpy Logging - DNSpy 디버깅: 먼저 Assembly attributes에서 debugging과 관련된 항목을 변경합니다](<../../images/image (973).png>)

다음에서:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
수신:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
그리고 **compile**을 클릭합니다:

![DNSpy Logging - DNSpy Debugging: compile 클릭](<../../images/image (314) (1).png>)

그런 다음 _**File >> Save module...**_을 통해 새 파일을 저장합니다:

![DNSpy Logging - DNSpy Debugging: File Save module을 통한 새 파일 저장](<../../images/image (602).png>)

이 작업이 필요한 이유는 이렇게 하지 않으면 **runtime**에 코드에 여러 **optimisations**가 적용되어, 디버깅 중 **break-point가 절대 적중되지 않거나** 일부 **variables가 존재하지 않을** 수 있기 때문입니다.

그런 다음 .NET 애플리케이션이 **IIS**에 의해 **run** 중이라면 다음 명령으로 **restart**할 수 있습니다:
```
iisreset /noforce
```
그런 다음 debugging을 시작하려면 열려 있는 모든 파일을 닫고 **Debug Tab**에서 **Attach to Process...**를 선택합니다:

![DNSpy Logging - DNSpy Debugging: 그런 다음 debugging을 시작하려면 열려 있는 모든 파일을 닫고 Debug Tab에서 Attach to Process를 선택합니다](<../../images/image (318).png>)

그런 다음 **IIS server**에 attach할 **w3wp.exe**를 선택하고 **attach**를 클릭합니다:

![DNSpy Logging - DNSpy Debugging: 그런 다음 IIS server에 attach할 w3wp.exe를 선택하고 attach를 클릭합니다](<../../images/image (113).png>)

이제 process를 debugging하고 있으므로 이를 중지하고 모든 module을 load할 차례입니다. 먼저 _Debug >> Break All_을 클릭한 다음 _**Debug >> Windows >> Modules**_를 클릭합니다:

![DNSpy Logging - DNSpy Debugging: 이제 process를 debugging하고 있으므로 이를 중지하고 모든 module을 load할 차례입니다. 먼저 Debug Break All을 클릭한 다음 Debug Windows Modules를 클릭합니다](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: 이제 process를 debugging하고 있으므로 이를 중지하고 모든 module을 load할 차례입니다. 먼저 Debug Break All을 클릭한 다음 Debug Windows Modules를 클릭합니다](<../../images/image (834).png>)

**Modules**에서 아무 module이나 클릭하고 **Open All Modules**를 선택합니다:

![DNSpy Logging - DNSpy Debugging: Modules에서 아무 module이나 클릭하고 Open All Modules를 선택합니다](<../../images/image (922).png>)

**Assembly Explorer**에서 아무 module이나 마우스 오른쪽 버튼으로 클릭하고 **Sort Assemblies**를 클릭합니다:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer에서 아무 module이나 마우스 오른쪽 버튼으로 클릭하고 Sort Assemblies를 클릭합니다](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL debugging

### IDA 사용

- **rundll32 load** (64bits는 C:\Windows\System32\rundll32.exe에 있으며 32 bits는 C:\Windows\SysWOW64\rundll32.exe에 있음)
- **Windbg** debugger를 선택합니다.
- "**Suspend on library load/unload**"를 선택합니다.

![Debugging DLLs - Using IDA: " Suspend on library load/unload "를 선택합니다](<../../images/image (868).png>)

- 실행의 **parameters**를 설정하고 **DLL path**와 호출하려는 function을 입력합니다:

![Debugging DLLs - Using IDA: 실행의 parameters를 설정하고 DLL path와 호출하려는 function을 입력합니다](<../../images/image (704).png>)

그런 다음 debugging을 시작하면 **각 DLL이 load될 때 execution이 중지**됩니다. 따라서 rundll32가 사용자의 DLL을 load하면 execution이 중지됩니다.

이 방법은 module-load event에서 중지하지만, 아래의 x64dbg workflow보다 load된 DLL의 entry point에 도달하는 과정이 직접적이지 않습니다.

### x64dbg/x32dbg 사용

- **rundll32 load** (64bits는 C:\Windows\System32\rundll32.exe에 있으며 32 bits는 C:\Windows\SysWOW64\rundll32.exe에 있음)
- **Command Line 변경** ( _File --> Change Command Line_ ) 후 dll의 path와 호출하려는 function을 설정합니다. 예: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_를 변경하고 "**DLL Entry**"를 선택합니다.
- 그런 다음 **execution을 시작**하면 debugger가 각 dll main에서 중지됩니다. 어느 시점에 **사용자의 dll Entry에서 중지**됩니다. 그곳에서 breakpoint를 설정할 지점을 찾으면 됩니다.

win64dbg에서 어떤 이유로든 execution이 중지되면 **win64dbg window 상단**을 확인하여 **현재 어느 code에 있는지** 볼 수 있습니다:

![Using IDA - Using x64dbg/x32dbg: win64dbg에서 어떤 이유로든 execution이 중지되면 win64dbg window 상단에서 현재 어느 code를 보고 있는지 확인할 수 있습니다](<../../images/image (842).png>)

이 indicator를 통해 execution이 debugging하려는 DLL 내부에서 중지되었는지 확인할 수 있습니다.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)은 실행 중인 game의 memory 내부에 중요한 value가 저장된 위치를 찾고 이를 변경하는 데 유용한 program입니다. 자세한 정보는 다음을 참조하세요:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE)는 GNU Project Debugger (GDB)의 front-end/reverse engineering tool이며, game에 중점을 둡니다. 하지만 reverse-engineering과 관련된 어떤 작업에도 사용할 수 있습니다.

[**Decompiler Explorer**](https://dogbolt.org/)는 여러 decompiler를 위한 web front-end입니다. 이 web service를 사용하면 작은 executable에서 서로 다른 decompiler의 output을 비교할 수 있습니다.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner로 shellcode debugging

[**BlobRunner**](https://github.com/OALabs/BlobRunner)는 **shellcode**를 할당하고 **memory address**를 출력한 다음 execution을 일시 중지합니다.\
IDA 또는 x64dbg와 같은 debugger를 attach하고, 출력된 address에 breakpoint를 설정한 다음 execution을 재개하여 shellcode를 debugging합니다.

releases github page에는 compiled release가 포함된 zip 파일이 있습니다: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
다음 link에서 약간 수정된 Blobrunner version을 찾을 수 있습니다. 이를 compile하려면 **Visual Studio Code에서 C/C++ project를 생성하고, code를 copy and paste한 다음 build하면** 됩니다.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it을 사용한 shellcode debugging

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)은 BlobRunner와 유사합니다. shellcode를 할당하고 infinite loop에 진입합니다. debugger를 attach하고 **2–5초 동안** resume한 다음, 해당 loop 내부에서 pause하고 execution을 할당된 shellcode로 전달하는 다음 call까지 step합니다.

![할당된 shellcode로의 call 직전에 jmp2it의 infinite loop에서 pause된 debugger](<../../images/image (509).png>)

compiled version의 [jmp2it releases page](https://github.com/adamkramer/jmp2it/releases/)에서 다운로드할 수 있습니다.

### Cutter를 사용한 shellcode debugging

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)는 radare의 GUI입니다. Cutter를 사용하면 shellcode를 emulate하고 이를 dynamically inspect할 수 있습니다.

Cutter에서는 "Open File"과 "Open Shellcode"를 사용할 수 있다는 점에 유의하세요. 제 경우 shellcode를 file로 열었을 때는 올바르게 decompile되었지만, shellcode로 열었을 때는 그렇지 않았습니다:

![동일한 bytes를 file 또는 shellcode로 열었을 때 서로 다른 analysis results를 보여주는 Cutter](<../../images/image (562).png>)

원하는 위치에서 emulation을 시작하려면 해당 위치에 bp를 설정하세요. 그러면 Cutter가 그 위치에서 자동으로 emulation을 시작하는 것으로 보입니다:

![Cutter emulation을 시작하기 전에 원하는 shellcode entry에 breakpoint를 설정](<../../images/image (589).png>)

![선택한 shellcode breakpoint에서 pause된 Cutter emulator](<../../images/image (387).png>)

예를 들어 hex dump 내부에서 stack을 볼 수 있습니다:

![Cutter의 hex dump에서 emulated shellcode stack을 확인](<../../images/image (186).png>)

### shellcode deobfuscating 및 executed function 확인

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)를 사용해 보세요.\
이 tool은 shellcode가 사용하는 **function이 무엇인지**, 그리고 shellcode가 memory에서 스스로 **decoding하는지**와 같은 정보를 알려줍니다.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg에는 원하는 옵션을 선택하고 shellcode를 실행할 수 있는 graphical launcher도 있습니다.

![shellcode emulation 및 tracing 옵션을 선택할 수 있는 scDbg graphical launcher](<../../images/image (258).png>)

**Create Dump** 옵션은 메모리에서 shellcode가 동적으로 변경된 경우 최종 shellcode를 dump합니다(디코딩된 shellcode를 다운로드할 때 유용합니다). **start offset**은 특정 offset에서 shellcode를 시작하는 데 유용할 수 있습니다. **Debug Shell** 옵션은 scDbg terminal을 사용해 shellcode를 debug하는 데 유용합니다(하지만 이 경우 앞에서 설명한 옵션 중 하나를 사용하는 것이 더 좋다고 생각합니다. Ida 또는 x64dbg를 사용할 수 있기 때문입니다).

### CyberChef를 사용한 Disassembling

shellcode 파일을 input으로 업로드하고 다음 recipe를 사용해 decompile합니다: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation은 arithmetic 연산(`+`, `-`, `*`)과 bitwise 연산자(`&`, `|`, `^`, `~`, shifts)를 혼합한 formula를 사용해 `x + y`와 같은 단순한 expression을 숨깁니다. 중요한 점은 이러한 identity가 일반적으로 **fixed-width modular arithmetic**에서만 올바르다는 것입니다. 따라서 carry와 overflow가 중요합니다:
```c
(x ^ y) + 2 * (x & y) == x + y
```
이러한 종류의 표현을 일반 algebra tooling으로 단순화하면 bit-width semantics가 무시되기 때문에 쉽게 잘못된 결과를 얻을 수 있습니다.<sup>[[1]](#references)</sup>

### 실용적인 workflow

1. lifted code/IR/decompiler output에서 **원래 bit-width**(`8/16/32/64` bits)를 유지합니다.
2. 단순화를 시도하기 전에 **표현식을 분류**합니다:
- **Linear**: bitwise atom의 가중 합
- **Semilinear**: `x & 0xFF`와 같은 상수 mask를 더한 linear
- **Polynomial**: 곱셈이 나타남
- **Mixed**: 곱셈과 bitwise logic가 interleave되며, 반복되는 subexpression이 자주 나타남
3. 모든 candidate rewrite를 random testing 또는 SMT proof로 **검증**합니다. equivalence를 증명할 수 없다면 추측하는 대신 원래 표현식을 유지합니다.

### 좁은 execution slice로 flattened control flow 우회

완전한 control-flow graph를 복구하는 작업은 불필요한 경우가 많습니다. control-flow flattening, opaque predicate, 대형 dispatcher 또는 MBA-heavy code가 있는 경우, encrypted blob과 output buffer에서 참조를 따라 이를 변환하는 가장 작은 routine까지 이동합니다. 그런 다음 해당 data-flow slice만 재현하거나 독립적으로 실행합니다. 관련 state를 직접 초기화할 수 있다면 dispatcher는 필요한 solution의 일부가 아닙니다.<sup>[[7]](#references)</sup>

실용적인 workflow는 다음과 같습니다:<sup>[[7]](#references)</sup>

1. executable 및 data section, relocation, cross-reference를 목록화합니다. byte order와 element width를 유지하면서 `.rodata`에서 candidate table을 dump합니다.
2. plaintext 또는 output buffer에 마지막으로 write하는 routine을 식별합니다. 해당 routine의 input, 참조하는 table, imported call 및 필요한 global state를 기록합니다.
3. 해당 operation만 fixed-width Python model로 lift합니다. slice가 여전히 너무 많은 state에 의존한다면 전체 program을 emulate하는 대신 Unicorn, QEMU 또는 debugger에서 routine을 invoke하고 관련 없는 import를 hook합니다.
4. extractor가 실제로 제공된 binary에서 output을 도출하는지 검증합니다. silent fallback을 제거하고, embedded answer를 검색하며, string, key, identifier, layout 및 obfuscation seed가 변경된 unseen build에서 실행합니다.

첫 번째 pass에서 유용한 command는 다음과 같습니다:<sup>[[7]](#references)</sup>
```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```
#### 상수로 위장된 MBA 표현식 감지

겉보기에는 입력에 의존하는 byte 표현식이 실제로는 입력을 완전히 상쇄할 수 있습니다. 해당 테이블을 추출한 후 전체 8-bit domain에서 표현식을 평가하세요. 출력 집합이 singleton이면 주변 state machine을 복구하지 않고도 해당 byte가 상수임을 증명할 수 있습니다.<sup>[[7]](#references)</sup>
```python
def mba(a, b, c, d, e, x):
return ((((a | (~x & 0xff)) & c) +
((x | b) & d)) ^ e) & 0xff

decoded = bytearray()
for row in zip(A, B, C, D, E):
outputs = {mba(*row, x) for x in range(256)}
if len(outputs) != 1:
raise ValueError("expression depends on x")
decoded.append(outputs.pop())
print(decoded)
```
최종 mask를 유지해야 합니다. 원래의 덧셈은 byte-width wraparound을 일으키기 때문입니다. 더 넓은 domain에서는 동일한 width의 symbolic input 두 개에 대해 `f(x1) != f(x2)`가 satisfiable한지 SMT solver에 질의하십시오. `unsat`이면 invariance가 증명되고, `sat`이면 counterexample이 제공되므로 해당 input을 제거할 수 없습니다.<sup>[[7]](#references)</sup>

#### 환경에 종속된 decoding 인식

Anti-analysis check는 반드시 분기하거나 crash를 발생시킬 필요가 없습니다. Decoder는 sensor result를 key bit, opaque-predicate constant 또는 flattened-dispatcher state에 섞은 뒤 정상적으로 계속 실행하면서 emulator에서 그럴듯하지만 잘못된 plaintext를 생성할 수 있습니다. 따라서 눈에 보이는 failure branch만 patch하는 것으로는 충분하지 않습니다. 환경 probe에서 decoder state로 이어지는 data dependency를 추적하고, authentic device와 emulator에서 동일한 slice를 비교하며, 각 sensor result를 강제로 변경했을 때 최종 buffer가 어떻게 달라지는지 테스트해야 합니다.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA)는 malware analysis 및 protected-binary reversing을 위한 실용적인 MBA simplifier입니다. 모든 항목에 하나의 generic rewrite pass를 적용하는 대신 expression을 분류하고 specialized pipeline으로 전달합니다.<sup>[[2]](#references)</sup>

간단한 사용법:
```bash
# Recover arithmetic from a logic-heavy MBA
cobra-cli --mba "(x&y)+(x|y)"
# x + y

# Preserve fixed-width wraparound semantics
cobra-cli --mba "(x&0xFF)+(x&0xFF00)" --bitwidth 16
# x

# Ask CoBRA to prove the rewrite with Z3
cobra-cli --mba "(a^b)+(a&b)+(a&b)" --verify
```
유용한 사례:

- **Linear MBA**: CoBRA는 Boolean 입력에서 표현식을 평가하고, signature를 도출한 다음 pattern matching, ANF conversion, coefficient interpolation과 같은 여러 recovery method를 병렬로 실행합니다.
- **Semilinear MBA**: constant-masked atom은 bit-partitioned reconstruction을 사용해 다시 구성되므로 masked region이 올바르게 유지됩니다.
- **Polynomial/Mixed MBA**: product는 core로 분해되며, 단순화하기 전에 반복되는 subexpression을 temporary로 끌어올려 outer relation을 처리할 수 있습니다.

일반적으로 복구를 시도해 볼 가치가 있는 mixed identity의 예:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
다음과 같이 축약할 수 있습니다:
```c
x * y
```
### Reversing notes

- 정확한 computation을 분리한 후 **lifted IR expressions** 또는 decompiler output에 CoBRA를 실행하는 것을 권장합니다.
- expression이 masked arithmetic 또는 narrow registers에서 나온 경우 `--bitwidth`를 명시적으로 사용합니다.
- 더 강력한 proof step이 필요한 경우 여기의 local Z3 notes를 확인하세요:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA는 **LLVM pass plugin** (`libCobraPass.so`)으로도 제공되며, 이후 analysis passes 전에 MBA-heavy LLVM IR을 normalize할 때 유용합니다.
- 지원되지 않는 carry-sensitive mixed-domain residuals는 원래 expression을 유지하고 carry path를 수동으로 분석해야 한다는 신호로 취급해야 합니다.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

이 obfuscator는 program operations를 `mov` 기반 instruction sequences로 대체하고 signal/exception handling을 사용하여 control flow를 변경합니다. 자세한 내용은 다음을 참조하세요:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

지원되는 binaries의 경우 [demovfuscator](https://github.com/kirschju/demovfuscator)를 사용하여 결과를 deobfuscate할 수 있습니다. 여러 dependencies가 필요합니다.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
그리고 [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTF를 진행 중이라면, flag를 찾기 위한 이 workaround가** 매우 유용할 수 있습니다: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point**를 찾으려면 다음과 같이 `::main`을 기준으로 functions를 검색합니다:

![Ghidra에서 function 이름을 double-colon main으로 검색하여 Rust entry point 찾기](<../../images/image (1080).png>)

이 경우 binary 이름이 authenticator였으므로, 이것이 흥미로운 main function이라는 점은 매우 분명합니다.\
호출되는 **functions**의 **name**을 확인한 후, **inputs**와 **outputs**에 대해 알아보기 위해 **Internet**에서 검색합니다.

### ELF firmware에서 Rust 문자열 복구

**Rust ELF** binaries에서는 많은 static 문자열이 C-style NUL-terminated pointers로 참조되지 않습니다. 일반적인 `rustc` layout은 실제 문자열 blob이 저장된 **`.rodata`**를 가리키는 **pointer/length tuple**이 **`.data.rel.ro`** 내부에 있는 형태입니다:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
이는 `strings` 또는 기본 Ghidra 분석이 인접한 문자열을 병합하거나 cross-reference를 완전히 놓칠 수 있음을 의미합니다.<sup>[[3]](#references)</sup>

빠른 워크플로:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. **`.rodata`**의 virtual address와 크기를 가져옵니다.
2. **`.data.rel.ro`**를 한 word씩 열거합니다.
3. `.rodata` 주소 범위 내의 모든 값을 후보 문자열 포인터로 취급합니다.
4. 다음 word를 후보 길이로 취급합니다.
5. 타당성 필터를 적용합니다(예: 길이가 **4**~**100**바이트인 값만 유지).
6. `0x00`까지 검색하는 대신 `.rodata`에서 정확히 `length`바이트를 읽습니다.

최소 extractor 로직:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
이는 복구된 Rust 문자열이 **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, auth-related logic**를 자주 드러내기 때문에 firmware reversing에서 특히 유용합니다.

Ghidra가 이러한 문자열을 놓치는 경우, 동일한 heuristic을 적용하고 참조된 `.rodata` offset에 string data를 생성하는 custom script/plugin을 실행하세요. Pen Test Partners가 공개한 `rust-strings` 및 `RustStrings.py` 도구는 이 아이디어를 다른 **word sizes, endianness, section layouts**에 맞게 적용할 때 좋은 참고 자료입니다.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries에는 [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)을 사용할 수 있습니다.

Delphi binary를 reverse해야 한다면 IDA plugin인 [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)을 사용하는 것을 권장합니다.

IDA에서 **Alt+F7**을 눌러 Python plugin을 로드한 다음 plugin file을 선택합니다.

이 plugin은 debugging 시작 시 binary를 실행하고 function names를 동적으로 resolve합니다. debugging을 시작한 후 Start button(초록색 버튼 또는 f9)을 다시 누르면 실제 code의 시작 부분에서 breakpoint가 hit됩니다.

graphical application에서 button을 누르면 debugger가 해당 button이 invoke한 function에서 멈출 수 있습니다.

## Golang

Golang binary를 reverse해야 한다면 IDA plugin인 [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)을 사용하는 것을 권장합니다.

IDA에서 **Alt+F7**을 눌러 Python plugin을 로드한 다음 plugin file을 선택합니다.

이 plugin은 function names를 resolve합니다.

## Compiled Python

이 페이지에서는 ELF/EXE Python compiled binary에서 Python code를 가져오는 방법을 확인할 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBA 게임의 **binary**를 얻었다면 다양한 도구를 사용하여 이를 **emulate**하고 **debug**할 수 있습니다:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug version 다운로드_) - interface가 포함된 debugger
- [**mgba** ](https://mgba.io)- CLI debugger가 포함됨
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm)의 _**Options --> Emulation Setup --> Controls**_** **에서 Game Boy Advance **buttons**를 누르는 방법을 확인할 수 있습니다.

![Game Boy Advance button mappings를 보여주는 no$gba controls configuration](<../../images/image (581).png>)

누르면 각 **key에는 식별을 위한 value가 할당됩니다**:
```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```
따라서 이러한 종류의 프로그램에서 흥미로운 부분은 **프로그램이 사용자 입력을 어떻게 처리하는지**입니다. 주소 **0x4000130**에서 흔히 발견되는 함수인 **KEYINPUT**을 확인할 수 있습니다.

![주소 0x4000130에서 KEYINPUT을 참조하는 GBA 바이너리의 Ghidra 화면](<../../images/image (447).png>)

이전 이미지에서 해당 함수가 **FUN_080015a8**(주소: _0x080015fa_ 및 _0x080017ac_)에서 호출되는 것을 확인할 수 있습니다.

해당 함수에서 몇 가지 init 작업(중요하지 않음)을 수행한 후:
```c
void FUN_080015a8(void)

{
ushort uVar1;
undefined4 uVar2;
undefined4 uVar3;
ushort uVar4;
int iVar5;
ushort *puVar6;
undefined *local_2c;

DISPCNT = 0x1140;
FUN_08000a74();
FUN_08000ce4(1);
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
```
다음 코드를 찾았습니다:
```c
do {
DAT_030004da = uVar4; //This is the last key pressed
DAT_030004d8 = KEYINPUT | 0xfc00;
puVar6 = &DAT_0200b03c;
uVar4 = DAT_030004d8;
do {
uVar2 = DAT_030004dc;
uVar1 = *puVar6;
if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```
마지막 if문은 **`uVar4`**가 **마지막 Keys**에 포함되어 있으며 현재 키가 아닌지 확인합니다. 이는 버튼에서 손을 떼는 동작을 의미합니다(현재 키는 **`uVar1`**에 저장됨).
```c
if (uVar1 == 4) {
DAT_030000d4 = 0;
uVar3 = FUN_08001c24(DAT_030004dc);
FUN_08001868(uVar2,0,uVar3);
DAT_05000000 = 0x1483;
FUN_08001844(&DAT_0200ba18);
FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
DAT_030000d8 = 0;
uVar4 = DAT_030004d8;
}
else {
if (uVar1 == 8) {
if (DAT_030000d8 == 0xf3) {
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
}
}
else {
if (DAT_030000d4 < 8) {
DAT_030000d4 = DAT_030000d4 + 1;
FUN_08000864();
if (uVar1 == 0x10) {
DAT_030000d8 = DAT_030000d8 + 0x3a;
```
이전 코드에서 **uVar1**(**눌린 버튼의 값**이 있는 위치)를 몇몇 값과 비교하고 있음을 확인할 수 있습니다.

- 먼저 **값 4**(**SELECT** 버튼)와 비교합니다. 이 challenge에서 이 버튼은 화면을 지웁니다.
- 그런 다음 **8**(**START** 버튼)과 값을 비교합니다. 이 challenge에서 해당 경로는 입력한 코드가 유효한지 확인합니다.
- 이 경우 변수 **`DAT_030000d8`**는 0xf3과 비교되며, 값이 같으면 일부 코드가 실행됩니다.
- 그 외의 모든 경우에는 counter (`DAT_030000d4`)를 확인하고 증가시킵니다.\
counter가 8보다 작은 동안, 눌린 키의 값이 `DAT_030000d8`에 누적됩니다.

따라서 이 challenge에서는 버튼의 값을 알고 있으므로, **길이가 8보다 짧고 그 합이 0xf3이 되는 조합을 눌러야 했습니다.**

**이 tutorial의 참고 자료:** [보관된 Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [MBA obfuscation을 CoBRA로 단순화하기](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust strings 디코딩 - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (보관됨)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI 지원 Reverse Engineering 물리치기, 또는 적어도 시도하기](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
