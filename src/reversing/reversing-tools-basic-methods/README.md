# Reversing 도구 및 기본 방법

{{#include ../../banners/hacktricks-training.md}}

## ImGui 기반 Reversing 도구

소프트웨어:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

온라인:

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)을 사용하여 wasm (binary)을 wat (clear text)로 **decompile**
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)을 사용하여 wat을 wasm으로 **compile**
- [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/)을 사용하여 decompile을 시도할 수도 있습니다.

소프트웨어:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek은 **libraries** (.dll), **Windows metadata file** (.winmd), **executables** (.exe)를 포함한 여러 형식을 **decompile하고 검사하는** decompiler입니다. decompile한 후 assembly를 Visual Studio 프로젝트 (.csproj)로 저장할 수 있습니다.

여기서 얻을 수 있는 이점은 손실된 source code를 legacy assembly에서 복원해야 하는 경우 이 작업으로 시간을 절약할 수 있다는 것입니다. 또한 dotPeek은 decompile된 code 전체에서 편리한 탐색 기능을 제공하므로 **Xamarin algorithm analysis**를 위한 완벽한 도구 중 하나입니다.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

포괄적인 add-in model과 도구를 정확한 요구 사항에 맞게 확장하는 API를 갖춘 .NET reflector는 시간을 절약하고 development를 간소화합니다. 이 도구가 제공하는 다양한 reverse engineering 서비스를 살펴보겠습니다.

- library 또는 component를 통해 data가 어떻게 흐르는지 파악할 수 있습니다.
- .NET languages 및 frameworks의 implementation과 사용 방식을 파악할 수 있습니다.
- 사용 중인 APIs 및 technologies에서 더 많은 기능을 활용할 수 있도록 문서화되지 않았거나 노출되지 않은 functionality를 찾습니다.
- dependencies 및 서로 다른 assemblies를 찾습니다.
- code, third-party components 및 libraries에서 errors의 정확한 위치를 추적합니다.
- 작업하는 모든 .NET code의 source를 대상으로 debug합니다.

### [ILSpy](https://github.com/icsharpcode/ILSpy) 및 [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): 모든 OS에서 사용할 수 있습니다(VSCode에서 직접 설치할 수 있으므로 git을 다운로드할 필요가 없습니다. **Extensions**를 클릭하고 **ILSpy 검색**).\
다시 **decompile**, **modify** 및 **recompile**해야 한다면 [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) 또는 이를 기반으로 활발하게 유지 관리되는 fork인 [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)를 사용할 수 있습니다. (함수 내부의 내용을 변경하려면 **Right Click -> Modify Method**).

### DNSpy Logging

**DNSpy가 일부 정보를 파일에 log하도록** 하려면 다음 snippet을 사용할 수 있습니다:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

DNSpy를 사용하여 code를 debug하려면 다음을 수행해야 합니다:

먼저 **debugging**과 관련된 **Assembly attributes**를 변경합니다:

![DNSpy Logging - DNSpy Debugging: 먼저 debugging과 관련된 Assembly attributes를 변경합니다](<../../images/image (973).png>)

다음에서:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
받는 사람:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
그리고 **compile**을 클릭합니다:

![DNSpy Logging - DNSpy Debugging: compile을 클릭합니다](<../../images/image (314) (1).png>)

그런 다음 _**File >> Save module...**_을 통해 새 파일을 저장합니다:

![DNSpy Logging - DNSpy Debugging: File Save module을 통해 새 파일을 저장합니다](<../../images/image (602).png>)

이 작업이 필요한 이유는 이렇게 하지 않으면 **runtime**에 여러 **optimisations**가 코드에 적용되며, 디버깅 중 **break-point가 절대 적중되지 않거나** 일부 **변수가 존재하지 않을** 수 있기 때문입니다.

그런 다음 .NET 애플리케이션이 **IIS**에 의해 **run**되고 있다면 다음과 같이 **restart**할 수 있습니다:
```
iisreset /noforce
```
그런 다음 debugging을 시작하려면 열려 있는 모든 파일을 닫고 **Debug Tab**에서 **Attach to Process...**를 선택합니다:

![DNSpy Logging - DNSpy Debugging: 그런 다음 debugging을 시작하려면 열려 있는 모든 파일을 닫고 Debug Tab에서 Attach to Process를 선택합니다](<../../images/image (318).png>)

그런 다음 **w3wp.exe**를 선택하여 **IIS server**에 attach하고 **attach**를 클릭합니다:

![DNSpy Logging - DNSpy Debugging: 그런 다음 w3wp.exe를 선택하여 IIS server에 attach하고 attach를 클릭합니다](<../../images/image (113).png>)

이제 process를 debugging하고 있으므로 process를 중지하고 모든 module을 load할 차례입니다. 먼저 _Debug >> Break All_을 클릭한 다음 _**Debug >> Windows >> Modules**_를 클릭합니다:

![DNSpy Logging - DNSpy Debugging: 이제 process를 debugging하고 있으므로 process를 중지하고 모든 module을 load할 차례입니다. 먼저 Debug Break All을 클릭한 다음 Debug Windows Modules를 클릭합니다](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: 이제 process를 debugging하고 있으므로 process를 중지하고 모든 module을 load할 차례입니다. 먼저 Debug Break All을 클릭한 다음 Debug Windows Modules를 클릭합니다](<../../images/image (834).png>)

**Modules**에서 아무 module이나 클릭하고 **Open All Modules**를 선택합니다:

![DNSpy Logging - DNSpy Debugging: Modules에서 아무 module이나 클릭하고 Open All Modules를 선택합니다](<../../images/image (922).png>)

**Assembly Explorer**에서 아무 module이나 마우스 오른쪽 버튼으로 클릭하고 **Sort Assemblies**를 클릭합니다:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer에서 아무 module이나 마우스 오른쪽 버튼으로 클릭하고 Sort Assemblies를 클릭합니다](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs debugging

### IDA 사용

- **rundll32 load** (64bits는 C:\Windows\System32\rundll32.exe, 32 bits는 C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** debugger를 선택합니다.
- "**Suspend on library load/unload**"를 선택합니다.

![Debugging DLLs - Using IDA: " Suspend on library load/unload "를 선택합니다](<../../images/image (868).png>)

- 실행의 **parameters**를 설정하고 **DLL path**와 호출하려는 function을 입력합니다:

![Debugging DLLs - Using IDA: DLL path와 호출하려는 function을 입력하여 실행 parameters를 설정합니다](<../../images/image (704).png>)

그런 다음 debugging을 시작하면 **각 DLL이 load될 때 execution이 중지**되고, rundll32가 DLL을 load하면 execution이 중지됩니다.

하지만 load된 DLL의 code로 어떻게 이동할 수 있을까요? 이 method를 사용하는 방법은 모르겠습니다.

### x64dbg/x32dbg 사용

- **rundll32 load** (64bits는 C:\Windows\System32\rundll32.exe, 32 bits는 C:\Windows\SysWOW64\rundll32.exe)
- **Command Line 변경** ( _File --> Change Command Line_ ) 후 dll의 path와 호출하려는 function을 설정합니다. 예: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_를 변경하고 "**DLL Entry**"를 선택합니다.
- 그런 다음 **execution을 시작**하면 debugger가 각 dll main에서 중지됩니다. 어느 시점에 **여러분의 dll Entry에서 중지**하게 됩니다. 여기서부터 breakpoint를 설정하려는 지점을 찾기만 하면 됩니다.

win64dbg에서 어떤 이유로든 execution이 중지되면 **win64dbg window 상단**에서 현재 **어떤 code에 있는지** 확인할 수 있습니다:

![Using IDA - Using x64dbg/x32dbg: 어떤 이유로든 execution이 중지되면 win64dbg에서 win64dbg window 상단을 확인하여 현재 어떤 code에 있는지 볼 수 있습니다](<../../images/image (842).png>)

그런 다음 이를 확인하면 debugging하려는 dll에서 execution이 중지된 시점을 알 수 있습니다.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)은 실행 중인 game의 memory 내부에 중요한 value가 저장된 위치를 찾고 이를 변경하는 데 유용한 program입니다. 자세한 정보는 다음을 참조하세요:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE)는 game에 초점을 맞춘 GNU Project Debugger (GDB)의 front-end/reverse engineering tool입니다. 하지만 reverse-engineering과 관련된 모든 작업에 사용할 수 있습니다.

[**Decompiler Explorer**](https://dogbolt.org/)는 여러 decompiler를 위한 web front-end입니다. 이 web service를 사용하면 작은 executable에서 서로 다른 decompiler의 output을 비교할 수 있습니다.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner를 사용한 shellcode debugging

[**Blobrunner**](https://github.com/OALabs/BlobRunner)는 memory 공간을 **allocate**하여 그 안에 **shellcode**를 저장하고, shellcode가 allocate된 **memory address**를 **표시**한 다음 execution을 **중지**합니다.\
그런 다음 process에 **debugger**(Ida 또는 x64dbg)를 **attach**하고 표시된 memory address에 **breakpoint**를 설정한 후 execution을 **resume**해야 합니다. 이렇게 하면 shellcode를 debugging할 수 있습니다.

releases github page에는 compiled release가 포함된 zip 파일이 있습니다: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
다음 link에서 약간 수정된 Blobrunner version을 찾을 수 있습니다. compile하려면 **Visual Studio Code에서 C/C++ project를 생성하고, code를 copy and paste한 다음 build**하면 됩니다.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it을 사용한 shellcode debugging

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)은 blobrunner와 매우 유사합니다. **memory** 공간을 **allocate**하여 그 안에 **shellcode**를 저장하고 **무한 loop**를 시작합니다. 그런 다음 process에 **debugger를 attach**하고 **play start wait 2-5 secs and press stop**하면 **무한 loop** 내부에 있게 됩니다. 무한 loop의 다음 instruction으로 이동하면 해당 instruction은 shellcode를 호출하는 call이며, 결국 shellcode를 실행하는 위치에 도달하게 됩니다.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it은 blobrunner와 매우 유사합니다. memory 공간을 allocate하여 그 안에 shellcode를 저장하고...](<../../images/image (509).png>)

compiled version의 [jmp2it은 releases page에서 다운로드할 수 있습니다](https://github.com/adamkramer/jmp2it/releases/).

### Cutter를 사용한 shellcode debugging

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)는 radare의 GUI입니다. Cutter를 사용하면 shellcode를 emulate하고 동적으로 inspect할 수 있습니다.

Cutter에서는 "Open File"과 "Open Shellcode"를 사용할 수 있습니다. 제 경우 shellcode를 file로 열었을 때는 올바르게 decompile했지만, shellcode로 열었을 때는 그렇지 않았습니다:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Cutter에서는 "Open File"과 "Open Shellcode"를 사용할 수 있습니다. 제 경우 shellcode를 file로 열었을 때는...](<../../images/image (562).png>)

원하는 위치에서 emulation을 시작하려면 해당 위치에 bp를 설정하면 됩니다. 그러면 Cutter가 해당 위치에서 자동으로 emulation을 시작하는 것으로 보입니다:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: 원하는 위치에서 emulation을 시작하려면 해당 위치에 bp를 설정하면 됩니다. 그러면 Cutter가 해당 위치에서 자동으로...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: 원하는 위치에서 emulation을 시작하려면 해당 위치에 bp를 설정하면 됩니다. 그러면 Cutter가 해당 위치에서 자동으로...](<../../images/image (387).png>)

예를 들어 hex dump 내부에서 stack을 확인할 수 있습니다:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: 예를 들어 hex dump 내부에서 stack을 확인할 수 있습니다](<../../images/image (186).png>)

### shellcode deobfuscating 및 executed function 가져오기

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)를 사용해 보세요.\
scdbg는 shellcode가 사용하는 **function**이 무엇인지, 그리고 shellcode가 memory에서 스스로 **decoding**하는지 여부 등을 알려줍니다.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg에는 원하는 옵션을 선택하고 shellcode를 실행할 수 있는 그래픽 launcher도 포함되어 있습니다.

![Cutter를 사용한 shellcode 디버깅 - shellcode 난독화 해제 및 실행된 함수 확인: scDbg에는 원하는 옵션을 선택하고...](<../../images/image (258).png>)

**Create Dump** 옵션은 메모리에서 shellcode가 동적으로 변경된 경우 최종 shellcode를 dump합니다(디코딩된 shellcode를 다운로드할 때 유용합니다). **start offset**은 특정 offset에서 shellcode를 시작하는 데 유용할 수 있습니다. **Debug Shell** 옵션은 scDbg 터미널을 사용해 shellcode를 디버깅할 때 유용합니다(다만 이 목적에는 앞에서 설명한 옵션을 사용하는 편이 더 좋다고 생각합니다. Ida 또는 x64dbg를 사용할 수 있기 때문입니다).

### CyberChef를 사용한 Disassembling

shellcode 파일을 입력으로 업로드하고 다음 recipe를 사용해 디컴파일합니다: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation은 산술 연산자(`+`, `-`, `*`)와 bitwise 연산자(`&`, `|`, `^`, `~`, shift)를 혼합한 수식을 사용해 `x + y`와 같은 단순한 식을 숨깁니다. 중요한 점은 이러한 항등식이 일반적으로 **고정 폭 모듈러 산술**에서만 올바르다는 것입니다. 따라서 carry와 overflow가 중요합니다:
```c
(x ^ y) + 2 * (x & y) == x + y
```
이러한 종류의 표현식을 generic algebra tooling으로 단순화하면 bit-width semantics가 무시되어 쉽게 잘못된 결과를 얻을 수 있습니다.<sup>[[1]](#references)</sup>

### Practical workflow

1. **원래 bit-width를 유지합니다.** lifted code/IR/decompiler output의 (`8/16/32/64` bits)를 그대로 사용합니다.
2. **단순화를 시도하기 전에 expression을 분류합니다.**
- **Linear**: bitwise atom의 가중 합
- **Semilinear**: `x & 0xFF`와 같은 constant mask가 포함된 linear expression
- **Polynomial**: product가 포함됨
- **Mixed**: product와 bitwise logic이 서로 섞여 있으며, 반복되는 subexpression이 자주 나타남
3. **모든 후보 rewrite를 random testing 또는 SMT proof로 검증합니다.** equivalence를 증명할 수 없다면 추측으로 처리하지 말고 원래 expression을 유지합니다.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA)는 malware analysis와 protected-binary reversing을 위한 실용적인 MBA simplifier입니다. expression을 분류한 뒤 모든 항목에 하나의 generic rewrite pass를 적용하는 대신 specialized pipeline으로 전달합니다.<sup>[[2]](#references)</sup>

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
유용한 경우:

- **Linear MBA**: CoBRA는 Boolean inputs에서 expression을 평가하고, signature를 도출한 다음 pattern matching, ANF conversion, coefficient interpolation과 같은 여러 recovery methods를 병렬로 실행합니다.
- **Semilinear MBA**: constant-masked atoms는 bit-partitioned reconstruction을 사용해 재구성되므로 masked regions가 올바르게 유지됩니다.
- **Polynomial/Mixed MBA**: products는 cores로 분해되며, simplifying the outer relation 전에 반복되는 subexpressions를 temporaries로 승격할 수 있습니다.

일반적으로 복구를 시도해 볼 가치가 있는 mixed identity의 예:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
이는 다음과 같이 축약할 수 있습니다:
```c
x * y
```
### Reversing 노트

- 정확한 computation을 분리한 후 **lifted IR expressions** 또는 decompiler output에 CoBRA를 실행하는 것을 우선하세요.
- 표현식이 masked arithmetic 또는 narrow registers에서 나온 경우 `--bitwidth`를 명시적으로 사용하세요.
- 더 강력한 proof step이 필요한 경우 여기의 로컬 Z3 노트를 확인하세요:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA는 **LLVM pass plugin**(`libCobraPass.so`)으로도 제공되며, 이후 analysis passes 전에 MBA-heavy LLVM IR을 normalize하려는 경우 유용합니다.
- 지원되지 않는 carry-sensitive mixed-domain residuals는 원래 표현식을 유지하고 carry path를 수동으로 분석해야 한다는 신호로 취급해야 합니다.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

이 obfuscator는 **`mov`에 대한 모든 instruction을 수정**합니다(네, 정말 멋집니다). 또한 execution flow를 변경하기 위해 interruptions를 사용합니다. 작동 방식에 대한 자세한 정보는 다음을 참고하세요:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

운이 좋다면 [demovfuscator](https://github.com/kirschju/demovfuscator)가 binary를 deobfuscate할 수 있습니다. 여러 dependency가 필요합니다.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
그리고 [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTF를 진행 중이라면, **flag를 찾기 위한 이 workaround가 매우 유용할 수 있습니다**: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point**를 찾으려면 다음과 같이 `::main`으로 함수를 검색합니다:

![Movfuscator - Rust: 다음과 같이 ::main으로 함수를 검색하여 entry point 찾기](<../../images/image (1080).png>)

이 경우 binary의 이름이 authenticator였으므로, 이것이 흥미로운 main 함수라는 점은 매우 분명합니다.\
호출되는 **functions**의 **name**을 확인한 후, **inputs**와 **outputs**에 대해 알아보기 위해 **Internet**에서 검색합니다.

### ELF firmware에서 Rust strings 복구하기

**Rust ELF** binaries에서는 많은 static strings가 C-style NUL-terminated pointers로 참조되지 않습니다. 일반적인 `rustc` layout은 실제 string blob이 저장된 **`.rodata`**를 가리키는 **pointer/length tuple**이 **`.data.rel.ro`** 내부에 있는 형태입니다:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
이는 `strings` 또는 기본 Ghidra 분석이 인접한 문자열을 병합하거나 cross-reference를 완전히 놓칠 수 있음을 의미합니다.<sup>[[3]](#references)</sup>

빠른 워크플로:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. **`.rodata`**의 가상 주소와 크기를 가져옵니다.
2. **`.data.rel.ro`**를 한 word씩 열거합니다.
3. **`.rodata`** 주소 범위 내의 모든 값을 후보 문자열 포인터로 취급합니다.
4. 다음 word를 후보 길이로 취급합니다.
5. sanity 필터를 적용합니다(예: **4**~**100** bytes 사이의 길이만 유지).
6. `0x00`까지 scan하는 대신 `.rodata`에서 정확히 `length` bytes를 읽습니다.

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

Ghidra가 이러한 문자열을 놓치는 경우, 동일한 heuristic을 적용하고 참조된 `.rodata` 오프셋에 string data를 생성하는 custom script/plugin을 실행하세요. Pen Test Partners가 공개한 `rust-strings` 및 `RustStrings.py` 도구는 이 아이디어를 다른 **word sizes, endianness, section layouts**에 맞게 적용할 때 참고하기 좋습니다.<sup>[[4]](#references)[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries에는 [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)를 사용할 수 있습니다.

Delphi binary를 reverse해야 한다면 IDA plugin인 [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)를 사용하는 것을 권장합니다.

**ATL+f7** (IDA에서 python plugin import)를 누르고 python plugin을 선택하세요.

이 plugin은 binary를 실행하고 debugging 시작 시 function names를 동적으로 resolve합니다. debugging을 시작한 후 Start button(초록색 버튼 또는 f9)을 다시 누르면 real code의 시작 부분에서 breakpoint가 hit됩니다.

또한 graphic application에서 button을 누르면 debugger가 해당 bottom에 의해 실행된 function에서 중지되므로 매우 흥미롭습니다.

## Golang

Golang binary를 reverse해야 한다면 IDA plugin인 [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)를 사용하는 것을 권장합니다.

**ATL+f7** (IDA에서 python plugin import)를 누르고 python plugin을 선택하세요.

이 plugin은 function names를 resolve합니다.

## Compiled Python

이 페이지에서 ELF/EXE python compiled binary에서 python code를 가져오는 방법을 확인할 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

GBA game의 **binary**를 얻었다면 다양한 도구를 사용하여 이를 **emulate**하고 **debug**할 수 있습니다:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - interface가 포함된 debugger
- [**mgba** ](https://mgba.io)- CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm)에서 _**Options --> Emulation Setup --> Controls**_**로 이동하면 Game Boy Advance **buttons**를 누르는 방법을 확인할 수 있습니다.

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

누르면 각 **key has a value**가 할당되어 해당 key를 식별합니다:
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

![주소 0x4000130에서 KEYINPUT을 참조하는 GBA 바이너리의 Ghidra 뷰](<../../images/image (447).png>)

이전 이미지에서 해당 함수가 **FUN_080015a8**(주소: _0x080015fa_ 및 _0x080017ac_)에서 호출되는 것을 확인할 수 있습니다.

해당 함수에서 일부 init 작업(중요하지 않음)을 수행한 후:
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
이 코드를 찾았습니다:
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
마지막 if문은 **`uVar4`**가 이전 **Keys**에 포함되어 있지만 현재 키는 아닌지 확인합니다. 이는 버튼에서 손을 떼는 동작이라고도 합니다 (현재 키는 **`uVar1`**에 저장됨).
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
이전 코드에서 **uVar1**(**눌린 버튼의 값**이 저장된 위치)를 일부 값과 비교하고 있음을 확인할 수 있습니다:

- 먼저 **value 4** (**SELECT** 버튼)와 비교합니다: challenge에서는 이 버튼이 화면을 지웁니다.
- 그런 다음 **value 8** (**START** 버튼)과 비교합니다: challenge에서는 이 값이 유효한지 확인하여 flag를 가져옵니다.
- 이 경우 변수 **`DAT_030000d8`**가 0xf3과 비교되며, 값이 같으면 일부 코드가 실행됩니다.
- 그 외의 경우에는 일부 cont(**`DAT_030000d4`**)를 확인합니다. code에 진입한 직후 1을 더하고 있기 때문에 cont입니다.\
**I**f 8보다 작으면 **`DAT_030000d8`**에 값을 **더하는** 작업이 수행됩니다(기본적으로 cont가 8보다 작은 동안 눌린 키의 값을 이 변수에 더합니다).

따라서 이 challenge에서는 버튼의 값을 알고 있으므로, **길이가 8보다 작고 그 합이 0xf3이 되는 조합을 눌러야 했습니다.**

**이 tutorial의 Reference:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
