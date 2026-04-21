# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui Based Reversing tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Use [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) to **decompile** from wasm (binary) to wat (clear text)
- Use [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) to **compile** from wat to wasm
- you can also try to use [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) to decompile

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek는 **여러 형식을 디컴파일하고 검사**하는 디컴파일러로, **libraries** (.dll), **Windows metadata file**s (.winmd), 그리고 **executables** (.exe)를 포함합니다. 디컴파일된 후에는 assembly를 Visual Studio 프로젝트 (.csproj)로 저장할 수 있습니다.

여기서의 장점은 분실된 source code를 legacy assembly에서 복원해야 할 때 이 작업이 시간을 절약해 준다는 점입니다. 또한 dotPeek는 디컴파일된 code 전체에서 편리한 탐색 기능을 제공하므로, **Xamarin algorithm analysis**에 매우 적합한 도구 중 하나입니다.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

포괄적인 add-in model과 tool을 정확한 필요에 맞게 확장하는 API를 갖춘 .NET reflector는 시간을 절약하고 development를 단순화합니다. 이 tool이 제공하는 다양한 reverse engineering services를 살펴보겠습니다:

- library나 component를 통해 data가 어떻게 흐르는지에 대한 insight를 제공합니다
- .NET languages 및 frameworks의 implementation과 usage에 대한 insight를 제공합니다
- APIs와 technologies에서 더 많은 것을 활용할 수 있도록 문서화되지 않았고 노출되지 않은 functionality를 찾습니다.
- dependencies와 서로 다른 assemblies를 찾습니다
- 코드, third-party components, libraries에서 오류의 정확한 위치를 추적합니다.
- 작업하는 모든 .NET code의 source로 디버깅합니다.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): 모든 OS에서 사용할 수 있습니다 (VSCode에서 바로 설치할 수 있으며, git을 다운로드할 필요가 없습니다. **Extensions**를 클릭하고 **ILSpy**를 검색하세요).\
**decompile**, **modify**, 그리고 다시 **recompile**해야 한다면 [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) 또는 활발히 유지보수되는 fork인 [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)를 사용할 수 있습니다. (함수 내부의 내용을 변경하려면 **Right Click -> Modify Method**).

### DNSpy Logging

**DNSpy가 파일에 일부 정보를 log**하도록 하려면, 이 snippet을 사용할 수 있습니다:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy 디버깅

DNSpy를 사용하여 코드를 디버깅하려면 다음이 필요합니다:

먼저, **디버깅**과 관련된 **Assembly attributes**를 변경하세요:

![](<../../images/image (973).png>)

From:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
To:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
그리고 **compile**을 클릭하세요:

![](<../../images/image (314) (1).png>)

그다음 _**File >> Save module...**_를 통해 새 파일을 저장하세요:

![](<../../images/image (602).png>)

이 단계가 필요한 이유는, 이렇게 하지 않으면 **runtime**에서 여러 **optimisations**가 코드에 적용될 수 있고, 그 결과 디버깅 중 **break-point가 절대 걸리지 않거나** 일부 **variables**가 존재하지 않을 수도 있기 때문입니다.

그다음, .NET application이 **IIS**로 **run**되고 있다면 다음으로 **restart**할 수 있습니다:
```
iisreset /noforce
```
Then, in order to start debugging you should close all the opened files and inside the **Debug Tab** select **Attach to Process...**:

![](<../../images/image (318).png>)

Then select **w3wp.exe** to attach to the **IIS server** and click **attach**:

![](<../../images/image (113).png>)

Now that we are debugging the process, it's time to stop it and load all the modules. First click on _Debug >> Break All_ and then click on _**Debug >> Windows >> Modules**_:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Click any module on **Modules** and select **Open All Modules**:

![](<../../images/image (922).png>)

Right click any module in **Assembly Explorer** and click **Sort Assemblies**:

![](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![](<../../images/image (868).png>)

- Configure the **parameters** of the execution putting the **path to the DLL** and the function that you want to call:

![](<../../images/image (704).png>)

Then, when you start debugging **the execution will be stopped when each DLL is loaded**, then, when rundll32 load your DLL the execution will be stopped.

But, how can you get to the code of the DLL that was lodaded? Using this method, I don't know how.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Notice that when the execution is stopped by any reason in win64dbg you can see **in which code you are** looking in the **top of the win64dbg window**:

![](<../../images/image (842).png>)

Then, looking to this ca see when the execution was stopped in the dll you want to debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is a useful program to find where important values are saved inside the memory of a running game and change them. More info in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is a front-end/reverse engineering tool for the GNU Project Debugger (GDB), focused on games. However, it can be used for any reverse-engineering related stuff

[**Decompiler Explorer**](https://dogbolt.org/) is a web front-end to a number of decompilers. This web service lets you compare the output of different decompilers on small executables.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) will **allocate** the **shellcode** inside a space of memory, will **indicate** you the **memory address** were the shellcode was allocated and will **stop** the execution.\
Then, you need to **attach a debugger** (Ida or x64dbg) to the process and put a **breakpoint the indicated memory address** and **resume** the execution. This way you will be debugging the shellcode.

The releases github page contains zips containing the compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
You can find a slightly modified version of Blobrunner in the following link. In order to compile it just **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)is very similar to blobrunner. It will **allocate** the **shellcode** inside a space of memory, and start an **eternal loop**. You then need to **attach the debugger** to the process, **play start wait 2-5 secs and press stop** and you will find yourself inside the **eternal loop**. Jump to the next instruction of the eternal loop as it will be a call to the shellcode, and finally you will find yourself executing the shellcode.

![](<../../images/image (509).png>)

You can download a compiled version of [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is the GUI of radare. Using cutter you can emulate the shellcode and inspect it dynamically.

Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it decompiled it correctly, but when I opened it as a shellcode it didn't:

![](<../../images/image (562).png>)

In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically start the emulation from there:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

You can see the stack for example inside a hex dump:

![](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

You should try [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
It will tell you things like **which functions** is the shellcode using and if the shellcode is **decoding** itself in memory.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg는 또한 그래픽 런처를 제공하며, 여기서 원하는 옵션을 선택하고 shellcode를 실행할 수 있습니다.

![](<../../images/image (258).png>)

**Create Dump** 옵션은 메모리에서 shellcode가 동적으로 변경되는 경우 최종 shellcode를 덤프합니다. 이는 디코딩된 shellcode를 다운로드할 때 유용합니다. **start offset**은 특정 오프셋에서 shellcode를 시작할 때 유용할 수 있습니다. **Debug Shell** 옵션은 scDbg 터미널을 사용해 shellcode를 디버깅할 때 유용합니다(다만 이 경우에는 앞서 설명한 옵션들보다 Ida나 x64dbg를 사용할 수 있는 방식이 더 좋다고 생각합니다).

### CyberChef를 사용한 Disassembling

shellcode 파일을 입력으로 업로드하고 다음 recipe를 사용해 decompile하세요: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation은 `x + y` 같은 단순한 표현식을 산술 연산자(`+`, `-`, `*`)와 비트 연산자(`&`, `|`, `^`, `~`, shifts`)를 섞은 수식 뒤에 숨깁니다. 중요한 점은 이러한 항등식이 보통 **고정 폭 모듈러 산술**에서만 정확하므로, carry와 overflow가 중요하다는 것입니다:
```c
(x ^ y) + 2 * (x & y) == x + y
```
이런 종류의 expression을 generic algebra tooling으로 단순화하면 bit-width semantics가 무시되어 쉽게 잘못된 결과를 얻을 수 있습니다.

### Practical workflow

1. **원래 bit-width를 유지**하세요: lifted code/IR/decompiler output의 (`8/16/32/64` bits).
2. **단순화하기 전에 expression을 분류**하세요:
- **Linear**: bitwise atoms의 weighted sums
- **Semilinear**: `x & 0xFF` 같은 constant masks가 더해진 linear
- **Polynomial**: products가 나타남
- **Mixed**: products와 bitwise logic이 interleave되며, 종종 repeated subexpressions가 있음
3. **모든 candidate rewrite를 검증**하세요. random testing이나 SMT proof를 사용합니다. equivalence를 증명할 수 없다면 추측하지 말고 원래 expression을 유지하세요.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) is a practical MBA simplifier for malware analysis and protected-binary reversing. It classifies the expression and routes it through specialized pipelines instead of applying one generic rewrite pass to everything.

Quick usage:
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

- **Linear MBA**: CoBRA는 Boolean 입력에서 표현식을 평가하고, 시그니처를 도출한 다음, pattern matching, ANF conversion, coefficient interpolation 같은 여러 복구 방법을 동시에 시도한다.
- **Semilinear MBA**: constant-masked atom은 bit-partitioned reconstruction으로 재구성되어 masked region이 올바르게 유지된다.
- **Polynomial/Mixed MBA**: product는 core로 분해되며, outer relation을 단순화하기 전에 반복되는 subexpression을 temporary로 올릴 수 있다.

복구를 시도해볼 만한, 흔히 유용한 mixed identity의 예:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
이는 다음과 같이 축약될 수 있습니다:
```c
x * y
```
### Reversing notes

- 정확한 computation을 분리한 뒤에는 **lifted IR expressions** 또는 decompiler output에서 CoBRA를 실행하는 것을 권장한다.
- expression이 masked arithmetic 또는 narrow registers에서 왔다면 `--bitwidth`를 명시적으로 사용한다.
- 더 강한 proof step이 필요하면, 여기의 local Z3 notes를 확인하라:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA는 **LLVM pass plugin**(`libCobraPass.so`)으로도 제공되며, 이후 analysis passes 전에 MBA-heavy LLVM IR을 normalize하고 싶을 때 유용하다.
- 지원되지 않는 carry-sensitive mixed-domain residuals는 original expression을 유지하고 carry path를 수동으로 reason about 하라는 신호로 처리해야 한다.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

이 obfuscator는 **모든 instructions를 `mov`로 수정**한다(정말 멋지다). 또한 executions flows를 바꾸기 위해 interruptions를 사용한다. 동작 방식에 대한 자세한 정보는 다음을 참고하라:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

운이 좋다면 [demovfuscator](https://github.com/kirschju/demovfuscator)가 binary를 deofuscate해 줄 것이다. 여러 dependencies가 있다
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
그리고 [keystone를 설치](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)하세요 (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTF를 하고 있다면, flag를 찾기 위한 이 우회 방법**이 매우 유용할 수 있습니다: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point**를 찾으려면 `::main`이 포함된 함수들을 다음처럼 검색하세요:

![](<../../images/image (1080).png>)

이 경우 binary 이름이 authenticator였으므로, 이것이 흥미로운 main function임이 꽤 분명합니다.\
호출되는 **functions**의 **name**을 알면, 해당 **inputs**와 **outputs**를 알아내기 위해 **Internet**에서 검색하세요.

## **Delphi**

Delphi로 컴파일된 binaries의 경우 [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)를 사용할 수 있습니다

Delphi binary를 reverse해야 한다면 IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)를 사용하는 것을 추천합니다

그냥 **ATL+f7**(IDA에서 python plugin import) 를 누르고 python plugin을 선택하세요.

이 plugin은 binary를 실행하고 debugging 시작 시점에 function names를 동적으로 resolve합니다. debugging을 시작한 뒤 Start button(초록색 버튼 또는 f9)을 다시 누르면 breakpoint가 실제 code의 시작 부분에서 hit됩니다.

그래픽 application에서 button을 누르면 debugger가 그 bottom에 의해 실행된 function에서 멈춘다는 점도 매우 흥미롭습니다.

## Golang

Golang binary를 reverse해야 한다면 IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)를 사용하는 것을 추천합니다

그냥 **ATL+f7**(IDA에서 python plugin import) 를 누르고 python plugin을 선택하세요.

이것은 function들의 name을 resolve합니다.

## Compiled Python

이 페이지에서 ELF/EXE python compiled binary에서 python code를 얻는 방법을 볼 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

GBA game의 **binary**를 얻었다면, 이를 **emulate**하고 **debug**하기 위해 여러 도구를 사용할 수 있습니다:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Debug version 다운로드_) - interface가 있는 debugger 포함
- [**mgba** ](https://mgba.io) - CLI debugger 포함
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm)에서 _**Options --> Emulation Setup --> Controls**_** **로 들어가면 Game Boy Advance **buttons**를 어떻게 누르는지 볼 수 있습니다

![](<../../images/image (581).png>)

눌렀을 때, 각 **key**는 이를 식별하기 위한 **value**를 가집니다:
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
따라서, 이런 종류의 프로그램에서 흥미로운 부분은 **프로그램이 사용자 입력을 어떻게 처리하는지**입니다. 주소 **0x4000130**에서 흔히 발견되는 함수인 **KEYINPUT**를 찾을 수 있습니다.

![](<../../images/image (447).png>)

이전 이미지에서 이 함수가 **FUN_080015a8**에서 호출되는 것을 확인할 수 있습니다(주소: _0x080015fa_ 및 _0x080017ac_).

그 함수에서, 몇 가지 초기화 작업(중요하지 않음) 후:
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
이 코드가 발견되었습니다:
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
마지막 if는 **`uVar4`**가 **마지막 Keys**에 있는지, 그리고 현재 key가 아닌지를 확인하는 것으로, 버튼에서 손을 떼는 것과 같습니다(현재 key는 **`uVar1`**에 저장됨).
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
이전 코드에서 **uVar1**(**pressed button의 value**가 들어있는 곳)과 몇 가지 값들을 비교하는 것을 볼 수 있습니다:

- 먼저 **value 4** (**SELECT** button)와 비교합니다: challenge에서 이 button은 screen을 clear합니다
- 그다음 **value 8** (**START** button)와 비교합니다: challenge에서 이것은 flag를 얻기 위해 code가 valid한지 확인합니다.
- 이 경우 var **`DAT_030000d8`**가 0xf3와 비교되며, 값이 같으면 some code가 실행됩니다.
- 다른 경우에는 일부 cont (**`DAT_030000d4`**)가 checked 됩니다. cont인 이유는 code에 들어간 직후 1이 더해지기 때문입니다.\
**I**f 8보다 작으면 **`DAT_030000d8`**에 값을 **더하는** 작업이 수행됩니다(기본적으로 cont가 8보다 작은 동안 이 variable에 pressed keys의 값들을 더합니다).

따라서 이 challenge에서는 button의 values를 알고 있었으므로, **길이가 8보다 작은 combination**을 눌러서 결과적인 addition이 0xf3가 되게 해야 했습니다.

**Reference for this tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)

{{#include ../../banners/hacktricks-training.md}}
