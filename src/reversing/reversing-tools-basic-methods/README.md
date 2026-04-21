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

dotPeek는 **여러 형식을 decompile하고 검사하는** decompiler로, **libraries** (.dll), **Windows metadata file**s (.winmd), **executables** (.exe)를 포함합니다. decompile된 후 assembly는 Visual Studio project (.csproj)로 저장할 수 있습니다.

여기서의 장점은 소실된 source code를 legacy assembly에서 복원해야 할 때 이 작업으로 시간을 절약할 수 있다는 점입니다. 또한 dotPeek는 decompile된 code 전반에서 편리한 navigation을 제공하므로, **Xamarin algorithm analysis**에 매우 적합한 tools 중 하나입니다.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

포괄적인 add-in model과 tool을 정확한 필요에 맞게 확장하는 API를 통해, .NET reflector는 시간을 절약하고 development를 단순화합니다. 이 tool이 제공하는 다양한 reverse engineering services를 살펴보겠습니다:

- library 또는 component를 통해 data가 어떻게 흐르는지에 대한 insight를 제공합니다
- .NET languages 및 frameworks의 implementation과 usage에 대한 insight를 제공합니다
- API와 사용된 technologies를 더 많이 활용할 수 있도록 undocumented 및 unexposed functionality를 찾습니다.
- dependencies와 다양한 assemblies를 찾습니다
- code, third-party components, libraries에서 오류의 정확한 위치를 추적합니다.
- 작업 중인 모든 .NET code의 source로 debug합니다.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code용 ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode): 어떤 OS에서도 사용할 수 있습니다 (VSCode에서 직접 설치할 수 있으며, git을 다운로드할 필요가 없습니다. **Extensions**를 클릭하고 **ILSpy**를 검색하세요).\
**decompile**, **modify**, 그리고 다시 **recompile**해야 한다면 [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) 또는 이를 활발히 유지보수하는 fork인 [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)를 사용할 수 있습니다. (함수 내부를 변경하려면 **Right Click -> Modify Method**).

### DNSpy Logging

**DNSpy가 정보를 파일에 log**하도록 하려면, 이 snippet을 사용할 수 있습니다:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

DNSpy를 사용하여 코드를 디버깅하려면 다음이 필요합니다:

먼저, **debugging**과 관련된 **Assembly attributes**를 변경하세요:

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

이 작업이 필요한 이유는, 이것을 하지 않으면 **runtime**에서 여러 **optimisations**가 코드에 적용되어 디버깅 중에 **break-point**가 절대 걸리지 않거나 일부 **variables**가 존재하지 않을 수 있기 때문입니다.

그다음, .NET application이 **IIS**에 의해 **run**되고 있다면 다음 명령으로 **restart**할 수 있습니다:
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
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) will **allocate** the **shellcode** inside a space of memory, will **indicate** you the **memory address** were the shellcode was allocated and will **stop** the execution.\
Then, you need to **attach a debugger** (Ida or x64dbg) to the process and put a **breakpoint the indicated memory address** and **resume** the execution. This way you will be debugging the shellcode.

The releases github page contains zips containing the compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
You can find a slightly modified version of Blobrunner in the following link. In order to compile it just **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

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
scDbg는 원하는 옵션을 선택하고 shellcode를 실행할 수 있는 그래픽 런처도 제공합니다

![](<../../images/image (258).png>)

**Create Dump** 옵션은 shellcode가 메모리 내에서 동적으로 변경된 경우 최종 shellcode를 덤프합니다(디코딩된 shellcode를 다운로드할 때 유용함). **start offset**은 특정 오프셋에서 shellcode를 시작하는 데 유용할 수 있습니다. **Debug Shell** 옵션은 scDbg 터미널을 사용해 shellcode를 디버그하는 데 유용합니다(하지만 이 용도에는 앞서 설명한 옵션들 중 하나가 더 낫다고 봅니다. Ida나 x64dbg를 사용할 수 있기 때문입니다).

### CyberChef를 사용한 Disassembling

shellcode 파일을 입력으로 업로드하고 다음 recipe를 사용해 decompile하세요: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation은 `x + y` 같은 단순한 표현식을 산술 연산(`+`, `-`, `*`)과 비트 연산자(`&`, `|`, `^`, `~`, shifts`)를 섞은 공식 뒤에 숨깁니다. 중요한 점은 이러한 항등식이 보통 **fixed-width modular arithmetic**에서만 올바르므로, carry와 overflow가 중요하다는 것입니다:
```c
(x ^ y) + 2 * (x & y) == x + y
```
이런 종류의 표현식을 generic algebra tooling으로 단순화하면 bit-width semantics가 무시되어 쉽게 잘못된 결과가 나올 수 있습니다.

### Practical workflow

1. **원래 bit-width를 유지**하세요. lifted code/IR/decompiler output의 (`8/16/32/64` bits) 값을 그대로 사용합니다.
2. 단순화하기 전에 expression을 **분류**하세요:
- **Linear**: bitwise atoms의 가중합
- **Semilinear**: `x & 0xFF` 같은 상수 mask가 포함된 linear
- **Polynomial**: product가 나타남
- **Mixed**: product와 bitwise logic이 interleave되어 있으며, 종종 repeated subexpression이 있음
3. 모든 candidate rewrite를 random testing 또는 SMT proof로 **검증**하세요. equivalence를 증명할 수 없으면, 추측하지 말고 원래 expression을 유지하세요.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) is malware analysis와 protected-binary reversing을 위한 practical MBA simplifier입니다. expression을 분류한 뒤, 모든 것에 하나의 generic rewrite pass를 적용하는 대신 specialized pipelines로 라우팅합니다.

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

- **Linear MBA**: CoBRA는 Boolean 입력에서 식을 평가하고, signature를 도출한 뒤, pattern matching, ANF conversion, coefficient interpolation 같은 여러 recovery methods를 동시에 시도합니다.
- **Semilinear MBA**: constant-masked atoms는 bit-partitioned reconstruction으로 재구성되어 masked regions가 올바르게 유지됩니다.
- **Polynomial/Mixed MBA**: products는 cores로 분해되고, 반복되는 subexpressions는 바깥 관계를 단순화하기 전에 temporaries로 끌어올릴 수 있습니다.

복구를 시도해 볼 만한 흔한 mixed identity의 예:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
이것은 다음으로 축약될 수 있습니다:
```c
x * y
```
### Reversing notes

- exact computation을 분리한 뒤에는 **lifted IR expressions** 또는 decompiler output에서 CoBRA를 실행하는 것이 좋습니다.
- expression이 masked arithmetic 또는 narrow registers에서 왔다면 `--bitwidth`를 명시적으로 사용하세요.
- 더 강한 proof step이 필요하면 여기의 local Z3 notes를 확인하세요:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA는 **LLVM pass plugin**(`libCobraPass.so`)으로도 제공되며, 나중의 analysis passes 전에 MBA-heavy LLVM IR을 normalize하고 싶을 때 유용합니다.
- 지원되지 않는 carry-sensitive mixed-domain residual은 original expression을 유지하고 carry path를 수동으로 reasoning해야 한다는 신호로 취급해야 합니다.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

This obfuscator **modifies all the instructions for `mov`**(yeah, really cool). It also uses interruptions to change executions flows. For more information about how does it works:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

If you are lucky [demovfuscator](https://github.com/kirschju/demovfuscator) will deofuscate the binary. It has several dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
And [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

If you are playing a **CTF, this workaround to find the flag** could be very useful: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

To find the **entry point** search the functions by `::main` like in:

![](<../../images/image (1080).png>)

In this case the binary was called authenticator, so it's pretty obvious that this is the interesting main function.\
Having the **name** of the **functions** being called, search for them on the **Internet** to learn about their **inputs** and **outputs**.

## **Delphi**

For Delphi compiled binaries you can use [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

If you have to reverse a Delphi binary I would suggest you to use the IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Just press **ATL+f7** (import python plugin in IDA) and select the python plugin.

This plugin will execute the binary and resolve function names dynamically at the start of the debugging. After starting the debugging press again the Start button (the green one or f9) and a breakpoint will hit in the beginning of the real code.

It is also very interesting because if you press a button in the graphic application the debugger will stop in the function executed by that bottom.

## Golang

If you have to reverse a Golang binary I would suggest you to use the IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Just press **ATL+f7** (import python plugin in IDA) and select the python plugin.

This will resolve the names of the functions.

## Compiled Python

In this page you can find how to get the python code from an ELF/EXE python compiled binary:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

If you get the **binary** of a GBA game you can use different tools to **emulate** and **debug** it:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Contains a debugger with interface
- [**mgba** ](https://mgba.io)- Contains a CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_** ** you can see how to press the Game Boy Advance **buttons**

![](<../../images/image (581).png>)

When pressed, each **key has a value** to identify it:
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
이런 종류의 프로그램에서는 흥미로운 부분이 **프로그램이 사용자 입력을 어떻게 처리하는지**입니다. 주소 **0x4000130**에서 흔히 볼 수 있는 함수인 **KEYINPUT**을 찾을 수 있습니다.

![](<../../images/image (447).png>)

이전 이미지에서 이 함수가 **FUN_080015a8**에서 호출되는 것을 확인할 수 있습니다(주소: _0x080015fa_ 및 _0x080017ac_).

그 함수에서는 몇 가지 초기화 작업(중요하지 않음) 후에:
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
발견된 코드는 다음과 같습니다:
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
마지막 if는 **`uVar4`**가 **마지막 Keys**에 있는지, 그리고 현재 key가 아닌지를 확인합니다. 이것은 버튼에서 손을 떼는 것(현재 key는 **`uVar1`**에 저장됨)이라고도 합니다.
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
이전 code에서 볼 수 있듯이, 우리는 **uVar1** (**pressed button의 value**가 들어있는 위치)를 다음 값들과 비교하고 있습니다:

- 먼저, 이를 **value 4** (**SELECT** button)와 비교합니다: 이 challenge에서는 이 button이 screen을 clear합니다
- 그다음, 이를 **value 8** (**START** button)와 비교합니다: 이 challenge에서는 이 code가 valid한지 확인해서 flag를 얻습니다.
- 이 경우 **`DAT_030000d8`** var가 0xf3와 비교되며, 값이 같으면 일부 code가 실행됩니다.
- 다른 경우에는 어떤 cont (**`DAT_030000d4`**)가 checked 됩니다. 이것이 cont인 이유는 code에 들어간 직후 1을 더하기 때문입니다.\
**I**f 8보다 작으면 **`DAT_030000d8`**에 값을 **adding**하는 작업이 수행됩니다(기본적으로 cont가 8보다 작은 동안 이 var에 pressed key의 value들을 더합니다).

따라서 이 challenge에서는 button들의 value를 알고 있으므로, **length가 8보다 작은 combination을 눌러서 그 합이 0xf3이 되게 해야 합니다.**

**이 tutorial의 Reference:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

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
