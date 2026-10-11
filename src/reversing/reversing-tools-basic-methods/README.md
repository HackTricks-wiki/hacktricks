# 리버싱 도구 및 기본 기법

{{#include ../../banners/hacktricks-training.md}}

## ImGui 기반 리버싱 도구

소프트웨어:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windows 커널 디버깅

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm 디컴파일러 / Wat 컴파일러

온라인:

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)를 사용해 wasm(바이너리)을 wat(일반 텍스트)로 **디컴파일**
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)를 사용해 wat을 wasm으로 **컴파일**
- 디컴파일에는 [web-wasmdec](https://wwwg.github.io/web-wasmdec/)도 사용해 볼 수 있습니다.

소프트웨어:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 캐시된 바이트코드

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET 디컴파일러

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek은 **라이브러리**(.dll), **Windows 메타데이터 파일**(.winmd), **실행 파일**(.exe) 등 여러 형식을 **디컴파일하고 분석하는** 디컴파일러입니다. 디컴파일한 어셈블리는 Visual Studio 프로젝트(.csproj)로 저장할 수 있습니다.

레거시 어셈블리에서 손실된 소스 코드를 복원해야 하는 경우 이 도구를 사용하면 시간을 절약할 수 있습니다. 또한 dotPeek은 디컴파일된 코드를 편리하게 탐색할 수 있어 **Xamarin 알고리즘 분석**에 적합한 도구 중 하나입니다.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

포괄적인 add-in 모델과 필요에 맞게 도구를 확장하는 API를 갖춘 .NET Reflector는 시간을 절약하고 개발을 간소화합니다. 이 도구가 제공하는 다양한 리버스 엔지니어링 기능을 살펴보겠습니다.

- 라이브러리나 컴포넌트에서 데이터가 어떻게 흐르는지 파악할 수 있습니다.
- .NET 언어 및 프레임워크의 구현과 사용 방식에 대한 통찰력을 제공합니다.
- API와 사용 중인 기술을 더 폭넓게 활용할 수 있도록 문서화되지 않았거나 노출되지 않은 기능을 찾습니다.
- 종속성과 여러 어셈블리를 찾습니다.
- 코드, 타사 컴포넌트, 라이브러리에서 오류가 발생한 정확한 위치를 찾아냅니다.
- 작업 중인 모든 .NET 코드의 소스를 디버깅합니다.

### [ILSpy](https://github.com/icsharpcode/ILSpy) 및 [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code용 ILSpy 플러그인](https://github.com/icsharpcode/ilspy-vscode): 모든 OS에서 사용할 수 있습니다(VSCode에서 바로 설치할 수 있으므로 git을 다운로드할 필요가 없습니다. **Extensions**를 클릭한 다음 **ILSpy**를 검색하세요).\
**디컴파일**, **수정**, **재컴파일**이 필요하다면 [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) 또는 활발히 유지 관리되는 포크인 [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)를 사용할 수 있습니다. (**마우스 오른쪽 클릭 -> Modify Method**를 선택해 함수 내부를 변경하세요.)

### DNSpy 로깅

**DNSpy가 파일에 정보를 기록하도록** 하려면 다음 코드를 사용할 수 있습니다:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy 디버깅

DNSpy를 사용해 코드를 디버깅하려면 다음을 수행해야 합니다.

먼저 **디버깅**과 관련된 **어셈블리 특성**을 변경합니다.

![DNSpy Logging - DNSpy 디버깅: 먼저 디버깅과 관련된 어셈블리 특성을 변경합니다](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: 그리고 compile을 클릭합니다](<../../images/image (314) (1).png>)

그런 다음 _**File >> Save module...**_을 통해 새 파일을 저장합니다:

![DNSpy Logging - DNSpy Debugging: 그런 다음 File Save module을 통해 새 파일을 저장합니다](<../../images/image (602).png>)

이 작업은 필수입니다. 이렇게 하지 않으면 **runtime**에 코드에 여러 **최적화**가 적용되어, 디버깅 중에 **breakpoint가 적중되지 않거나** 일부 **변수가 존재하지 않을 수 있습니다**.

그런 다음 .NET 애플리케이션이 **IIS**에서 **실행 중**이라면 다음 명령으로 **재시작**할 수 있습니다:

```
iisreset /noforce
```

그런 다음 디버깅을 시작하려면 열려 있는 파일을 모두 닫고 **Debug Tab**에서 **Attach to Process...**를 선택합니다.

![DNSpy Logging - DNSpy Debugging: 디버깅을 시작하려면 열려 있는 파일을 모두 닫고 Debug Tab에서 Attach to Process를 선택합니다](<../../images/image (318).png>)

그런 다음 **w3wp.exe**를 선택해 **IIS server**에 연결하고 **attach**를 클릭합니다.

![DNSpy Logging - DNSpy Debugging: w3wp.exe를 선택해 IIS server에 연결하고 attach를 클릭합니다](<../../images/image (113).png>)

프로세스 디버깅을 시작했으니 이제 프로세스를 중지하고 모든 모듈을 로드해야 합니다. 먼저 _Debug >> Break All_을 클릭한 다음 _**Debug >> Windows >> Modules**_를 클릭합니다.

![DNSpy Logging - DNSpy Debugging: 프로세스 디버깅을 시작했으니 이제 프로세스를 중지하고 모든 모듈을 로드해야 합니다. 먼저 Debug Break All을 클릭한 다음 Debug Windows Modules를 클릭합니다](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: 프로세스 디버깅을 시작했으니 이제 프로세스를 중지하고 모든 모듈을 로드해야 합니다. 먼저 Debug Break All을 클릭한 다음 Debug Windows Modules를 클릭합니다](<../../images/image (834).png>)

**Modules**에서 모듈을 하나 클릭하고 **Open All Modules**를 선택합니다.

![DNSpy Logging - DNSpy Debugging: Modules에서 모듈을 하나 클릭하고 Open All Modules를 선택합니다](<../../images/image (922).png>)

**Assembly Explorer**에서 모듈을 하나 마우스 오른쪽 버튼으로 클릭하고 **Sort Assemblies**를 클릭합니다.

![DNSpy Logging - DNSpy Debugging: Assembly Explorer에서 모듈을 하나 마우스 오른쪽 버튼으로 클릭하고 Sort Assemblies를 클릭합니다](<../../images/image (339).png>)

## Java 디컴파일러

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL 디버깅

### IDA 사용

- **rundll32 로드** (64비트 버전은 C:\Windows\System32\rundll32.exe, 32비트 버전은 C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** 디버거 선택
- "**Suspend on library load/unload**" 선택

![Debugging DLLs - Using IDA: "Suspend on library load/unload" 선택](<../../images/image (868).png>)

- **parameters**에 **DLL 경로**와 호출하려는 함수를 지정하여 실행을 구성합니다.

![Debugging DLLs - Using IDA: DLL 경로와 호출하려는 함수를 지정하여 실행 parameters를 구성합니다](<../../images/image (704).png>)

그런 다음 디버깅을 시작하면 **각 DLL이 로드될 때 실행이 중지됩니다**. 따라서 rundll32가 DLL을 로드하면 실행이 중지됩니다.

이 방법은 모듈 로드 이벤트에서 중지하지만, 아래의 x64dbg 워크플로와 비교하면 로드된 DLL의 entry point에 도달하는 과정이 덜 직접적입니다.

### x64dbg/x32dbg 사용

- **rundll32 로드** (64비트 버전은 C:\Windows\System32\rundll32.exe, 32비트 버전은 C:\Windows\SysWOW64\rundll32.exe)
- **Command Line 변경** ( _File --> Change Command Line_ ) 후 DLL 경로와 호출하려는 함수를 지정합니다. 예: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_를 변경하고 "**DLL Entry**"를 선택합니다.
- 그런 다음 **실행을 시작**합니다. 디버거는 각 dll main에서 중지되며, 어느 시점에 **사용자 DLL의 DLL Entry에서 중지됩니다**. 여기서부터 breakpoint를 설정하려는 지점을 찾으면 됩니다.

win64dbg에서 어떤 이유로든 실행이 중지되면 **win64dbg 창 상단**에서 **현재 어떤 코드에 있는지** 확인할 수 있습니다.

![Using IDA - Using x64dbg/x32dbg: 실행이 어떤 이유로든 win64dbg에서 중지되면 win64dbg 창 상단에서 현재 어떤 코드에 있는지 확인할 수 있습니다](<../../images/image (842).png>)

이 표시를 통해 디버깅하려는 DLL 내부에서 실행이 중지되었는지 확인할 수 있습니다.

## GUI 앱 / 비디오게임

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)은 실행 중인 게임의 메모리에서 중요한 값이 저장된 위치를 찾고 값을 변경하는 데 유용한 프로그램입니다. 자세한 내용은 다음을 참고하세요.

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE)는 게임에 초점을 맞춘 GNU Project Debugger (GDB)용 프런트엔드/리버스 엔지니어링 도구입니다. 하지만 리버스 엔지니어링과 관련된 모든 작업에 사용할 수 있습니다.

[**Decompiler Explorer**](https://dogbolt.org/)는 여러 디컴파일러를 위한 웹 프런트엔드입니다. 이 웹 서비스에서는 작은 실행 파일을 여러 디컴파일러로 디컴파일한 결과를 비교할 수 있습니다.

## ARM & MIPS

{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner로 shellcode 디버깅하기

[**BlobRunner**](https://github.com/OALabs/BlobRunner)는 **shellcode**를 할당하고 **메모리 주소**를 출력한 다음 실행을 일시 중지합니다.\
IDA 또는 x64dbg 같은 디버거를 연결하고, 출력된 주소에 breakpoint를 설정한 뒤 실행을 재개하여 shellcode를 디버깅합니다.

릴리스 GitHub 페이지에는 컴파일된 릴리스가 포함된 zip 파일이 있습니다: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
다음 링크에서 약간 수정된 Blobrunner 버전을 찾을 수 있습니다. 컴파일하려면 **Visual Studio Code에서 C/C++ 프로젝트를 만들고 코드를 복사해 붙여넣은 다음 빌드하면 됩니다**.

{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it으로 shellcode 디버깅하기

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)는 BlobRunner와 비슷합니다. shellcode를 할당하고 무한 루프에 진입합니다. 디버거를 연결하고 **2–5초** 동안 실행을 재개한 다음, 루프 안에서 일시 중지하고 할당된 shellcode로 실행을 전달하는 다음 호출까지 step합니다.

![jmp2it의 무한 루프에서 할당된 shellcode를 호출하기 직전에 일시 중지된 디버거](<../../images/image (509).png>)

[jmp2it 릴리스 페이지에서](https://github.com/adamkramer/jmp2it/releases/) 컴파일된 버전을 다운로드할 수 있습니다.

### Cutter를 사용한 shellcode 디버깅

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)는 radare의 GUI입니다. Cutter를 사용하면 shellcode를 에뮬레이션하고 동적으로 검사할 수 있습니다.

Cutter에서는 "Open File"과 "Open Shellcode"를 사용할 수 있습니다. 제 경우 shellcode를 파일로 열었을 때는 올바르게 디컴파일했지만, shellcode로 열었을 때는 그렇지 않았습니다.

![동일한 바이트를 파일 또는 shellcode로 열었을 때 서로 다른 분석 결과를 표시하는 Cutter](<../../images/image (562).png>)

원하는 위치에서 에뮬레이션을 시작하려면 해당 위치에 bp를 설정하면 됩니다. Cutter가 그 위치부터 자동으로 에뮬레이션을 시작하는 것 같습니다.

![Cutter 에뮬레이션을 시작하기 전에 원하는 shellcode 진입점에 breakpoint 설정](<../../images/image (589).png>)

![선택한 shellcode breakpoint에서 일시 중지된 Cutter 에뮬레이터](<../../images/image (387).png>)

예를 들어 hex dump에서 스택을 확인할 수 있습니다.

![Cutter의 hex dump에서 에뮬레이션된 shellcode 스택 확인](<../../images/image (186).png>)

### shellcode 난독화 해제 및 실행된 함수 확인

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)를 사용해 보세요.\
shellcode가 사용하는 **함수**와 메모리에서 스스로 **디코딩**하는지 여부 등을 알려줍니다.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg에는 원하는 옵션을 선택하고 shellcode를 실행할 수 있는 그래픽 런처도 있습니다.

![shellcode 에뮬레이션 및 tracing 옵션을 선택하는 scDbg 그래픽 런처](<../../images/image (258).png>)

**Create Dump** 옵션은 메모리에서 shellcode가 동적으로 변경된 경우 최종 shellcode를 덤프합니다(디코딩된 shellcode를 다운로드할 때 유용합니다). **start offset**을 사용하면 특정 오프셋에서 shellcode를 시작할 수 있습니다. **Debug Shell** 옵션은 scDbg 터미널을 사용해 shellcode를 디버깅할 때 유용합니다(하지만 이 작업에는 앞서 설명한 옵션 중 하나가 더 낫다고 생각합니다. Ida 또는 x64dbg를 사용할 수 있기 때문입니다).

### CyberChef를 사용한 Disassembling

shellcode 파일을 입력으로 업로드한 다음, 다음 recipe를 사용해 디스어셈블하세요: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation은 산술 연산자(`+`, `-`, `*`)와 비트 연산자(`&`, `|`, `^`, `~`, shift)를 조합한 수식으로 `x + y`와 같은 간단한 표현식을 숨깁니다. 중요한 점은 이런 항등식이 일반적으로 **고정 너비 모듈러 산술**에서만 성립한다는 것입니다. 따라서 carry와 overflow가 중요합니다:

```c
(x ^ y) + 2 * (x & y) == x + y
```

이런 종류의 표현을 일반 대수 도구로 단순화하면 비트 폭 의미를 무시했기 때문에 잘못된 결과를 얻기 쉽습니다.<sup>[[1]](#references)</sup>

### 실용적인 작업 흐름

1. lift된 코드/IR/decompiler 출력의 **원래 비트 폭**(`8/16/32/64` bits)을 유지합니다.
2. 단순화를 시도하기 전에 표현식을 **분류**합니다.
   - **Linear**: 비트 연산 원자들의 가중 합
   - **Semilinear**: `x & 0xFF`와 같은 상수 마스크에 선형 연산을 더한 것
   - **Polynomial**: 곱셈이 포함됨
   - **Mixed**: 곱셈과 비트 논리가 서로 얽혀 있으며, 반복되는 부분식이 자주 나타남
3. 모든 후보 재작성을 random testing이나 SMT proof로 검증합니다. 동등성을 증명할 수 없다면 추측하는 대신 원래 표현식을 유지합니다.

### 좁은 실행 슬라이스로 평탄화된 제어 흐름 우회

완전한 control-flow graph를 복구할 필요가 없는 경우가 많습니다. control-flow flattening, opaque predicate, 대규모 dispatcher 또는 MBA-heavy 코드가 있는 경우, 암호화된 blob과 output buffer에서 참조를 따라가 이를 변환하는 가장 작은 루틴을 찾습니다. 그런 다음 해당 data-flow slice만 재현하거나 독립적으로 실행합니다. 관련 state를 직접 초기화할 수 있다면 dispatcher는 필수 해결 요소가 아닙니다.<sup>[[7]](#references)</sup>

실용적인 작업 흐름은 다음과 같습니다.<sup>[[7]](#references)</sup>

1. 실행 파일 및 데이터 섹션, relocation, cross-reference를 목록화합니다. `.rodata`에서 후보 테이블을 덤프할 때 바이트 순서와 요소 너비를 유지합니다.
2. plaintext 또는 output buffer에 마지막으로 쓰는 루틴을 찾습니다. 해당 루틴의 입력, 참조 테이블, imported call, 필요한 global state를 기록합니다.
3. 해당 연산만 고정 너비 Python 모델로 lift합니다. 이 슬라이스가 여전히 너무 많은 state에 의존한다면, 전체 프로그램을 에뮬레이션하는 대신 Unicorn, QEMU 또는 debugger로 루틴을 호출하고 관련 없는 import를 hook합니다.
4. extractor가 실제로 제공된 binary에서 출력을 도출하는지 검증합니다. 조용한 fallback을 제거하고, binary 안에 답이 포함되어 있는지 검색하며, 문자열, 키, 식별자, 레이아웃, obfuscation seed가 바뀐 미확인 빌드에서도 실행합니다.

첫 단계에서 유용한 명령은 다음과 같습니다.<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 상수로 위장한 MBA 표현식 탐지

겉보기에는 입력에 따라 달라지는 바이트 표현식이 입력을 완전히 상쇄할 수 있습니다. 테이블을 추출한 후 전체 8비트 도메인에 대해 표현식을 평가합니다. 출력 집합에 값이 하나뿐이라면 주변 상태 머신을 복원하지 않고도 해당 바이트가 상수임을 증명할 수 있습니다.<sup>[[7]](#references)</sup>

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

최종 mask를 유지하세요. 원래 덧셈에는 바이트 너비에서의 wraparound가 있기 때문입니다. 더 넓은 도메인에서는 SMT solver에 동일한 너비의 symbolic input 두 개에 대해 `f(x1) != f(x2)`가 satisfiable한지 물어보세요. `unsat`이면 불변성이 증명되고, `sat`이면 반례가 제공되므로 해당 입력을 버릴 수 없습니다.<sup>[[7]](#references)</sup>

#### 환경에 종속된 디코딩 식별

Anti-analysis 검사는 분기하거나 충돌을 일으킬 필요가 없습니다. 디코더는 센서 결과를 키 비트, opaque predicate 상수 또는 flattened dispatcher 상태에 섞고, 정상적으로 계속 실행하여 에뮬레이터에서 그럴듯하지만 잘못된 평문을 생성할 수 있습니다. 따라서 눈에 보이는 실패 분기만 패치하는 것으로는 충분하지 않습니다. 환경 프로브에서 디코더 상태로 이어지는 데이터 종속성을 추적하고, 실제 기기와 에뮬레이터에서 같은 슬라이스를 비교한 다음, 각 센서 결과를 강제로 설정했을 때 최종 버퍼가 어떻게 달라지는지 테스트하세요.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA)는 malware 분석과 protected binary reversing을 위한 실용적인 MBA simplifier입니다. 모든 항목에 하나의 일반적인 rewrite pass를 적용하는 대신, 표현식을 분류하고 전문화된 파이프라인으로 전달합니다.<sup>[[2]](#references)</sup>

빠른 사용법:

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

- **Linear MBA**: CoBRA는 Boolean 입력에서 식을 평가하고, 시그니처를 도출한 다음, 패턴 매칭, ANF 변환, 계수 보간 등 여러 복구 방법을 동시에 실행합니다.
- **Semilinear MBA**: 상수 마스크가 적용된 원자는 비트 분할 재구성을 통해 다시 만들어 마스크된 영역이 올바르게 유지되도록 합니다.
- **Polynomial/Mixed MBA**: 곱을 핵심 항으로 분해하고, 반복되는 부분식을 임시 변수로 끌어올린 뒤 외부 관계를 단순화할 수 있습니다.

복구를 시도해 볼 만한 흔한 혼합 항등식의 예:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

다음과 같이 축약할 수 있습니다:

```c
x * y
```

### Reversing 참고 사항

- 정확한 연산을 분리한 후 CoBRA를 **lifted IR expressions** 또는 decompiler 출력에 적용하는 것이 좋습니다.
- 표현식이 masked arithmetic 또는 narrow registers에서 나온 경우 `--bitwidth`를 명시적으로 사용하세요.
- 더 강력한 증명 단계가 필요하다면 여기의 Z3 참고 사항을 확인하세요:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA는 **LLVM pass plugin**(`libCobraPass.so`)으로도 제공됩니다. 이후 분석 pass를 실행하기 전에 MBA가 많은 LLVM IR을 정규화할 때 유용합니다.
- 지원되지 않는 carry-sensitive mixed-domain residuals는 원래 표현식을 유지하고 carry 경로를 수동으로 분석해야 한다는 신호로 취급해야 합니다.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

이 obfuscator는 프로그램 연산을 `mov` 기반 명령어 시퀀스로 대체하고 signal/exception handling을 사용해 control flow를 변경합니다. 자세한 내용은 다음을 참조하세요.

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

지원되는 바이너리의 경우 [demovfuscator](https://github.com/kirschju/demovfuscator)를 사용해 결과를 deobfuscate할 수 있습니다. 몇 가지 종속성이 필요합니다.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

그리고 [keystone을 설치](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTF를 하고 있다면, flag를 찾기 위한 이 우회 방법**이 매우 유용할 수 있습니다: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**진입점**을 찾으려면 다음과 같이 `::main`을 검색해 함수들을 살펴보세요.

![함수 이름에서 이중 콜론 main을 검색해 Ghidra에서 Rust 진입점을 찾는 모습](<../../images/image (1080).png>)

이 경우 바이너리 이름이 authenticator였으므로, 이것이 관심을 가질 만한 main 함수라는 점은 꽤 분명합니다.\
호출되는 **함수**의 **이름**을 확인한 뒤, **입력**과 **출력**을 알아보려면 **인터넷**에서 해당 이름을 검색하세요.

### ELF 펌웨어에서 Rust 문자열 복구하기

**Rust ELF** 바이너리에서는 많은 정적 문자열이 C 스타일의 NUL 종료 포인터로 참조되지 않습니다. 일반적인 `rustc` 레이아웃은 **`.data.rel.ro`** 안에 있는 **포인터/길이 튜플**이 실제 문자열 데이터가 저장된 **`.rodata`**를 가리키는 형태입니다:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

이는 `strings` 또는 기본 Ghidra 분석이 인접한 문자열을 병합하거나 교차 참조를 완전히 놓칠 수 있다는 뜻입니다.<sup>[[3]](#references)</sup>

빠른 워크플로:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`**의 가상 주소와 크기를 가져옵니다.
2. **`.data.rel.ro`**를 한 워드씩 열거합니다.
3. **`.rodata`** 주소 범위 안의 값을 문자열 포인터 후보로 간주합니다.
4. 다음 워드를 후보 길이로 간주합니다.
5. 유효성 필터를 적용합니다(예: 길이가 **4**~**100**바이트인 항목만 유지).
6. `0x00`까지 스캔하는 대신 `.rodata`에서 `length`바이트를 정확히 읽습니다.

최소 extractor 로직:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

이는 firmware reversing에서 특히 유용합니다. 복구된 Rust 문자열을 통해 **HTTP 경로, RPC 이름, 로그 메시지, assertion, 파일 이름, config 키, command handler, 인증 관련 로직**을 확인할 수 있습니다.

Ghidra가 이러한 문자열을 놓치면, 동일한 휴리스틱을 적용하고 참조된 `.rodata` 오프셋에 문자열 데이터를 생성하는 custom script/plugin을 실행하세요. Pen Test Partners가 공개한 `rust-strings`와 `RustStrings.py` 도구는 이 아이디어를 다른 **word size, endianness, section layout**에 맞게 적용할 때 참고하기 좋습니다.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi 컴파일 바이너리에는 [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)을 사용할 수 있습니다.

Delphi 바이너리를 reverse해야 한다면 IDA plugin인 [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)를 사용하는 것을 권장합니다.

IDA에서 **Alt+F7**을 눌러 Python plugin을 불러온 다음 plugin 파일을 선택하세요.

이 plugin은 디버깅을 시작할 때 바이너리를 실행하고 함수 이름을 동적으로 확인합니다. 디버깅을 시작한 후 Start 버튼(초록색 버튼 또는 f9)을 다시 누르면 실제 코드의 시작 부분에서 breakpoint가 발생합니다.

그래픽 애플리케이션에서 버튼을 누르면 디버거가 해당 버튼으로 호출된 함수에서 멈출 수 있습니다.

## Golang

일반적인 Go 바이너리의 경우 [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)를 사용하면 runtime 구조를 복구하고 IDA에서 함수 이름을 개선할 수 있습니다. **Alt+F7**을 눌러 Python plugin을 불러오세요.

### 심볼 테이블 없이 메타데이터 복구하기

stripped Go 실행 파일도 program counter를 함수에 연결하려면 runtime 메타데이터가 필요합니다. [GoReSym](https://github.com/mandiant/GoReSym)은 Go runtime에서 파생된 코드를 사용해 `pclntab` 및 `moduledata` 같은 구조를 찾아 파싱합니다. 이를 통해 기존 심볼 테이블에 의존하지 않고 함수 경계, 이름, 소스 경로, 타입, 빌드 정보를 복구할 수 있습니다.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

난독화 도구는 복구된 이름을 바꾸면서도 해당 구조를 사용할 수 있는 상태로 남겨둘 수 있습니다. 예를 들어 Garble은 식별자와 패키지 경로를 해시하고 build, module 및 debug 정보를 제거합니다.<sup>[[12]](#references)</sup> 난독화된 패키지 토큰은 해당 패키지의 함수들에서 일관되게 유지되어야 합니다. 반복되는 토큰을 기준으로 함수를 그룹화하고, 호출 대상, 문자열 및 API를 통해 패키지 하나를 추론한 다음 해당 패키지 레이블을 그룹 전체에 적용합니다.<sup>[[13]](#references)</sup>

### GoResolver로 Garble 이름 복구하기

[GoResolver](https://github.com/volexity/GoResolver)는 runtime-symbol 추출과 clean-reference 생성 및 control-flow-graph (CFG) 매칭을 결합합니다. 다음 순서로 진행합니다:<sup>[[10]](#references)[[13]](#references)</sup>

1. **컴파일러 버전을 식별합니다.** 먼저 `BuildInfo`와 내장된 버전 문자열을 확인합니다. 난독화 도구가 이를 제거했다면, 번들에 포함된 Go runtime의 일부를 버전별 참조 runtime과 비교합니다. Volexity의 테스트에서는 runtime의 약 `2%`만으로도 주요 Go 버전을 구분할 수 있었습니다. 이를 보편적인 기준이 아니라 경험적 최적화로 간주하세요.<sup>[[13]](#references)</sup>
2. **매칭할 참조 바이너리를 빌드합니다.** 식별한 Go 버전, 대상 아키텍처 및 사용 가능성이 높은 라이브러리에 맞춰 clean 바이너리를 생성합니다. toolchain을 일치시키면 컴파일러가 생성한 CFG의 차이를 줄일 수 있습니다.<sup>[[10]](#references)[[13]](#references)</sup>
3. **함수를 비교합니다.** GoGrapher는 함수 CFG를 매칭하고 `0.0`부터 `1.0`까지 정규화된 점수를 출력합니다. 기본 블록 매칭은 유사한 명령어를 가중 비교하는 방식입니다. 신뢰도가 높은 매칭을 통해 무작위화된 함수와 clean 구현을 연결합니다. 신뢰도가 낮은 매칭으로도 패키지나 모듈을 식별할 수 있습니다.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **검증하고 가져옵니다.** 호출 관계, 상수, 문자열 및 부수 효과를 사용해 제안된 이름을 확인한 다음, IDA 또는 Ghidra용 GoResolver plugin으로 JSON 보고서를 가져옵니다.<sup>[[10]](#references)[[13]](#references)</sup>

toolchain을 설치하고 통합 extractor 및 graph matcher를 실행합니다:<sup>[[10]](#references)</sup>

```bash
python3 -m venv goresolver-env
source goresolver-env/bin/activate
pip install goresolver

# Automatic Go-version detection and reference selection
goresolver resolve -o report.json /path/to/sample.exe

# Override the version/libraries and confidence threshold when known
goresolver resolve -v go1.23.4 -l os/exec net/http \
  -t 0.9 -o report.json /path/to/sample.exe
```

기본 significant-match 임계값은 `0.9`입니다. `--extract` 및 `--graph` 스위치를 사용하면 각 단계를 따로 실행할 수 있으며, 복구한 런타임 메타데이터와 CFG 증거가 서로 보완되므로 기본적으로는 두 단계 모두 실행됩니다.<sup>[[10]](#references)</sup> CFG 점수는 휴리스틱입니다. 인라이닝, 빌드 플래그, 아키텍처, 라이브러리 버전 차이에 따라 그래프 형태가 달라질 수 있으므로, 신뢰도가 낮은 이름을 억지로 지정하는 대신 해결되지 않은 함수는 그대로 두세요.<sup>[[13]](#references)</sup>

## 컴파일된 Python

이 페이지에서는 ELF/EXE Python 컴파일 바이너리에서 Python 코드를 가져오는 방법을 확인할 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBA 게임의 **binary**를 구했다면 여러 도구를 사용해 이를 **에뮬레이션**하고 **디버그**할 수 있습니다:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_디버그 버전 다운로드_) - 인터페이스가 포함된 디버거
- [**mgba** ](https://mgba.io)- CLI 디버거
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra 플러그인
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra 플러그인

[**no$gba**](https://problemkaputt.de/gba.htm)에서 _**Options --> Emulation Setup --> Controls**_** **로 이동하면 Game Boy Advance **버튼**을 누르는 방법을 확인할 수 있습니다.

![Game Boy Advance 버튼 매핑을 보여주는 no$gba 컨트롤 설정](<../../images/image (581).png>)

누르면 각 **키에는 이를 식별하는 값**이 지정됩니다:

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

따라서 이런 종류의 프로그램에서 흥미로운 부분은 **프로그램이 사용자 입력을 어떻게 처리하는지**입니다. 주소 **0x4000130**에서 흔히 볼 수 있는 함수인 **KEYINPUT**을 찾을 수 있습니다.

![주소 0x4000130의 KEYINPUT을 참조하는 GBA 바이너리의 Ghidra 뷰](<../../images/image (447).png>)

이전 이미지에서 이 함수가 **FUN_080015a8**에서 호출되는 것을 확인할 수 있습니다(주소: _0x080015fa_ 및 _0x080017ac_).

이 함수에서는 몇 가지 초기화 작업을 수행한 다음(중요하지 않음):

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

마지막 if문은 **`uVar4`**가 **마지막 Keys**에 포함되어 있지만 현재 키는 아닌지 확인합니다. 즉, 버튼에서 손을 떼는 동작입니다(현재 키는 **`uVar1`**에 저장됩니다).

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

이전 코드에서 **uVar1**(**눌린 버튼의 값**이 저장된 위치)을 몇 가지 값과 비교하는 것을 볼 수 있습니다.

- 먼저 **값 4**(**SELECT** 버튼)와 비교합니다. 이 challenge에서 이 버튼을 누르면 화면이 지워집니다.
- 그런 다음 **값 8**(**START** 버튼)과 비교합니다. 이 challenge에서는 해당 경로에서 입력한 코드가 유효한지 확인합니다.
  - 이 경우 변수 **`DAT_030000d8`**을 0xf3과 비교하며, 값이 같으면 일부 코드가 실행됩니다.
- 그 외의 경우에는 카운터(`DAT_030000d4`)를 확인한 뒤 증가시킵니다.\
  카운터가 8보다 작은 동안 눌린 키의 값이 `DAT_030000d8`에 누적됩니다.

따라서 이 challenge에서는 버튼의 값을 알고 있다면, **길이가 8보다 짧고 더한 결과가 0xf3이 되는 버튼 조합을 눌러야 합니다.**

**이 튜토리얼의 참고 자료:** [보존된 Nostalgia challenge 풀이](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## 강의

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [MBA 난독화 간소화: CoBRA 활용](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA 저장소](https://github.com/trailofbits/CoBRA)
- [3] [Rust 문자열 디코딩 - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing 튜토리얼 (보존본)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI 지원 reverse engineering 무력화하기, 또는 적어도 시도하기](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Basic block 매칭을 기반으로 한 Control Flow Graph 비교 접근법](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble 난독화 메커니즘](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Control-Flow Graph 유사성을 활용해 Golang 바이너리를 자동으로 난독화 해제하기](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
