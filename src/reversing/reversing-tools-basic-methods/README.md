# Reversing 도구 및 기본 방법

{{#include ../../banners/hacktricks-training.md}}

## ImGui 기반 Reversing 도구

소프트웨어:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windows 커널 디버깅

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm 디컴파일러 / Wat 컴파일러

온라인:

- wasm(바이너리)을 wat(일반 텍스트)로 **decompile**하려면 [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)을 사용하세요.
- wat을 wasm으로 **compile**하려면 [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)을 사용하세요.
- 디컴파일에는 [web-wasmdec](https://wwwg.github.io/web-wasmdec/)도 사용해 볼 수 있습니다.

소프트웨어:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 캐시 바이트코드

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET 디컴파일러

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek은 **라이브러리**(.dll), **Windows 메타데이터 파일**(.winmd), **실행 파일**(.exe) 등 다양한 형식을 **디컴파일하고 분석하는** 디컴파일러입니다. 디컴파일한 어셈블리는 Visual Studio 프로젝트(.csproj)로 저장할 수 있습니다.

레거시 어셈블리에서 잃어버린 소스 코드를 복구해야 하는 경우 이 기능으로 시간을 절약할 수 있습니다. 또한 dotPeek은 디컴파일된 코드를 편리하게 탐색할 수 있어 **Xamarin 알고리즘 분석에** 적합한 도구 중 하나입니다.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

포괄적인 add-in 모델과 필요에 맞게 도구를 확장하는 API를 갖춘 .NET Reflector는 시간을 절약하고 개발을 간소화합니다. 이 도구가 제공하는 다양한 reverse engineering 기능을 살펴보겠습니다.

- 라이브러리나 컴포넌트를 통해 데이터가 흐르는 방식을 파악할 수 있습니다.
- .NET 언어와 프레임워크의 구현 및 사용법을 파악할 수 있습니다.
- 문서화되지 않았거나 노출되지 않은 기능을 찾아 API와 사용 기술을 더 폭넓게 활용할 수 있습니다.
- 종속성과 여러 어셈블리를 찾을 수 있습니다.
- 코드, 서드파티 컴포넌트, 라이브러리에서 오류가 발생한 정확한 위치를 찾을 수 있습니다.
- 사용하는 모든 .NET 코드의 소스를 디버깅할 수 있습니다.

### [ILSpy](https://github.com/icsharpcode/ILSpy) 및 [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code용 ILSpy 플러그인](https://github.com/icsharpcode/ilspy-vscode): 모든 OS에서 사용할 수 있습니다(VSCode에서 바로 설치할 수 있으므로 git을 다운로드할 필요가 없습니다. **Extensions**를 클릭하고 **ILSpy를 검색**하세요).\
**decompile**하고 **수정한 뒤** 다시 **recompile**해야 한다면 [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) 또는 활발히 유지 관리되는 fork인 [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)를 사용할 수 있습니다. (함수 내부를 변경하려면 **Right Click -> Modify Method**를 선택하세요.)

### DNSpy 로깅

**DNSpy가 일부 정보를 파일에 기록하도록** 하려면 다음 스니펫을 사용할 수 있습니다.

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy 디버깅

DNSpy를 사용해 코드를 디버깅하려면 다음을 수행해야 합니다.

먼저 **디버깅**과 관련된 **Assembly 특성**을 변경합니다.

![DNSpy Logging - DNSpy 디버깅: 먼저 디버깅과 관련된 Assembly 특성을 변경합니다](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

그런 다음 _**File >> Save module...**_을 통해 새 파일을 저장합니다:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

이 과정을 거쳐야 합니다. 그렇지 않으면 **runtime**에 코드에 여러 **최적화**가 적용되어, 디버깅 중에 **break-point가 한 번도 적중하지 않거나** 일부 **변수가 존재하지 않을** 수 있습니다.

그런 다음 .NET 애플리케이션이 **IIS**에서 **실행 중**이라면 다음 명령으로 **다시 시작**할 수 있습니다:

```
iisreset /noforce
```

그런 다음 디버깅을 시작하려면 열려 있는 파일을 모두 닫고 **Debug Tab**에서 **Attach to Process...**를 선택합니다:

![DNSpy Logging - DNSpy Debugging: 디버깅을 시작하려면 열려 있는 파일을 모두 닫고 Debug Tab에서 Attach to Process를 선택합니다](<../../images/image (318).png>)

그런 다음 **w3wp.exe**를 선택해 **IIS server**에 연결하고 **attach**를 클릭합니다:

![DNSpy Logging - DNSpy Debugging: w3wp.exe를 선택해 IIS server에 연결한 다음 attach를 클릭합니다](<../../images/image (113).png>)

이제 프로세스를 디버깅하고 있으므로 프로세스를 중지하고 모든 모듈을 로드할 차례입니다. 먼저 _Debug >> Break All_을 클릭한 다음 _**Debug >> Windows >> Modules**_를 클릭합니다:

![DNSpy Logging - DNSpy Debugging: 프로세스를 디버깅하고 있으므로 프로세스를 중지하고 모든 모듈을 로드합니다. 먼저 Debug Break All을 클릭한 다음 Debug Windows Modules를 클릭합니다](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: 프로세스를 디버깅하고 있으므로 프로세스를 중지하고 모든 모듈을 로드합니다. 먼저 Debug Break All을 클릭한 다음 Debug Windows Modules를 클릭합니다](<../../images/image (834).png>)

**Modules**에서 아무 모듈이나 클릭하고 **Open All Modules**를 선택합니다:

![DNSpy Logging - DNSpy Debugging: Modules에서 아무 모듈이나 클릭하고 Open All Modules를 선택합니다](<../../images/image (922).png>)

**Assembly Explorer**에서 아무 모듈이나 마우스 오른쪽 버튼으로 클릭하고 **Sort Assemblies**를 클릭합니다:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer에서 아무 모듈이나 마우스 오른쪽 버튼으로 클릭하고 Sort Assemblies를 클릭합니다](<../../images/image (339).png>)

## Java 디컴파일러

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL 디버깅

### IDA 사용

- **rundll32 로드** (64비트는 C:\Windows\System32\rundll32.exe, 32비트는 C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** debugger를 선택합니다
- "**Suspend on library load/unload**"를 선택합니다

![DLL 디버깅 - IDA 사용: "Suspend on library load/unload"를 선택합니다](<../../images/image (868).png>)

- 실행 **parameters**를 설정하고, **DLL 경로**와 호출하려는 함수를 입력합니다:

![DLL 디버깅 - IDA 사용: DLL 경로와 호출하려는 함수를 입력해 실행 parameters를 설정합니다](<../../images/image (704).png>)

그러면 디버깅을 시작할 때 **각 DLL이 로드될 때 실행이 중지됩니다**. 따라서 rundll32가 DLL을 로드하면 실행이 중지됩니다.

이 방법은 모듈 로드 이벤트에서 중지하지만, 아래의 x64dbg 워크플로와 비교하면 로드된 DLL의 entry point에 도달하는 과정이 덜 직접적입니다.

### x64dbg/x32dbg 사용

- **rundll32 로드** (64비트는 C:\Windows\System32\rundll32.exe, 32비트는 C:\Windows\SysWOW64\rundll32.exe)
- **Command Line 변경** ( _File --> Change Command Line_ ) 후 DLL 경로와 호출하려는 함수를 설정합니다. 예: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_를 변경하고 "**DLL Entry**"를 선택합니다.
- 그런 다음 **실행을 시작**합니다. 디버거는 각 DLL main에서 중지되며, 어느 시점에 **대상 DLL의 DLL Entry에서 중지됩니다**. 여기서부터 브레이크포인트를 설정하려는 지점을 찾으면 됩니다.

win64dbg에서 어떤 이유로든 실행이 중지되면 **win64dbg 창 상단에서 현재 어떤 코드에 있는지** 확인할 수 있습니다:

![IDA 사용 - x64dbg/x32dbg 사용: 실행이 어떤 이유로든 중지되면 win64dbg 창 상단에서 현재 어떤 코드에 있는지 확인할 수 있습니다](<../../images/image (842).png>)

이 표시를 통해 디버깅하려는 DLL 내부에서 실행이 중지되었는지 확인할 수 있습니다.

## GUI 앱 / 비디오 게임

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)은 실행 중인 게임의 메모리에서 중요한 값이 저장된 위치를 찾고 해당 값을 변경하는 데 유용한 프로그램입니다. 자세한 내용은 다음을 참고하세요:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE)는 게임에 초점을 둔 GNU Project Debugger (GDB)용 front-end/reverse engineering 도구입니다. 하지만 reverse engineering과 관련된 작업이라면 무엇이든 사용할 수 있습니다.

[**Decompiler Explorer**](https://dogbolt.org/)는 여러 디컴파일러를 위한 웹 front-end입니다. 이 웹 서비스에서는 소규모 실행 파일을 대상으로 다양한 디컴파일러의 출력을 비교할 수 있습니다.

## ARM 및 MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode

### blobrunner로 Shellcode 디버깅하기

[**BlobRunner**](https://github.com/OALabs/BlobRunner)는 **shellcode**를 할당하고 **메모리 주소**를 출력한 다음 실행을 일시 중지합니다.\
IDA 또는 x64dbg 같은 디버거를 연결하고 출력된 주소에 브레이크포인트를 설정한 후 실행을 재개하면 shellcode를 디버깅할 수 있습니다.

releases github 페이지에서 컴파일된 릴리스가 포함된 zip 파일을 받을 수 있습니다: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
다음 링크에서 약간 수정된 Blobrunner 버전을 찾을 수 있습니다. 컴파일하려면 **Visual Studio Code에서 C/C++ 프로젝트를 만들고 코드를 복사해 붙여넣은 다음 빌드하면 됩니다**.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it으로 Shellcode 디버깅하기

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)은 BlobRunner와 유사합니다. shellcode를 할당하고 무한 루프에 진입합니다. 디버거를 연결하고 **2~5초간** 실행을 재개한 다음 해당 루프 안에서 일시 중지하고, 실행을 할당된 shellcode로 전달하는 다음 call까지 step합니다.

![jmp2it의 무한 루프에서 할당된 shellcode를 호출하기 직전에 일시 중지된 디버거](<../../images/image (509).png>)

컴파일된 버전은 [releases 페이지에서 jmp2it 다운로드](https://github.com/adamkramer/jmp2it/releases/)할 수 있습니다.

### Cutter를 사용해 Shellcode 디버깅하기

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)는 radare의 GUI입니다. Cutter를 사용하면 shellcode를 에뮬레이션하고 동적으로 검사할 수 있습니다.

Cutter에서는 "Open File"과 "Open Shellcode"를 선택할 수 있습니다. 제 경우 shellcode를 파일로 열었을 때는 올바르게 디컴파일했지만, shellcode로 열었을 때는 그렇지 않았습니다:

![같은 바이트를 파일 또는 shellcode로 열었을 때 서로 다른 분석 결과를 표시하는 Cutter](<../../images/image (562).png>)

원하는 위치에서 에뮬레이션을 시작하려면 그 위치에 bp를 설정합니다. 그러면 Cutter가 해당 위치에서 자동으로 에뮬레이션을 시작하는 것 같습니다:

![Cutter 에뮬레이션을 시작하기 전에 원하는 shellcode 진입점에 브레이크포인트 설정](<../../images/image (589).png>)

![선택한 shellcode 브레이크포인트에서 일시 중지된 Cutter 에뮬레이터](<../../images/image (387).png>)

예를 들어 hex dump에서 스택을 확인할 수 있습니다:

![Cutter의 hex dump에서 에뮬레이션된 shellcode 스택 확인](<../../images/image (186).png>)

### Shellcode 난독화 해제 및 실행된 함수 확인하기

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)를 사용해 보세요.\
shellcode에서 **어떤 함수**를 사용하는지, 메모리에서 shellcode가 스스로 **디코딩**되는지 등의 정보를 알려줍니다.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg에는 원하는 옵션을 선택하고 shellcode를 실행할 수 있는 그래픽 런처도 있습니다.

![shellcode 에뮬레이션 및 추적 옵션을 선택하기 위한 scDbg 그래픽 런처](<../../images/image (258).png>)

**Create Dump** 옵션은 메모리에서 shellcode가 동적으로 변경된 경우 최종 shellcode를 덤프합니다(디코딩된 shellcode를 다운로드할 때 유용합니다). **start offset**을 지정하면 특정 오프셋에서 shellcode를 시작할 수 있습니다. **Debug Shell** 옵션을 사용하면 scDbg 터미널에서 shellcode를 디버깅할 수 있습니다(하지만 이 경우 앞에서 설명한 옵션 중 하나를 사용하는 편이 더 낫다고 생각합니다. Ida나 x64dbg를 사용할 수 있기 때문입니다).

### CyberChef를 사용한 디스어셈블리

shellcode 파일을 입력으로 업로드하고 다음 레시피를 사용해 디컴파일하세요: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation 역난독화

**Mixed Boolean-Arithmetic (MBA)** obfuscation은 산술 연산자(`+`, `-`, `*`)와 비트 연산자(`&`, `|`, `^`, `~`, 시프트)를 섞은 수식을 사용해 `x + y` 같은 간단한 표현식을 숨깁니다. 중요한 점은 이러한 항등식이 대개 **고정 폭 모듈러 연산**에서만 성립한다는 것입니다. 따라서 캐리와 오버플로가 중요합니다:

```c
(x ^ y) + 2 * (x & y) == x + y
```

이런 종류의 표현을 일반적인 대수 도구로 단순화하면 비트 폭 의미론을 무시해 잘못된 결과를 얻기 쉽습니다.<sup>[[1]](#references)</sup>

### 실용적인 워크플로

1. 리프트된 코드/IR/decompiler 출력의 **원래 비트 폭**(`8/16/32/64`비트)을 유지합니다.
2. 단순화를 시도하기 전에 표현식을 **분류**합니다.
   - **선형**: 비트 연산 원자의 가중 합
   - **반선형**: 선형식에 `x & 0xFF`와 같은 상수 마스크가 더해진 형태
   - **다항식**: 곱셈이 포함된 형태
   - **혼합형**: 곱셈과 비트 연산이 서로 섞여 있으며, 반복되는 부분식이 자주 나타나는 형태
3. 후보 재작성식은 모두 무작위 테스트나 SMT 증명으로 검증합니다. 동치성을 증명할 수 없다면 추측하지 말고 원래 표현식을 유지합니다.

### 좁은 실행 슬라이스로 평탄화된 제어 흐름 우회하기

완전한 제어 흐름 그래프를 복원할 필요가 없는 경우가 많습니다. control-flow flattening, opaque predicate, 대형 dispatcher 또는 MBA가 많은 코드에서는 암호화된 blob과 출력 버퍼에서 참조를 따라가 이를 변환하는 가장 작은 루틴을 찾습니다. 그런 다음 해당 데이터 흐름 슬라이스만 재현하거나 독립적으로 실행합니다. 관련 상태를 직접 초기화할 수 있다면 dispatcher는 필요한 해법의 일부가 아닙니다.<sup>[[7]](#references)</sup>

실용적인 워크플로는 다음과 같습니다.<sup>[[7]](#references)</sup>

1. 실행 파일 및 데이터 섹션, relocation, 상호 참조를 조사합니다. 바이트 순서와 요소 폭을 유지하면서 `.rodata`에서 후보 테이블을 덤프합니다.
2. 평문 또는 출력 버퍼에 마지막으로 쓰는 루틴을 찾습니다. 해당 루틴의 입력, 참조하는 테이블, imported call, 필요한 전역 상태를 기록합니다.
3. 해당 연산만 고정 폭 Python 모델로 옮깁니다. 슬라이스가 여전히 너무 많은 상태에 의존한다면 전체 프로그램을 에뮬레이션하는 대신 Unicorn, QEMU 또는 debugger에서 루틴을 호출하고 관련 없는 import를 hook합니다.
4. 추출기가 실제로 제공된 바이너리에서 출력을 도출하는지 검증합니다. 조용한 fallback을 제거하고, 내장된 답을 검색하며, 문자열, 키, 식별자, 레이아웃, 난독화 seed가 달라진 미확인 빌드에서도 실행합니다.

유용한 초기 명령은 다음과 같습니다.<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 상수로 위장된 MBA 표현식 탐지

겉보기에는 입력에 의존하는 바이트 표현식도 입력을 완전히 상쇄할 수 있습니다. 테이블을 추출한 후 전체 8비트 도메인에 대해 표현식을 평가하면, 출력 집합에 원소가 하나뿐인 경우 주변 상태 머신을 복원하지 않고도 해당 바이트가 상수임을 증명할 수 있습니다.<sup>[[7]](#references)</sup>

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

원래 덧셈은 바이트 너비에서 오버플로로 순환하므로 마지막 마스크를 유지하세요. 더 넓은 도메인에서는 SMT solver에 동일한 너비의 심볼릭 입력 두 개에 대해 `f(x1) != f(x2)`가 만족 가능한지 물어보세요. `unsat`이면 불변성이 증명되고, `sat`이면 반례가 나오므로 입력을 제거할 수 없습니다.<sup>[[7]](#references)</sup>

#### 환경에 종속된 디코딩 인식

Anti-analysis 검사는 분기하거나 충돌을 일으킬 필요가 없습니다. 디코더는 센서 결과를 키 비트, opaque predicate 상수 또는 flattened dispatcher 상태에 섞은 뒤 정상적으로 계속 실행하여 에뮬레이터에서 그럴듯하지만 잘못된 평문을 생성할 수 있습니다. 따라서 눈에 보이는 실패 분기만 패치하는 것으로는 충분하지 않습니다. 환경 프로브에서 디코더 상태로 이어지는 데이터 종속성을 추적하고, 실제 기기와 에뮬레이터에서 동일한 슬라이스를 비교하며, 각 센서 결과를 강제로 변경했을 때 최종 버퍼가 어떻게 바뀌는지 테스트하세요.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA)는 malware analysis 및 보호된 바이너리의 reversing에 유용한 MBA 단순화 도구입니다. 모든 항에 하나의 일반적인 재작성 패스를 적용하는 대신, 표현식을 분류하고 특화된 파이프라인으로 전달합니다.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA는 Boolean 입력에서 표현식을 평가하고, signature를 도출한 뒤 pattern matching, ANF 변환, coefficient interpolation 등의 여러 복구 방법을 동시에 실행합니다.
- **Semilinear MBA**: constant-masked atom은 bit-partitioned reconstruction을 통해 다시 구성하여 masked 영역이 올바르게 유지되도록 합니다.
- **Polynomial/Mixed MBA**: 곱을 core로 분해하고, 단순화 전에 반복되는 부분식을 임시 변수로 끌어올려 바깥쪽 관계를 단순화할 수 있습니다.

복구를 시도해 볼 만한 혼합 identity의 예:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

이는 다음과 같이 간략화할 수 있습니다:

```c
x * y
```

### 리버싱 참고 사항

- 정확한 연산을 분리한 후 **lifted IR 표현식**이나 디컴파일러 출력에 CoBRA를 실행하는 것이 좋습니다.
- 표현식이 masked arithmetic 또는 좁은 레지스터에서 나온 경우 `--bitwidth`를 명시적으로 사용하세요.
- 더 강력한 증명 단계가 필요하다면 다음의 로컬 Z3 참고 자료를 확인하세요:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA는 **LLVM pass plugin**(`libCobraPass.so`)으로도 제공되며, 이후 분석 패스 전에 MBA가 많은 LLVM IR을 정규화할 때 유용합니다.
- 지원되지 않는 carry에 민감한 mixed-domain 잔여식은 원래 표현식을 유지하고 carry 경로를 수동으로 분석하라는 신호로 취급해야 합니다.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

이 obfuscator는 프로그램 연산을 `mov` 기반 명령어 시퀀스로 대체하고, signal/exception 처리를 사용해 제어 흐름을 변경합니다. 자세한 내용은 다음을 참조하세요.

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

지원되는 바이너리의 경우 [demovfuscator](https://github.com/kirschju/demovfuscator)로 결과를 deobfuscate할 수 있습니다. 여러 종속성이 필요합니다.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

그리고 [keystone을 설치합니다](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTF를 플레이 중이라면, flag를 찾기 위한 이 우회 방법**이 매우 유용할 수 있습니다: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point**를 찾으려면 다음처럼 `::main`으로 함수를 검색합니다:

![Ghidra에서 함수 이름의 double-colon main을 검색해 Rust entry point 찾기](<../../images/image (1080).png>)

이 경우 바이너리 이름이 authenticator였으므로, 어떤 main 함수가 흥미로운지 꽤 명확합니다.\
호출되는 **함수**의 **이름**을 알았다면, **입력**과 **출력**에 대해 알아보기 위해 **인터넷**에서 검색합니다.

### ELF 펌웨어에서 Rust 문자열 복구하기

**Rust ELF** 바이너리에서는 많은 정적 문자열이 C 스타일의 NUL 종료 포인터로 참조되지 않습니다. 일반적인 `rustc` 레이아웃은 실제 문자열 데이터가 저장된 **`.rodata`**를 가리키는 **pointer/length tuple**을 **`.data.rel.ro`** 내부에 둡니다:

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
2. **`.data.rel.ro`**를 한 word씩 열거합니다.
3. **`.rodata`** 주소 범위 내의 값은 문자열 포인터 후보로 취급합니다.
4. 다음 word는 길이 후보로 취급합니다.
5. 타당성 필터를 적용합니다(예: 길이가 **4**~**100**바이트인 경우만 유지).
6. `0x00`이 나올 때까지 스캔하지 말고, **`.rodata`**에서 `length` 바이트만큼 정확히 읽습니다.

최소 추출 로직:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

펌웨어 reversing에서 특히 유용합니다. 복구된 Rust 문자열은 **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, auth-related logic**를 드러내는 경우가 많습니다.

Ghidra가 해당 문자열을 찾지 못하면, 동일한 heuristic을 적용하고 참조된 `.rodata` 오프셋에 문자열 데이터를 생성하는 custom script/plugin을 실행하세요. Pen Test Partners가 공개한 `rust-strings` 및 `RustStrings.py` 도구는 이 아이디어를 다른 **word sizes, endianness, section layouts**에 맞게 적용할 때 참고하기 좋습니다.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries에는 [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)를 사용할 수 있습니다.

Delphi binary를 reverse해야 한다면 IDA plugin인 [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)를 사용하는 것을 권장합니다.

IDA에서 **Alt+F7**을 눌러 Python plugin을 불러온 다음, plugin 파일을 선택하세요.

이 plugin은 binary를 실행하고 디버깅 시작 시 function names를 동적으로 확인합니다. 디버깅을 시작한 후 Start 버튼(초록색 버튼 또는 f9)을 다시 누르면 실제 코드의 시작 부분에서 breakpoint가 걸립니다.

그래픽 애플리케이션에서 버튼을 누르면 debugger가 해당 버튼으로 호출된 function에서 멈출 수 있습니다.

## Golang

Golang binary를 reverse해야 한다면 IDA plugin인 [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)를 사용하는 것을 권장합니다.

IDA에서 **Alt+F7**을 눌러 Python plugin을 불러온 다음, plugin 파일을 선택하세요.

이렇게 하면 function names를 확인할 수 있습니다.

## Compiled Python

이 페이지에서 ELF/EXE Python compiled binary에서 Python code를 가져오는 방법을 확인할 수 있습니다.

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBA 게임의 **binary**를 구했다면, 이를 **emulate**하고 **debug**할 여러 도구를 사용할 수 있습니다.

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug 버전 다운로드_) - 인터페이스가 있는 debugger 포함
- [**mgba** ](https://mgba.io)- CLI debugger 포함
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm)에서 _**Options --> Emulation Setup --> Controls**_** **로 이동하면 Game Boy Advance **버튼**을 누르는 방법을 확인할 수 있습니다.

![Game Boy Advance 버튼 매핑을 보여주는 no$gba 컨트롤 설정](<../../images/image (581).png>)

키를 누르면 각 **키에 식별을 위한 값**이 지정됩니다.

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

![주소 0x4000130에서 KEYINPUT을 참조하는 GBA 바이너리의 Ghidra 화면](<../../images/image (447).png>)

이전 이미지에서 해당 함수가 **FUN_080015a8**에서 호출되는 것을 확인할 수 있습니다 (주소: _0x080015fa_ 및 _0x080017ac_).

이 함수에서는 몇 가지 중요하지 않은 init 작업을 수행한 후:

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

이 코드를 발견했습니다:

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

마지막 if는 **`uVar4`**가 이전 Keys에 포함되어 있으면서 현재 키가 아닌지 확인합니다. 이는 버튼에서 손을 뗐다는 뜻입니다(현재 키는 **`uVar1`**에 저장됩니다).

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

- 먼저 **값 4**(**SELECT** 버튼)와 비교합니다. 이 챌린지에서 이 버튼은 화면을 지웁니다.
- 다음으로 **값 8**(**START** 버튼)과 비교합니다. 이 챌린지에서 해당 경로는 입력한 코드가 유효한지 확인합니다.
  - 이 경우 변수 **`DAT_030000d8`**을 0xf3과 비교하고, 값이 일치하면 일부 코드가 실행됩니다.
- 그 외의 경우에는 카운터(`DAT_030000d4`)를 확인하고 증가시킵니다.\
  카운터가 8보다 작으면 눌린 키의 값이 `DAT_030000d8`에 누적됩니다.

따라서 이 챌린지에서는 버튼 값을 알고 있다면, 길이가 8보다 짧고 합계가 0xf3이 되는 조합을 **눌러야 합니다.**

**이 튜토리얼의 참고 자료:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## 강좌

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [CoBRA를 사용한 MBA 난독화 단순화](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA 저장소](https://github.com/trailofbits/CoBRA)
- [3] [Rust 문자열 디코딩 - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing 튜토리얼 (보관본)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI 지원 reverse engineering을 무력화하기, 아니면 적어도 시도해 보기](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
