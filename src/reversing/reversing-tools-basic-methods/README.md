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

- wasm(바이너리)을 wat(일반 텍스트)로 **디컴파일**하려면 [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)을 사용하세요.
- wat을 wasm으로 **컴파일**하려면 [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)을 사용하세요.
- 디컴파일에는 [web-wasmdec](https://wwwg.github.io/web-wasmdec/)도 사용해 볼 수 있습니다.

소프트웨어:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 캐시 바이트코드

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## 가상화된 페이로드 및 커스텀 VM

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET 디컴파일러

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek은 **라이브러리**(.dll), **Windows 메타데이터 파일**(.winmd), **실행 파일**(.exe) 등 여러 형식을 **디컴파일하고 검사하는** 디컴파일러입니다. 디컴파일한 어셈블리는 Visual Studio 프로젝트(.csproj)로 저장할 수 있습니다.

레거시 어셈블리에서 손실된 소스 코드를 복구해야 하는 경우, 이 도구를 사용하면 시간을 절약할 수 있습니다. 또한 dotPeek은 디컴파일된 코드 전체를 편리하게 탐색할 수 있어 **Xamarin 알고리즘 분석**에 적합한 도구입니다.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

포괄적인 추가 기능 모델과 도구를 필요에 맞게 확장하는 API를 갖춘 .NET Reflector는 시간을 절약하고 개발을 간소화합니다. 이 도구가 제공하는 다양한 reverse engineering 기능을 살펴보겠습니다.

- 라이브러리나 구성 요소를 통해 데이터가 흐르는 방식을 파악할 수 있습니다.
- .NET 언어와 프레임워크의 구현 및 사용 방식에 대한 통찰력을 제공합니다.
- 사용 중인 API와 기술을 더 잘 활용할 수 있도록 문서화되지 않았거나 노출되지 않은 기능을 찾습니다.
- 종속성과 여러 어셈블리를 찾습니다.
- 코드, 타사 구성 요소, 라이브러리에서 오류가 발생한 정확한 위치를 찾습니다.
- 사용하는 모든 .NET 코드의 소스를 디버깅합니다.

### [ILSpy](https://github.com/icsharpcode/ILSpy) 및 [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code용 ILSpy 플러그인](https://github.com/icsharpcode/ilspy-vscode): 모든 OS에서 사용할 수 있습니다(VSCode에서 바로 설치할 수 있어 git을 다운로드할 필요가 없습니다. **Extensions**를 클릭하고 **ILSpy**를 검색하세요).\
**디컴파일**, **수정**, **재컴파일**을 해야 한다면 [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) 또는 이를 활발히 유지 관리하는 fork인 [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)를 사용할 수 있습니다. (함수 내부를 변경하려면 **마우스 오른쪽 버튼 클릭 -> Modify Method**를 선택하세요.)

### DNSpy 로깅

**DNSpy에서 파일로 정보를 기록**하려면 다음 snippet을 사용할 수 있습니다:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy 디버깅

DNSpy를 사용해 코드를 디버깅하려면 다음을 수행해야 합니다.

먼저 **디버깅**과 관련된 **Assembly attributes**를 변경합니다.

![DNSpy Logging - DNSpy 디버깅: 먼저 디버깅과 관련된 Assembly attributes를 변경합니다](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: 그리고 compile 클릭](<../../images/image (314) (1).png>)

그런 다음 _**File >> Save module...**_을 통해 새 파일을 저장합니다:

![DNSpy Logging - DNSpy Debugging: 그런 다음 File Save module을 통해 새 파일 저장](<../../images/image (602).png>)

이 작업은 필수입니다. 그렇지 않으면 **runtime**에 코드에 여러 **최적화**가 적용되어, 디버깅 중에 **break-point에 도달하지 않거나** 일부 **변수가 존재하지 않을** 수 있습니다.

그런 다음 .NET 애플리케이션이 **IIS**에서 **실행** 중이라면 다음 명령으로 **재시작**할 수 있습니다:

```
iisreset /noforce
```

그런 다음 디버깅을 시작하려면 열려 있는 모든 파일을 닫고 **Debug Tab**에서 **Attach to Process...**를 선택합니다:

![DNSpy Logging - DNSpy Debugging: 디버깅을 시작하려면 열려 있는 모든 파일을 닫고 Debug Tab에서 Attach to Process를 선택합니다](<../../images/image (318).png>)

그런 다음 **w3wp.exe**를 선택해 **IIS server**에 연결하고 **attach**를 클릭합니다:

![DNSpy Logging - DNSpy Debugging: w3wp.exe를 선택해 IIS server에 연결한 다음 attach를 클릭합니다](<../../images/image (113).png>)

이제 프로세스를 디버깅하고 있으니, 프로세스를 중지하고 모든 모듈을 로드할 차례입니다. 먼저 _Debug >> Break All_을 클릭한 다음 _**Debug >> Windows >> Modules**_를 클릭합니다:

![DNSpy Logging - DNSpy Debugging: 프로세스를 디버깅하고 있으니, 프로세스를 중지하고 모든 모듈을 로드할 차례입니다. 먼저 Debug Break All을 클릭한 다음 Debug Windows Modules를 클릭합니다](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: 프로세스를 디버깅하고 있으니, 프로세스를 중지하고 모든 모듈을 로드할 차례입니다. 먼저 Debug Break All을 클릭한 다음 Debug Windows Modules를 클릭합니다](<../../images/image (834).png>)

**Modules**에서 모듈을 하나 클릭하고 **Open All Modules**를 선택합니다:

![DNSpy Logging - DNSpy Debugging: Modules에서 모듈을 하나 클릭하고 Open All Modules를 선택합니다](<../../images/image (922).png>)

**Assembly Explorer**에서 모듈을 하나 마우스 오른쪽 버튼으로 클릭한 다음 **Sort Assemblies**를 클릭합니다:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer에서 모듈을 하나 마우스 오른쪽 버튼으로 클릭한 다음 Sort Assemblies를 클릭합니다](<../../images/image (339).png>)

## Java 디컴파일러

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL 디버깅

### IDA 사용

- **rundll32 로드** (64비트는 C:\Windows\System32\rundll32.exe, 32비트는 C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** 디버거 선택
- "**Suspend on library load/unload**" 선택

![Debugging DLLs - Using IDA: "Suspend on library load/unload" 선택](<../../images/image (868).png>)

- 실행 **parameters**를 설정하고 **DLL 경로**와 호출할 함수를 입력합니다:

![Debugging DLLs - Using IDA: 실행 parameters를 설정하고 DLL 경로와 호출할 함수를 입력합니다](<../../images/image (704).png>)

이제 디버깅을 시작하면 **DLL이 로드될 때마다 실행이 중지됩니다**. 따라서 rundll32가 DLL을 로드하면 실행이 중지됩니다.

이 방법은 모듈 로드 이벤트에서 실행을 중지하지만, 아래의 x64dbg 작업 흐름에 비해 로드된 DLL의 entry point에 도달하는 과정은 덜 직접적입니다.

### x64dbg/x32dbg 사용

- **rundll32 로드** (64비트는 C:\Windows\System32\rundll32.exe, 32비트는 C:\Windows\SysWOW64\rundll32.exe)
- **Command Line 변경** (_File --> Change Command Line_) 후 dll 경로와 호출할 함수를 설정합니다. 예: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_를 변경하고 "**DLL Entry**"를 선택합니다.
- 그런 다음 **실행을 시작합니다**. 디버거는 각 dll main에서 중지되며, 어느 시점에는 **사용자 DLL의 DLL Entry에서 중지됩니다**. 그 지점부터 중단점을 설정할 위치를 찾으면 됩니다.

win64dbg에서 어떤 이유로든 실행이 중지되면 **win64dbg 창 상단**에서 **현재 어떤 코드에 있는지** 확인할 수 있습니다:

![Using IDA - Using x64dbg/x32dbg: 어떤 이유로든 win64dbg에서 실행이 중지되면 win64dbg 창 상단에서 현재 어떤 코드에 있는지 확인할 수 있습니다](<../../images/image (842).png>)

이 표시를 통해 디버깅하려는 DLL 내부에서 실행이 중지되었는지 확인할 수 있습니다.

## GUI 앱 / 비디오게임

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)은 실행 중인 게임의 메모리에서 중요한 값이 저장된 위치를 찾고 값을 변경하는 데 유용한 프로그램입니다. 자세한 내용은 다음을 참조하세요:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE)는 게임에 중점을 둔 GNU Project Debugger (GDB)용 프런트엔드/reverse engineering 도구입니다. 하지만 reverse engineering 관련 작업이라면 무엇이든 사용할 수 있습니다.

[**Decompiler Explorer**](https://dogbolt.org/)는 여러 디컴파일러를 사용할 수 있는 웹 프런트엔드입니다. 이 웹 서비스에서는 작은 실행 파일을 대상으로 여러 디컴파일러의 출력을 비교할 수 있습니다.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode

### blobrunner로 shellcode 디버깅

[**BlobRunner**](https://github.com/OALabs/BlobRunner)는 **shellcode**를 할당하고 **메모리 주소**를 출력한 뒤 실행을 일시 중지합니다.\
IDA나 x64dbg 같은 디버거를 연결하고 출력된 주소에 중단점을 설정한 다음, 실행을 재개해 shellcode를 디버깅합니다.

releases GitHub 페이지에서 컴파일된 릴리스가 들어 있는 zip 파일을 다운로드할 수 있습니다: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
다음 링크에서 약간 수정된 버전의 Blobrunner를 찾을 수 있습니다. 컴파일하려면 **Visual Studio Code에서 C/C++ 프로젝트를 만들고, 코드를 복사해 붙여넣은 다음 빌드하면 됩니다**.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it로 shellcode 디버깅

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)는 BlobRunner와 비슷합니다. shellcode를 할당하고 무한 루프에 진입합니다. 디버거를 연결하고 **2~5초간** 실행을 재개한 다음, 해당 루프 안에서 일시 중지하고 할당된 shellcode로 실행을 넘기는 다음 호출까지 step합니다.

![할당된 shellcode를 호출하기 직전, jmp2it의 무한 루프에서 일시 중지된 디버거](<../../images/image (509).png>)

컴파일된 버전은 [jmp2it releases 페이지](https://github.com/adamkramer/jmp2it/releases/)에서 다운로드할 수 있습니다.

### Cutter로 shellcode 디버깅

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)는 radare의 GUI입니다. Cutter를 사용하면 shellcode를 에뮬레이션하고 동적으로 검사할 수 있습니다.

Cutter에서는 "Open File"과 "Open Shellcode"를 사용할 수 있습니다. 제 경우 shellcode를 파일로 열었을 때는 올바르게 디컴파일했지만, shellcode로 열었을 때는 그렇지 않았습니다:

![같은 바이트를 파일로 열었을 때와 shellcode로 열었을 때 서로 다른 분석 결과를 보여 주는 Cutter](<../../images/image (562).png>)

원하는 위치에서 에뮬레이션을 시작하려면 그 위치에 bp를 설정합니다. 그러면 Cutter가 해당 지점부터 자동으로 에뮬레이션을 시작하는 것으로 보입니다:

![Cutter 에뮬레이션을 시작하기 전에 원하는 shellcode 진입점에 중단점 설정](<../../images/image (589).png>)

![선택한 shellcode 중단점에서 일시 중지된 Cutter emulator](<../../images/image (387).png>)

예를 들어 hex dump에서 스택을 확인할 수 있습니다:

![Cutter의 hex dump에서 에뮬레이션된 shellcode 스택 확인](<../../images/image (186).png>)

### shellcode 난독화 해제 및 실행된 함수 확인

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)를 사용해 보세요.\
shellcode가 사용하는 **함수**와 메모리에서 **자체적으로 디코딩**되는지 여부 등을 알려줍니다.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg에는 원하는 옵션을 선택하고 shellcode를 실행할 수 있는 그래픽 런처도 있습니다.

![shellcode 에뮬레이션 및 추적 옵션을 선택하는 scDbg 그래픽 런처](<../../images/image (258).png>)

**Create Dump** 옵션은 메모리에서 shellcode가 동적으로 변경된 경우 최종 shellcode를 덤프합니다(디코딩된 shellcode를 다운로드할 때 유용함). **start offset**은 특정 오프셋에서 shellcode를 시작할 때 유용합니다. **Debug Shell** 옵션은 scDbg 터미널을 사용해 shellcode를 디버깅할 때 유용합니다(하지만 이 경우에는 앞에서 설명한 옵션 중 하나를 사용하는 편이 더 낫다고 생각합니다. Ida나 x64dbg를 사용할 수 있기 때문입니다).

### CyberChef를 사용한 디스어셈블

입력으로 shellcode 파일을 업로드하고 다음 레시피를 사용해 디스어셈블하세요: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA 난독화 해제

**Mixed Boolean-Arithmetic (MBA)** 난독화는 산술 연산자(`+`, `-`, `*`)와 비트 연산자(`&`, `|`, `^`, `~`, 시프트)를 섞은 수식을 사용해 `x + y` 같은 간단한 표현식을 숨깁니다. 중요한 점은 이러한 항등식이 대개 **고정 너비 모듈러 산술**에서만 성립하므로, 캐리와 오버플로를 고려해야 한다는 것입니다:

```c
(x ^ y) + 2 * (x & y) == x + y
```

이러한 종류의 표현을 일반 대수 도구로 단순화하면 비트 폭의 의미를 무시해 잘못된 결과를 얻기 쉽습니다.<sup>[[1]](#references)</sup>

### 실용적인 워크플로

1. 리프트된 코드/IR/디컴파일러 출력의 **원래 비트 폭**(`8/16/32/64`비트)을 유지합니다.
2. 단순화를 시도하기 전에 **표현식을 분류**합니다.
   - **선형**: 비트 단위 원자의 가중 합
   - **준선형**: 선형 표현에 `x & 0xFF` 같은 상수 마스크가 더해진 형태
   - **다항식**: 곱셈이 나타남
   - **혼합형**: 곱셈과 비트 논리가 서로 얽혀 있으며, 반복되는 부분식이 자주 나타남
3. 무작위 테스트나 SMT 증명으로 각 후보 재작성을 검증합니다. 동등성을 증명할 수 없다면 추측하지 말고 원래 표현식을 유지합니다.

### 좁은 실행 슬라이스로 평탄화된 제어 흐름 우회하기

완전한 제어 흐름 그래프를 복구할 필요가 없는 경우가 많습니다. 제어 흐름 평탄화, 불투명 술어, 대형 디스패처 또는 MBA가 많은 코드에서는 암호화된 블롭과 출력 버퍼에서 참조를 따라가 이를 변환하는 가장 작은 루틴을 찾습니다. 그런 다음 해당 데이터 흐름 슬라이스만 재현하거나 독립적으로 실행합니다. 관련 상태를 직접 초기화할 수 있다면 디스패처는 필요한 해법의 일부가 아닙니다.<sup>[[7]](#references)</sup>

실용적인 워크플로는 다음과 같습니다.<sup>[[7]](#references)</sup>

1. 실행 파일 및 데이터 섹션, 재배치, 교차 참조를 목록화합니다. 바이트 순서와 요소 폭을 유지하면서 `.rodata`에서 후보 테이블을 덤프합니다.
2. 평문이나 출력 버퍼에 마지막으로 쓰는 루틴을 찾습니다. 해당 루틴의 입력, 참조 테이블, 임포트된 호출, 필요한 전역 상태를 기록합니다.
3. 해당 연산만 고정 폭 Python 모델로 옮깁니다. 슬라이스가 여전히 너무 많은 상태에 의존한다면 전체 프로그램을 에뮬레이션하는 대신 Unicorn, QEMU 또는 디버거에서 루틴을 호출하고 관련 없는 임포트를 후킹합니다.
4. 추출기가 실제로 제공된 바이너리에서 출력을 도출하는지 검증합니다. 조용한 폴백을 제거하고, 내장된 답이 있는지 검색하고, 문자열, 키, 식별자, 레이아웃, 난독화 시드가 바뀐 새 빌드에서 실행합니다.

유용한 초기 명령은 다음과 같습니다.<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 상수로 위장한 MBA 표현식 탐지

겉보기에는 입력에 의존하는 바이트 표현식도 입력이 완전히 상쇄될 수 있습니다. 테이블을 추출한 뒤 전체 8비트 도메인에서 표현식을 평가하면, 출력 집합이 단일 원소라는 사실만으로 주변 상태 머신을 복원하지 않고도 해당 바이트가 상수임을 증명할 수 있습니다.<sup>[[7]](#references)</sup>

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

원래 덧셈은 바이트 너비에서 오버플로 래핑이 발생하므로 마지막 mask를 유지하세요. 더 넓은 도메인에서는 SMT solver를 사용해 동일한 너비의 두 symbolic input에 대해 `f(x1) != f(x2)`가 만족 가능한지 확인하세요. `unsat`이면 불변성이 증명되고, `sat`이면 반례가 나온 것이므로 해당 입력을 제거할 수 없습니다.<sup>[[7]](#references)</sup>

#### 환경에 종속된 디코딩 식별하기

Anti-analysis 검사는 반드시 분기하거나 충돌을 일으키는 것은 아닙니다. 디코더가 센서 결과를 키 비트, opaque predicate 상수 또는 flattened dispatcher 상태에 섞고 정상적으로 계속 실행하면서 에뮬레이터에서 그럴듯하지만 잘못된 평문을 생성할 수 있습니다. 따라서 눈에 보이는 실패 분기만 패치하는 것으로는 충분하지 않습니다. 환경 프로브에서 디코더 상태로 이어지는 데이터 종속성을 추적하고, 실제 기기와 에뮬레이터에서 동일한 코드 조각을 비교하며, 각 센서 결과를 강제로 변경했을 때 최종 버퍼가 어떻게 달라지는지 테스트하세요.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA)는 malware 분석과 보호된 바이너리 reversing에 유용한 MBA simplifier입니다. 모든 항에 하나의 범용 rewrite pass를 적용하는 대신, 표현식을 분류해 특화된 파이프라인으로 처리합니다.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA는 Boolean 입력에서 식을 평가하고, 시그니처를 도출한 뒤 패턴 매칭, ANF 변환, 계수 보간 등 여러 복구 방법을 병렬로 시도합니다.
- **Semilinear MBA**: 상수 마스크가 적용된 원자는 비트 분할 재구성으로 다시 만들어 마스크가 적용된 영역이 올바르게 유지됩니다.
- **Polynomial/Mixed MBA**: 곱을 코어로 분해하고, 반복되는 부분식은 임시 변수로 추출한 뒤 바깥쪽 관계를 단순화할 수 있습니다.

복구를 시도해 볼 만한 혼합 항등식의 예:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

이는 다음과 같이 축약할 수 있습니다:

```c
x * y
```

### 리버싱 참고 사항

- 정확한 연산을 분리한 후, **lifted IR 표현식** 또는 decompiler 출력에 CoBRA를 실행하는 것이 좋습니다.
- 마스킹된 산술 연산이나 좁은 레지스터에서 나온 표현식에는 `--bitwidth`를 명시적으로 사용하세요.
- 더 강력한 증명 단계가 필요하다면, 여기의 Z3 참고 사항을 확인하세요.


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA는 **LLVM pass 플러그인**(`libCobraPass.so`)으로도 제공됩니다. 이후 분석 pass를 실행하기 전에 MBA가 많은 LLVM IR을 정규화할 때 유용합니다.
- 지원되지 않는 캐리 민감 혼합 도메인 잔여식은 원래 표현식을 유지하고 캐리 경로를 수동으로 분석해야 한다는 신호로 간주하세요.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

이 난독화 도구는 프로그램 연산을 `mov` 기반 명령어 시퀀스로 대체하고, 신호/예외 처리를 사용해 제어 흐름을 변경합니다. 자세한 내용은 다음을 참조하세요.

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

지원되는 바이너리의 경우, [demovfuscator](https://github.com/kirschju/demovfuscator)를 사용해 결과물을 역난독화할 수 있습니다. 여러 종속성이 필요합니다.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

그리고 [keystone을 설치](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)하세요 (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTF를 플레이 중이라면, flag를 찾기 위한 이 우회 방법**이 매우 유용할 수 있습니다: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**진입점**을 찾으려면 다음처럼 함수 이름에서 `::main`을 검색하세요:

![함수 이름에서 double-colon main을 검색해 Ghidra에서 Rust 진입점을 찾는 방법](<../../images/image (1080).png>)

이 경우 바이너리 이름이 authenticator였으므로, 이 함수가 흥미로운 main 함수라는 점은 꽤 명확합니다.\
호출되는 **함수**의 **이름**을 확인한 다음, **입력**과 **출력**을 알아보기 위해 **인터넷**에서 검색하세요.

### ELF 펌웨어에서 Rust 문자열 복구

**Rust ELF** 바이너리에서는 많은 정적 문자열이 C 스타일의 NUL 종료 포인터로 참조되지 않습니다. 일반적인 `rustc` 레이아웃에서는 **`.data.rel.ro`** 안의 **포인터/길이 튜플**이 **`.rodata`**에 저장된 실제 문자열 블롭을 가리킵니다:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

이는 `strings` 또는 Ghidra의 기본 분석이 인접한 문자열을 병합하거나 교차 참조를 완전히 놓칠 수 있음을 의미합니다.<sup>[[3]](#references)</sup>

빠른 작업 흐름:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`**의 가상 주소와 크기를 구합니다.
2. **`.data.rel.ro`**를 한 워드씩 열거합니다.
3. **`.rodata`** 주소 범위 안의 값을 문자열 포인터 후보로 취급합니다.
4. 다음 워드를 후보 길이로 취급합니다.
5. 타당성 필터를 적용합니다(예: 길이가 **4**~**100**바이트인 경우만 유지).
6. `0x00`까지 스캔하는 대신 `.rodata`에서 정확히 `length`바이트를 읽습니다.

최소 추출기 로직:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

This is especially useful in firmware 리버싱 because recovered Rust strings often reveal **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, and auth-related logic**.

If Ghidra misses those strings, run a custom script/plugin that applies the same heuristic and creates string data at the referenced `.rodata` offsets. The published `rust-strings` and `RustStrings.py` tools from Pen Test Partners are good references for adapting the idea to other **word sizes, endianness, and section layouts**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

For Delphi compiled binaries you can use [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

If you have to reverse a Delphi binary I would suggest you to use the IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Press **Alt+F7** in IDA to load a Python plugin, then select the plugin file.

This plugin will execute the binary and resolve function names dynamically at the start of the debugging. After starting the debugging press again the Start button (the green one or f9) and a breakpoint will hit in the beginning of the real code.

If you press a button in the graphical application, the debugger can stop in the function invoked by that button.

## Golang

For ordinary Go binaries, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) can recover runtime structures and improve function names in IDA. Load its Python plugin with **Alt+F7**.

### Recover metadata without the symbol table

A stripped Go executable still needs runtime metadata to map program counters to functions. [GoReSym](https://github.com/mandiant/GoReSym) locates and parses structures such as `pclntab` and `moduledata` using code derived from the Go runtime. This can recover function boundaries, names, source paths, types and build details without relying on the conventional symbol table.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

An obfuscator는 복구된 이름을 바꾸면서도 해당 구조를 사용할 수 있게 남겨둘 수 있습니다. 예를 들어 Garble은 식별자와 package 경로를 해시하고 build, module 및 debug 정보를 제거합니다.<sup>[[12]](#references)</sup> 난독화된 package 토큰은 해당 package의 함수들에서 일관되게 유지되어야 합니다. 반복되는 토큰을 기준으로 함수를 그룹화하고, callee, 문자열 및 API를 통해 package 하나를 추론한 다음 해당 package 레이블을 그룹 전체에 적용합니다.<sup>[[13]](#references)</sup>

### GoResolver로 Garble 이름 복구하기

[GoResolver](https://github.com/volexity/GoResolver)는 runtime 심볼 추출과 clean reference 생성, control-flow graph(CFG) 매칭을 결합합니다. 다음 순서로 진행합니다:<sup>[[10]](#references)[[13]](#references)</sup>

1. **컴파일러 버전을 식별합니다.** 먼저 `BuildInfo`와 내장된 버전 문자열을 확인합니다. obfuscator가 이를 제거했다면, 번들된 Go runtime의 일부를 버전별 reference runtime과 비교합니다. Volexity의 테스트에서는 runtime의 약 `2%`만으로도 주요 Go 버전을 구분할 수 있었습니다. 이는 경험적 최적화 기준일 뿐, 보편적인 임계값은 아닙니다.<sup>[[13]](#references)</sup>
2. **매칭에 사용할 reference를 빌드합니다.** 식별된 Go 버전, 대상 아키텍처 및 사용 가능성이 높은 라이브러리에 맞춰 clean 바이너리를 생성합니다. toolchain을 일치시키면 컴파일러가 생성하는 CFG 차이를 줄일 수 있습니다.<sup>[[10]](#references)[[13]](#references)</sup>
3. **함수를 비교합니다.** GoGrapher는 함수 CFG를 매칭하고 `0.0`에서 `1.0`까지의 정규화된 점수를 출력합니다. basic block 매칭은 유사한 명령어를 가중 비교하는 방식입니다. 신뢰도가 높은 매칭은 무작위화된 함수를 clean 구현에 대응시킵니다. 신뢰도가 낮은 매칭도 package 또는 module을 식별하는 데 도움이 될 수 있습니다.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **검증하고 가져옵니다.** call 관계, 상수, 문자열 및 side effect를 확인해 제안된 이름을 검증한 다음, IDA 또는 Ghidra용 GoResolver plugin으로 JSON 보고서를 가져옵니다.<sup>[[10]](#references)[[13]](#references)</sup>

toolchain을 설치하고 통합 extractor와 graph matcher를 실행합니다:<sup>[[10]](#references)</sup>

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

기본 significant-match 임계값은 `0.9`입니다. `--extract` 및 `--graph` 스위치를 사용하면 각 단계를 개별적으로 실행할 수 있으며, 복구된 런타임 메타데이터와 CFG 증거가 서로를 보완하므로 기본적으로 두 단계 모두 실행됩니다.<sup>[[10]](#references)</sup> CFG 점수는 휴리스틱입니다. 인라이닝, 빌드 플래그, 아키텍처 및 라이브러리 버전 차이에 따라 그래프 형태가 달라질 수 있으므로, 신뢰도가 낮은 이름을 억지로 지정하기보다는 미해결 함수로 남겨 두세요.<sup>[[13]](#references)</sup>

## 컴파일된 Python

이 페이지에서는 ELF/EXE Python 컴파일 바이너리에서 Python 코드를 추출하는 방법을 알아볼 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBA 게임의 **binary**를 얻었다면 여러 도구를 사용해 **에뮬레이션**하고 **디버그**할 수 있습니다:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_디버그 버전을 다운로드하세요_) - 인터페이스가 있는 디버거 포함
- [**mgba** ](https://mgba.io)- CLI 디버거 포함
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra 플러그인
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra 플러그인

[**no$gba**](https://problemkaputt.de/gba.htm)에서 _**Options --> Emulation Setup --> Controls**_** **로 이동하면 Game Boy Advance **버튼**을 누르는 방법을 확인할 수 있습니다.

![Game Boy Advance 버튼 매핑을 보여 주는 no$gba 컨트롤 설정](<../../images/image (581).png>)

각 **키에는 키를 식별하는 값**이 있습니다:

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

따라서 이런 종류의 프로그램에서는 **프로그램이 사용자 입력을 어떻게 처리하는지**가 흥미로운 부분입니다. 주소 **0x4000130**에서 흔히 볼 수 있는 함수인 **KEYINPUT**을 찾을 수 있습니다.

![GBA 바이너리의 0x4000130 주소에서 KEYINPUT을 참조하는 Ghidra 화면](<../../images/image (447).png>)

이전 이미지에서 이 함수가 **FUN_080015a8**에서 호출되는 것을 확인할 수 있습니다(주소: _0x080015fa_ 및 _0x080017ac_).

해당 함수에서 중요하지 않은 초기화 작업을 몇 가지 수행한 다음:

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

다음 코드가 발견되었습니다:

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

마지막 if는 **`uVar4`**가 이전 Keys에 포함되어 있지만 현재 키는 아닌지 확인합니다. 즉, 버튼에서 손을 뗐는지 확인하는 것이며(현재 키는 **`uVar1`**에 저장됨)】【。

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

- 먼저 **값 4**(**SELECT** 버튼)와 비교합니다. 이 챌린지에서 이 버튼을 누르면 화면이 지워집니다.
- 그런 다음 **값 8**(**START** 버튼)과 비교합니다. 이 챌린지에서 이 경로는 입력한 코드가 유효한지 확인합니다.
  - 이 경우 변수 **`DAT_030000d8`**를 0xf3과 비교하며, 값이 같으면 일부 코드가 실행됩니다.
- 그 외의 경우에는 카운터(`DAT_030000d4`)를 확인하고 증가시킵니다.\
  카운터가 8보다 작은 동안 눌린 키의 값이 `DAT_030000d8`에 누적됩니다.

따라서 이 챌린지에서는 각 버튼의 값을 알고, 합계가 0xf3이 되는 8개 미만 길이의 조합을 **눌러야 했습니다.**

**이 튜토리얼의 참고 자료:** [보관된 Nostalgia 챌린지 풀이](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## 강좌

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [CoBRA로 MBA 난독화 간소화하기](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA 저장소](https://github.com/trailofbits/CoBRA)
- [3] [Rust 문자열 디코딩 - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing 튜토리얼 (보관본)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI 지원 reverse engineering 무력화, 또는 적어도 시도하기](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [기본 블록 매칭을 기반으로 한 Control Flow Graph 비교 접근법](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble 난독화 메커니즘](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Control-Flow Graph 유사도를 사용해 Golang 바이너리의 난독화를 자동으로 해제하기](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
