# Reversing 도구 및 기본 방법

{{#include ../../banners/hacktricks-training.md}}

## ImGui 기반 Reversing 도구

소프트웨어:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg 사용자 모드 자동화

{{#ref}}
windbg-automation.md
{{#endref}}

## Windows 예외 기반 제어 흐름

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Windows 커널 디버깅

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm 디컴파일러 / Wat 컴파일러

온라인:

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)를 사용해 wasm(바이너리)을 wat(일반 텍스트)로 **디컴파일**합니다.
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)를 사용해 wat을 wasm으로 **컴파일**합니다.
- 디컴파일에는 [web-wasmdec](https://wwwg.github.io/web-wasmdec/)도 사용할 수 있습니다.

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

dotPeek은 **라이브러리**(.dll), **Windows 메타데이터 파일**(.winmd), **실행 파일**(.exe)을 포함한 여러 형식을 **디컴파일하고 검사**하는 디컴파일러입니다. 디컴파일한 어셈블리는 Visual Studio 프로젝트(.csproj)로 저장할 수 있습니다.

레거시 어셈블리에서 소스 코드를 복원해야 할 때 이 기능을 사용하면 시간을 절약할 수 있습니다. 또한 dotPeek은 디컴파일된 코드를 편리하게 탐색할 수 있어 **Xamarin 알고리즘 분석**에 적합한 도구 중 하나입니다.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

포괄적인 추가 기능 모델과 필요에 맞게 도구를 확장하는 API를 갖춘 .NET Reflector는 시간을 절약하고 개발을 간소화합니다. 이 도구가 제공하는 다양한 reverse engineering 기능을 살펴보겠습니다.

- 라이브러리나 구성 요소에서 데이터가 어떻게 흐르는지 파악할 수 있습니다.
- .NET 언어와 프레임워크의 구현 및 사용 방식을 파악할 수 있습니다.
- 사용 중인 API와 기술을 더 폭넓게 활용할 수 있도록 문서화되지 않았거나 노출되지 않은 기능을 찾습니다.
- 종속성 및 여러 어셈블리를 찾습니다.
- 코드, 타사 구성 요소 및 라이브러리에서 오류가 발생한 정확한 위치를 추적합니다.
- 작업 중인 모든 .NET 코드의 소스를 디버깅합니다.

### [ILSpy](https://github.com/icsharpcode/ILSpy) 및 [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code용 ILSpy 플러그인](https://github.com/icsharpcode/ilspy-vscode): 모든 OS에서 사용할 수 있습니다(VSCode에서 바로 설치할 수 있으므로 git을 다운로드할 필요가 없습니다. **Extensions**를 클릭한 다음 **ILSpy**를 검색하세요).\
**디컴파일**하고 **수정**한 뒤 다시 **컴파일**해야 한다면 [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) 또는 현재 활발히 유지 관리되는 fork인 [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)를 사용할 수 있습니다. (함수 내부를 변경하려면 **마우스 오른쪽 버튼 클릭 -> 메서드 수정**을 선택하세요.)

### REA를 사용한 실행 없는 managed 검사

**REA**는 어셈블리를 로드하지 않고 PE/CLI 메타데이터와 CIL을 검사할 수 있습니다. 먼저 아티팩트의 ID를 확인한 다음 멤버와 선언된 네이티브 경계를 살펴보세요. 디컴파일러를 사용하거나 프로그램을 실행하기 전에 의심스러운 호출을 검토할 때 유용합니다.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

버전 간 차이를 비교할 때 `compare_managed_members`는 metadata token이 빌드마다 안정적이라고 간주하지 않고, 원시 CIL/signature 식별 정보와 디코딩된 instruction fingerprint를 사용합니다. P/Invoke 선언만으로 native code가 실행되었다고 입증할 수는 없습니다. 경계를 확인하려면 `verify_managed_native_boundaries`에 일치하는 native export 또는 function Evidence가 필요합니다. 결과와 함께 artifact digest, MVID, 해결되지 않은 매핑도 보존하세요.<sup>[[17]](#references)</sup>

### DNSpy 로그 기록

**DNSpy가 일부 정보를 파일에 기록하도록** 하려면 다음 snippet을 사용할 수 있습니다:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy 디버깅

DNSpy를 사용해 코드를 디버깅하려면 다음을 수행해야 합니다.

먼저 **디버깅**과 관련된 **Assembly attributes**를 변경합니다.

![DNSpy Logging - DNSpy Debugging: 먼저 디버깅과 관련된 Assembly attributes를 변경합니다](<../../images/image (973).png>)

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

이 작업이 필요한 이유는 이렇게 하지 않으면 **런타임**에 코드에 여러 **최적화**가 적용되어, 디버깅 중에 **중단점이 한 번도 적중하지 않거나** 일부 **변수가 존재하지 않을 수 있기 때문**입니다.

그런 다음 .NET 애플리케이션이 **IIS**에서 **실행 중**이라면 다음 명령으로 **재시작**할 수 있습니다:

```
iisreset /noforce
```

그런 다음 디버깅을 시작하려면 열려 있는 파일을 모두 닫고 **Debug Tab**에서 **Attach to Process...**를 선택합니다.

![DNSpy Logging - DNSpy Debugging: 디버깅을 시작하려면 열려 있는 파일을 모두 닫고 Debug Tab에서 Attach to Process를 선택합니다](<../../images/image (318).png>)

그런 다음 **w3wp.exe**를 선택해 **IIS server**에 연결하고 **attach**를 클릭합니다.

![DNSpy Logging - DNSpy Debugging: w3wp.exe를 선택해 IIS server에 연결하고 attach를 클릭합니다](<../../images/image (113).png>)

이제 프로세스를 디버깅하고 있으므로 프로세스를 중지하고 모든 모듈을 불러올 차례입니다. 먼저 _Debug >> Break All_을 클릭한 다음 _**Debug >> Windows >> Modules**_를 클릭합니다.

![DNSpy Logging - DNSpy Debugging: 프로세스를 디버깅하고 있으므로 프로세스를 중지하고 모든 모듈을 불러올 차례입니다. 먼저 Debug Break All을 클릭한 다음 Debug Windows Modules를 클릭합니다](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: 프로세스를 디버깅하고 있으므로 프로세스를 중지하고 모든 모듈을 불러올 차례입니다. 먼저 Debug Break All을 클릭한 다음 Debug Windows Modules를 클릭합니다](<../../images/image (834).png>)

**Modules**에서 아무 모듈이나 클릭하고 **Open All Modules**를 선택합니다.

![DNSpy Logging - DNSpy Debugging: Modules에서 아무 모듈이나 클릭하고 Open All Modules를 선택합니다](<../../images/image (922).png>)

**Assembly Explorer**에서 아무 모듈이나 마우스 오른쪽 버튼으로 클릭하고 **Sort Assemblies**를 클릭합니다.

![DNSpy Logging - DNSpy Debugging: Assembly Explorer에서 아무 모듈이나 마우스 오른쪽 버튼으로 클릭하고 Sort Assemblies를 클릭합니다](<../../images/image (339).png>)

## Java 디컴파일러

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL 디버깅

### IDA 사용

- **rundll32를 불러옵니다** (64비트는 C:\Windows\System32\rundll32.exe, 32비트는 C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** 디버거를 선택합니다
- "**Suspend on library load/unload**"를 선택합니다

![Debugging DLLs - Using IDA: "Suspend on library load/unload"를 선택합니다](<../../images/image (868).png>)

- **parameters**를 설정하고, 실행할 **DLL 경로**와 호출할 함수를 입력합니다.

![Debugging DLLs - Using IDA: 실행 parameters에 DLL 경로와 호출할 함수를 입력합니다](<../../images/image (704).png>)

그런 다음 디버깅을 시작하면 **각 DLL이 로드될 때 실행이 중지됩니다**. 따라서 rundll32가 DLL을 로드하면 실행이 중지됩니다.

이 방법은 모듈 로드 이벤트에서 중지하지만, 아래의 x64dbg 워크플로와 비교하면 로드된 DLL의 entry point에 도달하기가 덜 직접적입니다.

### x64dbg/x32dbg 사용

- **rundll32를 불러옵니다** (64비트는 C:\Windows\System32\rundll32.exe, 32비트는 C:\Windows\SysWOW64\rundll32.exe)
- **Command Line을 변경**(_File --> Change Command Line_)하고 DLL 경로와 호출할 함수를 설정합니다. 예: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_를 변경하고 "**DLL Entry**"를 선택합니다.
- 그런 다음 **실행을 시작**합니다. 디버거는 각 dll main에서 중지하며, 어느 시점에는 **대상 DLL의 dll Entry에서 중지됩니다**. 여기서부터 breakpoint를 설정할 지점을 찾으면 됩니다.

win64dbg에서 어떤 이유로든 실행이 중지되면 **win64dbg 창 상단**에서 **현재 어느 코드에 있는지** 확인할 수 있습니다.

![Using IDA - Using x64dbg/x32dbg: 실행이 어떤 이유로든 중지되면 win64dbg 창 상단에서 현재 어느 코드에 있는지 확인할 수 있습니다](<../../images/image (842).png>)

이 표시를 통해 디버깅하려는 DLL 내부에서 실행이 중지됐는지 확인할 수 있습니다.

## GUI 앱 / 비디오 게임

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)은 실행 중인 게임의 메모리에서 중요한 값이 저장된 위치를 찾아 변경할 수 있는 유용한 프로그램입니다. 자세한 정보:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE)는 게임에 중점을 둔 GNU Project Debugger (GDB)용 프런트엔드/리버스 엔지니어링 도구입니다. 하지만 리버스 엔지니어링과 관련된 모든 작업에 사용할 수 있습니다.

[**Decompiler Explorer**](https://dogbolt.org/)는 여러 디컴파일러를 사용할 수 있는 웹 프런트엔드입니다. 이 웹 서비스에서는 작은 실행 파일에 대해 여러 디컴파일러의 출력을 비교할 수 있습니다.

### Godot PCK 복호화 및 프로젝트 복구

배포된 Godot 게임의 경우, 독립형 `.pck`, 실행 파일에 추가되거나 포함된 pack, 또는 APK의 `assets` 디렉터리에서 PCK를 찾습니다. [gore](https://github.com/figurophobia/gore)는 pack을 검사하고 추출할 수 있으며, 스크립트와 리소스를 완전히 재구성하려면 GDRE Tools가 필요합니다 (`gore setup`으로 설치하거나 `--gdre`를 사용). 이 워크플로에서 도구는 Godot 4.x PCK 형식 v2–v4를 지원합니다. v1 헤더는 감지할 수 있지만 v1에는 제공된 키가 필요합니다.<sup>[[25]](#references)</sup>

자동 키 복구에는 암호화된 파일 테이블이 필요합니다. 파일 내용만 암호화된 경우에는 알려진 키를 제공해야 합니다. 복구에 실패했다고 해서 pack이 암호화되지 않았다는 뜻은 아닙니다.<sup>[[28]](#references)</sup>

키 검색은 **AES-256 keyspace 공격이 아닙니다**. 암호화된 파일 테이블에는 평문 MD5, 평문 길이, IV, AES-256-CFB 암호문이 들어 있습니다.<sup>[[27]](#references)</sup> `gore`는 게임 실행 파일이나 인접 파일에서 32바이트 길이의 후보 키를 검색합니다. 복호화된 경로 길이와 접두사가 그럴듯한지 확인한 다음, binary scan에서 찾은 후보는 테이블 전체를 복호화하고 MD5를 검사해 확인합니다.<sup>[[26]](#references)[[28]](#references)</sup> 먼저 초기화된 PE/ELF 데이터 섹션을 검색하고, 찾지 못하면 전체 파일을 검색합니다. `--scan`을 사용하면 다른 후보 파일도 검색합니다.<sup>[[28]](#references)</sup>

내장 키를 찾지 못하면 기본 제공되는 짧은 비밀번호 목록을 시도합니다. 다른 후보를 지정하려면 `--wordlist`를 사용합니다. 각 비밀번호는 엔진의 비밀번호 파생 키 표현, 0으로 패딩된 리터럴 또는 64자리 16진수 키로 테스트됩니다. binary scan에서 찾은 후보와 달리, 이 구현에서는 wordlist 후보가 경로 구조 필터만 통과하면 됩니다. pack을 열고 추출된 asset을 검증해 후보를 확인하세요.<sup>[[26]](#references)[[28]](#references)</sup>

게임 파일을 로컬에서 사용할 수 있다면 분석에 필요한 단계를 선택합니다. `recover`는 GDRE를 사용해 열 수 있는 프로젝트를 재구성하고, `extract`는 원본 파일만 압축 해제합니다. `key`는 다른 도구에서 사용할 후보 키를 출력합니다.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## REA를 이용한 근거 기반 네이티브 조사

**REA**는 CLI와 MCP를 통해 Hopper, Ghidra, IDA 분석을 제공합니다. Node.js 22.x(최소 22.19), 24.x(최소 24.11) 또는 26+와 npm이 필요합니다. 먼저 기존 네이티브 provider를 구성하고, `rea providers --json`을 확인한 다음 둘 이상의 provider가 대상 플랫폼을 지원하면 provider를 명시적으로 선택하세요. 아래의 `0x1000` 대신 인벤토리에서 확인한 함수 이름이나 주소를 사용하세요.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

기능 문자열이나 심볼에서 시작해 참조와 호출자를 따라간 다음, 선택한 함수의 상세 정보와 의사 코드를 `rea decompile`로 확인합니다. REA는 세션을 선택한 provider에 연결하며, 실패 후 다른 provider로 조용히 전환하지 않습니다. 반복 가능한 쿼리의 경우 `--snapshot PATH`는 아티팩트 바이트, provider, 설정, 작업 및 매개변수가 일치할 때만 재사용합니다. snapshot은 로컬 캐시이지 저장된 provider 데이터베이스가 아닙니다. 추론된 경로나 디컴파일러 텍스트를 원본 소스로 취급하지 말고, 반환된 Evidence와 명시적인 미확인 사항을 보존하세요.<sup>[[16]](#references)[[18]](#references)</sup>

JavaScript/Electron 진입점에서 native add-on으로 이어지는 경로는 [Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea)를 참조하세요.

## 로컬 TCP 브리지를 이용한 IDA 및 Ghidra 스크립트 분석

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)는 **이미 열려 있는** IDA 데이터베이스 또는 Ghidra CodeBrowser 프로그램 내부에서 실행되며, 별도의 스크립트가 해당 분석 데이터베이스를 쿼리하고 수정할 수 있게 합니다. IDA의 Python CLI에서 `ID_Server.py`를 실행하거나(`import ID_Server`), Ghidra의 Script Manager에서 `Ghidra_Server.py`를 실행합니다. IDA는 `127.0.0.1`의 `5073` 포트부터 바인딩하고 더 높은 포트를 검색합니다. 현재 Ghidra 스크립트는 `5093` 포트부터 시작해 `5102`까지 10개의 포트를 시도합니다. Java 소켓은 루프백 주소만이 아니라 와일드카드 주소에 바인딩됩니다. 연결하기 전에 인스턴스가 출력한 포트를 확인하세요. headless analyzer와 달리, 이 브리지는 해당 GUI 인스턴스에서 현재 열려 있는 프로그램을 대상으로 작동합니다.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

연결할 때마다 줄바꿈으로 끝나는 명령 **하나를 보내고**, 줄바꿈으로 끝나는 응답을 읽습니다. 결과는 일반적으로 JSON입니다. 예를 들어 입력 경로와 관련된 imported API를 찾은 후 `IMPORTXREF`로 해당 API의 호출 지점을 찾고, `DECOMP_XREF`로 선택한 주소의 호출자를 일괄 디컴파일할 수 있습니다. `FUNC`는 함수를 검사하고, `PCODE`는 디컴파일러의 중간 표현을 반환합니다. 다른 기준 주소로 재배치된 바이너리에서 복사한 주소가 아니라 활성 데이터베이스의 주소를 사용하세요. 아래 예시는 IDA의 기본 포트를 사용합니다. Ghidra에서는 해당 스크립트가 출력한 포트를 사용하세요.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

같은 채널로 **분석 데이터베이스를 변경할 수도 있습니다**. `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC`, `PATCH`는 이름, 유형, 구조체 정의, 함수 경계 또는 저장된 바이트를 변경합니다. `PATCH`는 데이터베이스 편집이지, 실행 중인 프로세스에 패치를 적용했다는 증거가 아닙니다. 어느 리스너도 인증을 문서화하지 않았습니다. IDA는 루프백 전용이지만 Ghidra는 네트워크 인터페이스를 통해 접근할 수 있으므로, Ghidra 리스너를 사용할 때는 접근을 제한하세요. `QUIT`는 어느 쪽 리스너든 중지하며, IDA는 `ida_bridge_stop()`도 제공합니다.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner로 shellcode 디버깅하기

[**BlobRunner**](https://github.com/OALabs/BlobRunner)는 **shellcode**를 할당하고 **메모리 주소**를 출력한 뒤 실행을 일시 중지합니다.\
IDA 또는 x64dbg 같은 디버거를 연결하고, 출력된 주소에 중단점을 설정한 다음 실행을 재개하여 shellcode를 디버깅하세요.

GitHub 릴리스 페이지에는 컴파일된 릴리스가 포함된 zip 파일이 있습니다: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
다음 링크에서 Blobrunner를 약간 수정한 버전을 찾을 수 있습니다. 컴파일하려면 **Visual Studio Code에서 C/C++ 프로젝트를 만들고 코드를 복사해 붙여넣은 다음 빌드하면 됩니다**.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it으로 shellcode 디버깅하기

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)는 BlobRunner와 유사합니다. shellcode를 할당하고 무한 루프에 진입합니다. 디버거를 연결하고 **2–5초간** 실행을 재개한 다음, 루프 안에서 일시 중지하고 할당된 shellcode로 실행을 넘기는 다음 호출까지 단계별로 진행하세요.

![할당된 shellcode 호출 직전, jmp2it의 무한 루프에서 일시 중지된 디버거](<../../images/image (509).png>)

컴파일된 버전의 [jmp2it은 릴리스 페이지에서 다운로드할 수 있습니다](https://github.com/adamkramer/jmp2it/releases/).

### Cutter로 shellcode 디버깅하기

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)는 radare의 GUI입니다. Cutter를 사용하면 shellcode를 에뮬레이션하고 동적으로 검사할 수 있습니다.

Cutter에서는 "Open File"과 "Open Shellcode"를 선택할 수 있습니다. 제 경우 shellcode를 파일로 열었을 때는 올바르게 디컴파일했지만, shellcode로 열었을 때는 그렇지 않았습니다:

![같은 바이트를 파일 또는 shellcode로 열었을 때 서로 다른 분석 결과를 보여 주는 Cutter](<../../images/image (562).png>)

원하는 위치에서 에뮬레이션을 시작하려면 해당 위치에 bp를 설정하세요. 그러면 Cutter가 그 위치부터 에뮬레이션을 자동으로 시작하는 것 같습니다:

![Cutter 에뮬레이션을 시작하기 전에 원하는 shellcode 진입점에 중단점을 설정하는 모습](<../../images/image (589).png>)

![선택한 shellcode 중단점에서 일시 중지된 Cutter 에뮬레이터](<../../images/image (387).png>)

예를 들어 hex dump에서 stack을 확인할 수 있습니다:

![Cutter의 hex dump에서 에뮬레이션된 shellcode stack을 확인하는 모습](<../../images/image (186).png>)

### shellcode 난독화 해제 및 실행된 함수 확인

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)를 사용해 보세요.\
shellcode가 사용하는 **함수**와 메모리에서 스스로를 **디코딩**하는지 여부 등을 알려 줍니다.

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

**Create Dump** 옵션은 메모리에서 shellcode가 동적으로 변경된 경우 최종 shellcode를 덤프합니다(디코딩된 shellcode를 다운로드할 때 유용함). **start offset**을 사용하면 특정 오프셋에서 shellcode를 시작할 수 있습니다. **Debug Shell** 옵션을 사용하면 scDbg 터미널에서 shellcode를 디버깅할 수 있습니다(하지만 이 용도에는 앞서 설명한 옵션 중 하나를 사용하는 편이 낫다고 생각합니다. Ida나 x64dbg를 사용할 수 있기 때문입니다).

### CyberChef를 사용한 디스어셈블

shellcode 파일을 입력으로 업로드하고 다음 레시피를 사용해 디스어셈블하세요: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA 난독화 역난독화

**Mixed Boolean-Arithmetic (MBA)** 난독화는 산술 연산자(`+`, `-`, `*`)와 비트 연산자(`&`, `|`, `^`, `~`, 시프트)를 혼합한 수식으로 `x + y` 같은 간단한 표현식을 숨깁니다. 중요한 점은 이러한 항등식이 보통 **고정 폭 모듈러 연산**에서만 성립하므로, 자리올림과 오버플로가 중요하다는 것입니다:

```c
(x ^ y) + 2 * (x & y) == x + y
```

이러한 표현을 일반적인 대수 도구로 단순화하면 비트 폭 의미론을 무시해 잘못된 결과를 얻기 쉽습니다.<sup>[[1]](#references)</sup>

### 실용적인 워크플로

1. Lift된 코드/IR/decompiler 출력의 **원래 비트 폭**(`8/16/32/64`비트)을 유지합니다.
2. 단순화하기 전에 표현식을 **분류**합니다.
   - **Linear**: 비트 연산 원자의 가중합
   - **Semilinear**: `x & 0xFF` 같은 상수 마스크와 linear 항의 결합
   - **Polynomial**: 곱셈이 포함됨
   - **Mixed**: 곱셈과 비트 논리가 섞여 있으며, 반복되는 부분 표현식이 자주 나타남
3. 후보 재작성은 모두 random testing 또는 SMT proof로 **검증**합니다. 동등성을 증명할 수 없다면 추측하지 말고 원래 표현식을 유지합니다.

### 좁은 실행 슬라이스로 flattened control flow 우회하기

완전한 control-flow graph를 복원할 필요는 없는 경우가 많습니다. control-flow flattening, opaque predicates, 대형 dispatcher 또는 MBA-heavy 코드가 있다면, 암호화된 blob과 출력 버퍼에서 참조를 따라가 이를 변환하는 가장 작은 루틴을 찾습니다. 그런 다음 해당 data-flow slice만 재현하거나 독립적으로 실행합니다. 관련 상태를 직접 초기화할 수 있다면 dispatcher는 필수 해결 요소가 아닙니다.<sup>[[7]](#references)</sup>

실용적인 워크플로는 다음과 같습니다.<sup>[[7]](#references)</sup>

1. 실행 파일 및 데이터 섹션, relocation, cross-reference를 조사합니다. 바이트 순서와 요소 폭을 유지하면서 `.rodata`에서 후보 테이블을 덤프합니다.
2. 평문 또는 출력 버퍼에 마지막으로 쓰는 루틴을 찾습니다. 입력, 참조된 테이블, imported call, 필요한 전역 상태를 기록합니다.
3. 해당 연산만 고정 폭 Python 모델로 옮깁니다. 슬라이스가 여전히 너무 많은 상태에 의존한다면, 전체 프로그램을 에뮬레이트하는 대신 Unicorn, QEMU 또는 debugger에서 루틴을 호출하고 불필요한 import를 hook합니다.
4. extractor가 실제로 제공된 binary에서 출력을 도출하는지 검증합니다. 조용한 fallback을 제거하고, 내장된 답이 있는지 검색하며, 문자열, 키, 식별자, 레이아웃, 난독화 seed가 바뀐 미확인 build에서도 실행합니다.

유용한 초기 확인 명령은 다음과 같습니다.<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 상수로 위장한 MBA expressions 탐지

입력에 따라 달라지는 것처럼 보이는 바이트 표현식도 입력의 영향을 완전히 상쇄할 수 있습니다. 테이블을 추출한 뒤 8비트 전체 도메인에서 표현식을 평가합니다. 출력 집합이 단일 원소라면 주변 상태 머신을 복원하지 않고도 해당 바이트가 상수임을 증명할 수 있습니다.<sup>[[7]](#references)</sup>

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

최종 마스크는 유지하세요. 원래 덧셈에서 바이트 너비 오버플로가 발생하기 때문입니다. 더 넓은 도메인에서는 같은 너비의 심볼릭 입력 두 개에 대해 `f(x1) != f(x2)`가 만족 가능한지 SMT solver에 질의하세요. `unsat`이면 불변성이 증명되고, `sat`이면 반례가 나오므로 입력을 제거할 수 없습니다.<sup>[[7]](#references)</sup>

#### 환경에 종속된 디코딩 인식

Anti-analysis 검사는 반드시 분기하거나 크래시를 일으킬 필요가 없습니다. 디코더는 센서 결과를 키 비트, opaque-predicate 상수 또는 flattened dispatcher 상태에 섞고 정상적으로 계속 실행하여 에뮬레이터에서 그럴듯하지만 잘못된 평문을 만들 수 있습니다. 따라서 눈에 보이는 실패 분기만 패치해서는 충분하지 않습니다. 환경 프로브에서 디코더 상태로 이어지는 데이터 종속성을 추적하고, 실제 기기와 에뮬레이터에서 동일한 슬라이스를 비교하며, 각 센서 결과를 강제했을 때 최종 버퍼가 어떻게 달라지는지 테스트하세요.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA)는 malware 분석과 보호된 바이너리 reversing을 위한 실용적인 MBA simplifier입니다. 모든 항목에 하나의 일반적인 재작성 패스를 적용하는 대신, 표현식을 분류하고 전문화된 파이프라인으로 전달합니다.<sup>[[2]](#references)</sup>

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

Useful cases:

- **Linear MBA**: CoBRA는 Boolean 입력에서 표현식을 평가하고, 시그니처를 도출한 뒤, 패턴 매칭, ANF 변환, 계수 보간 등 여러 복구 방법을 경쟁시킵니다.
- **Semilinear MBA**: 상수 마스크가 적용된 원자는 비트 분할 재구성을 통해 다시 만들어 마스크된 영역이 올바르게 유지되도록 합니다.
- **Polynomial/Mixed MBA**: 곱을 핵심 요소로 분해하고, 반복되는 부분식을 임시 변수로 추출한 뒤 바깥쪽 관계를 단순화할 수 있습니다.

복구를 시도해 볼 만한 혼합 항등식의 예:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

이는 다음과 같이 축약할 수 있습니다:

```c
x * y
```

### Reversing 참고 사항

- 정확한 연산을 분리한 후, **lifted IR expressions** 또는 decompiler 출력에 CoBRA를 실행하는 것이 좋습니다.
- 표현식이 masked arithmetic 또는 narrow registers에서 나온 경우 `--bitwidth`를 명시적으로 사용하세요.
- 더 강력한 증명이 필요하면 여기의 로컬 Z3 참고 자료를 확인하세요:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA는 **LLVM pass plugin**(`libCobraPass.so`)으로도 제공되며, 이후 분석 pass를 실행하기 전에 MBA가 많은 LLVM IR을 정규화할 때 유용합니다.
- 지원되지 않는 carry-sensitive mixed-domain residuals가 나오면 원래 표현식을 유지하고 carry 경로를 수동으로 분석해야 한다는 신호로 보세요.

## XOR-state control-flow flattening 복구

OLLVM 스타일의 flattener는 두 개의 64비트 레지스터에 현재 basic-block state를 저장하고 dispatcher에서 XOR로 이를 재구성할 수 있습니다. 각 원본 block은 다음 state에 해당하는 쌍을 기록한 후 dispatcher로 되돌아갑니다. 조건부 block은 CPU flags에 따라 쌍의 한쪽을 대체하는 데 `CMOVcc`를 사용할 수 있으므로, 눈에 보이는 branch instruction만 따라가면 두 successor를 놓치게 됩니다. Indirect-jump dispatcher와 달리, 이 구조는 전반적으로 direct back-edge를 사용할 수 있습니다.<sup>[[19]](#references)[[20]](#references)</sup>

Control-flow graph를 복구하려면 dispatcher의 comparison tree와 두 state register를 찾고, 비교되는 각 XOR state를 대상 block에 대응시킨 다음, 각 원본 block에서 register 쌍에 도달하는 write를 추적하세요. 조건부 write의 경우 flag를 설정하는 instruction과 두 `CMOVcc` 결과를 모두 포함하세요. 각 block의 dispatcher 종료 지점을 확인된 direct successor 또는 conditional branch로 바꾸면 binary를 patch하지 않고도 dispatcher를 더 이상 도달할 수 없게 됩니다. 이는 전체 CFG를 대상으로 하는 방식입니다. decoder 하나만 중요하다면 위의 [narrow execution-slice workflow](#bypass-flattened-control-flow-with-a-narrow-execution-slice)가 더 빠를 수 있습니다.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis)는 Binary Ninja에서 이 구조를 자동화합니다. `plugins/DispatchThis`를 Binary Ninja 사용자 plugin 디렉터리에 복사한 뒤 재시작하세요. 해당 함수에서 **Function Settings**를 열고 `OLLVM_XOR_64`를 선택하세요. 분석이 시작되지 않으면 **Analysis → Reanalyze All Functions**를 사용하세요. 이 모드는 파일 바이트가 아니라 MLIL control-flow edge를 다시 작성하며, Z3 또는 indirect-jump resolver가 필요하지 않습니다. Binary Ninja 5.3.9757+에서 테스트되었습니다. block마다 남아 있는 사용되지 않는 state write는 제거하지 않으므로, 이를 아직 활성인 transition으로 오해하지 마세요.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

이 obfuscator는 프로그램 연산을 `mov` 기반 instruction sequence로 대체하고, signal/exception handling을 사용해 control flow를 변경합니다. 자세한 내용은 다음을 참고하세요.

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

지원되는 binary의 경우 [demovfuscator](https://github.com/kirschju/demovfuscator)를 사용해 결과를 deobfuscate할 수 있습니다. 몇 가지 dependency가 필요합니다.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

그리고 [keystone을 설치하세요](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTF를 플레이 중이라면, flag를 찾기 위한 이 우회 방법**이 매우 유용할 수 있습니다: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point**를 찾으려면 다음처럼 `::main`을 검색해 함수들을 살펴보세요.

![함수 이름에서 double-colon main을 검색해 Ghidra에서 Rust entry point 찾기](<../../images/image (1080).png>)

이 경우 바이너리 이름이 authenticator였으므로, 어떤 함수가 흥미로운 main 함수인지 꽤 분명합니다.\
호출되는 **함수**의 **이름**을 확인한 다음, **입력**과 **출력**을 알아보려면 **인터넷**에서 검색하세요.

### ELF firmware에서 Rust 문자열 복구하기

**Rust ELF** 바이너리에서는 많은 정적 문자열이 C 스타일의 NUL 종료 포인터로 참조되지 않습니다. 일반적인 `rustc` 레이아웃에서는 **`.data.rel.ro`** 안의 **포인터/길이 튜플**이 **`.rodata`**에 저장된 실제 문자열 blob을 가리킵니다:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

이는 `strings` 또는 Ghidra의 기본 분석이 인접한 문자열을 병합하거나 상호 참조를 완전히 놓칠 수 있다는 뜻입니다.<sup>[[3]](#references)</sup>

빠른 워크플로:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`**의 가상 주소와 크기를 가져옵니다.
2. **`.data.rel.ro`**를 한 워드씩 열거합니다.
3. `.rodata` 주소 범위 내의 값을 문자열 포인터 후보로 간주합니다.
4. 다음 워드를 후보 길이로 간주합니다.
5. 유효성 필터를 적용합니다(예: 길이가 **4**~**100**바이트인 항목만 유지).
6. `0x00`까지 스캔하지 말고, `.rodata`에서 `length` 바이트를 정확히 읽습니다.

최소 추출 로직:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

이는 firmware 리버싱에서 특히 유용합니다. 복구한 Rust 문자열을 통해 **HTTP 경로, RPC 이름, 로그 메시지, 어설션, 파일명, 설정 키, 명령 핸들러, 인증 관련 로직**을 확인할 수 있는 경우가 많습니다.

Ghidra가 이러한 문자열을 찾지 못하면, 동일한 휴리스틱을 적용하고 참조된 `.rodata` 오프셋에 문자열 데이터를 생성하는 커스텀 스크립트/플러그인을 실행하세요. Pen Test Partners가 공개한 `rust-strings` 및 `RustStrings.py` 도구는 이 아이디어를 다른 **워드 크기, 엔디언, 섹션 레이아웃**에 맞게 적용할 때 참고하기 좋습니다.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi 컴파일 바이너리에는 [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)를 사용할 수 있습니다.

Delphi 바이너리를 리버싱해야 한다면 IDA 플러그인 [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)를 사용하는 것을 권장합니다.

IDA에서 **Alt+F7**을 눌러 Python 플러그인을 불러온 다음, 플러그인 파일을 선택하세요.

이 플러그인은 바이너리를 실행하고 디버깅을 시작할 때 함수 이름을 동적으로 확인합니다. 디버깅을 시작한 후 Start 버튼(초록색 버튼 또는 f9)을 다시 누르면 실제 코드의 시작 부분에서 브레이크포인트에 걸립니다.

그래픽 애플리케이션에서 버튼을 누르면 디버거가 해당 버튼에 의해 호출되는 함수에서 멈출 수 있습니다.

## Golang

일반적인 Go 바이너리의 경우 [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)를 사용하면 런타임 구조를 복구하고 IDA에서 함수 이름을 개선할 수 있습니다. **Alt+F7**을 눌러 Python 플러그인을 불러오세요.

Golang 바이너리를 리버싱해야 한다면 IDA 플러그인 [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)를 사용하는 것을 권장합니다.

IDA에서 **Alt+F7**을 눌러 Python 플러그인을 불러온 다음, 플러그인 파일을 선택하세요.

이 플러그인은 함수 이름을 확인합니다.

### 심볼 테이블 없이 메타데이터 복구하기

strip된 Go 실행 파일도 프로그램 카운터를 함수에 매핑하기 위해 런타임 메타데이터가 필요합니다. [GoReSym](https://github.com/mandiant/GoReSym)은 Go 런타임에서 가져온 코드를 사용해 `pclntab` 및 `moduledata`와 같은 구조를 찾고 파싱합니다. 이를 통해 기존 심볼 테이블에 의존하지 않고 함수 경계, 이름, 소스 경로, 타입 및 빌드 정보를 복구할 수 있습니다.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

난독화 도구는 복구된 이름을 바꾸면서도 이러한 구조를 계속 사용할 수 있게 둘 수 있습니다. 예를 들어 Garble은 식별자와 패키지 경로를 해시하고 빌드, 모듈 및 디버그 정보를 제거합니다.<sup>[[12]](#references)</sup> 난독화된 패키지 토큰은 해당 패키지의 함수들에서 일관되게 유지되어야 합니다. 반복되는 토큰을 기준으로 함수를 그룹화하고, 각 함수의 callee, 문자열 및 API를 통해 패키지 하나를 추론한 다음, 그 패키지 레이블을 그룹 전체에 전파합니다.<sup>[[13]](#references)</sup>

### GoResolver로 Garble 이름 복구하기

[GoResolver](https://github.com/volexity/GoResolver)는 runtime-symbol 추출과 clean-reference 생성, control-flow-graph(CFG) 매칭을 결합합니다. 다음 순서로 진행하세요:<sup>[[10]](#references)[[13]](#references)</sup>

1. **컴파일러 버전을 식별합니다.** 먼저 `BuildInfo`와 포함된 버전 문자열을 확인합니다. 난독화 도구가 이를 제거했다면, 번들된 Go runtime의 일부를 버전별 참조 runtime과 비교합니다. Volexity의 테스트에서는 runtime의 약 `2%`만으로도 주요 Go 버전을 구분할 수 있었습니다. 이를 보편적인 기준이 아니라 경험적 최적화로 간주하세요.<sup>[[13]](#references)</sup>
2. **매칭에 사용할 참조 바이너리를 만듭니다.** 식별한 Go 버전, 대상 아키텍처 및 사용 가능성이 높은 라이브러리에 맞는 clean 바이너리를 생성합니다. toolchain을 일치시키면 컴파일러가 생성한 CFG의 차이를 줄일 수 있습니다.<sup>[[10]](#references)[[13]](#references)</sup>
3. **함수를 비교합니다.** GoGrapher는 함수 CFG를 매칭하고 `0.0`부터 `1.0`까지 정규화된 점수를 출력합니다. basic-block 매칭은 유사한 명령어를 가중 비교하는 방식입니다. 신뢰도가 높은 매칭은 무작위화된 함수를 clean 구현에 연결합니다. 신뢰도가 더 낮은 매칭도 패키지나 모듈을 식별하는 데 도움이 됩니다.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **검증한 뒤 가져옵니다.** 제안된 이름을 호출 관계, 상수, 문자열 및 side effect로 확인한 다음, IDA 또는 Ghidra용 GoResolver 플러그인으로 JSON 보고서를 가져옵니다.<sup>[[10]](#references)[[13]](#references)</sup>

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

기본 significant-match 임계값은 `0.9`입니다. `--extract` 및 `--graph` 스위치를 사용하면 각 단계를 개별적으로 실행할 수 있으며, 기본 설정에서는 복구된 runtime metadata와 CFG 증거가 서로 보완되므로 두 단계 모두 실행됩니다.<sup>[[10]](#references)</sup> CFG 점수는 휴리스틱입니다. 인라이닝, 빌드 플래그, 아키텍처 및 라이브러리 버전 차이에 따라 그래프 형태가 달라질 수 있으므로, 신뢰도가 낮은 이름을 억지로 지정하는 대신 확인되지 않은 함수는 그대로 두세요.<sup>[[13]](#references)</sup>

### Go 문자열 테이블 복구

Go 바이너리는 링크된 모든 패키지의 문자열 바이트를 하나의 연속된 테이블에 배치합니다. 항목은 NUL 문자로 끝나지 않으며 runtime 구조체에서도 테이블의 시작 주소나 크기를 확인할 수 없습니다. 하지만 컴파일러는 운영체제와 아키텍처에 관계없이 항목을 길이순, 그다음 알파벳순으로 정렬합니다. 따라서 항목 하나를 찾으면 분석가는 인접한 항목을 따라가고 데이터 교차 참조를 사용해 문자열을 코드와 연결할 수 있습니다.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor)는 IDA Pro와 Ghidra에서 이 작업을 자동화합니다. 플러그인은 데이터 세그먼트의 교차 참조를 사용하므로 먼저 자동 분석이 완료될 때까지 기다리세요. 기본 앵커는 runtime 문자열 `entersyscall`이며, 그 뒤 양방향으로 스캔하고 복구된 문자열을 데이터베이스에 정의한 다음 문자열과 이를 참조하는 함수의 매핑을 JSON으로 내보낼 수 있습니다.<sup>[[14]](#references)</sup>

참조 함수의 패키지별로 보고서를 필터링하면 애플리케이션 또는 malware 코드와 링크된 라이브러리의 불필요한 정보를 분리할 수 있습니다. 이 기법으로는 Garble의 `-literals` 변환처럼 난독화로 파괴된 리터럴을 복구할 수 없습니다. 그래도 난독화되지 않은 runtime 문자열을 정리하는 데는 유용합니다.<sup>[[14]](#references)[[15]](#references)</sup>

### Go runtime 타입 복구

Go는 garbage collection 같은 기능에 사용되는 runtime 타입 정보를 포함합니다. 빌드 정보가 제거되었거나 디스어셈블러가 이 메타데이터를 파싱하지 못하면, 명령어가 임의의 데이터 주소를 로드하는 것처럼 보이고 대상 영역은 타입이 지정되지 않은 상태로 남습니다. 메타데이터를 복구하면 해당 주소를 읽기 쉬운 타입 참조로 바꿀 수 있어 패키지의 기능을 더 쉽게 파악할 수 있습니다.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver)는 심볼을 추출하고 runtime 타입을 파싱해 JSON 보고서로 만들 수 있습니다. 현재 CLI에서는 `resolve` 하위 명령을 사용합니다.<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` 옵션은 타입 파싱을 활성화합니다. 보고서를 GoResolver의 IDA Pro 또는 Ghidra 플러그인으로 가져와 복구된 타입을 정의하고 분석 데이터베이스에 해당 참조를 적용하세요. 이 기능과 함께 도입된 보고서 형식에서는 `-y`를 생략하면 RTTI 주소와 복구된 타입 멤버가 null로 남습니다.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver는 x86, AMD64, ARM, ARM64용 PE, ELF, Mach-O 샘플을 지원하므로 Windows, Linux, macOS의 Go 바이너리에도 동일한 워크플로를 적용할 수 있습니다.<sup>[[10]](#references)</sup>

## 컴파일된 Python

이 페이지에서는 ELF/EXE Python 컴파일 바이너리에서 Python 코드를 가져오는 방법을 확인할 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBA 게임의 **바이너리**를 얻었다면, 여러 도구를 사용해 이를 **에뮬레이션**하고 **디버깅**할 수 있습니다:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_디버그 버전 다운로드_) - 인터페이스가 있는 디버거 포함
- [**mgba** ](https://mgba.io)- CLI 디버거 포함
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra 플러그인
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra 플러그인

[**no$gba**](https://problemkaputt.de/gba.htm)에서 _**Options --> Emulation Setup --> Controls**_** **로 이동하면 Game Boy Advance **버튼**을 누르는 방법을 확인할 수 있습니다.

![Game Boy Advance 버튼 매핑을 보여 주는 no$gba 컨트롤 설정](<../../images/image (581).png>)

각 **키에는 값이 있어** 키를 식별할 수 있습니다:

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

따라서 이런 종류의 프로그램에서 흥미로운 부분은 **프로그램이 사용자 입력을 어떻게 처리하는가**입니다. 주소 **0x4000130**에서 흔히 볼 수 있는 함수인 **KEYINPUT**을 찾을 수 있습니다.

![주소 0x4000130에서 KEYINPUT을 참조하는 GBA 바이너리의 Ghidra 보기](<../../images/image (447).png>)

이전 이미지에서 이 함수가 **FUN_080015a8**(주소: _0x080015fa_ 및 _0x080017ac_)에서 호출되는 것을 확인할 수 있습니다.

이 함수에서는 중요하지 않은 몇 가지 초기화 작업이 끝난 후:

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

마지막 if는 **`uVar4`**가 **마지막 키들**에 있고 현재 키가 아닌지 확인합니다. 즉, 버튼에서 손을 뗀 경우입니다(현재 키는 **`uVar1`**에 저장됨).

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

이전 코드에서 **uVar1**(**눌린 버튼의 값**이 저장된 위치)을 다음 값들과 비교하는 것을 볼 수 있습니다.

- 먼저 **값 4**(**SELECT** 버튼)와 비교합니다. 이 챌린지에서 이 버튼은 화면을 지웁니다.
- 그런 다음 **값 8**(**START** 버튼)과 비교합니다. 이 챌린지에서는 이 경로에서 입력한 코드가 유효한지 확인합니다.
  - 이 경우 변수 **`DAT_030000d8`**의 값을 0xf3과 비교하고, 값이 일치하면 일부 코드가 실행됩니다.
- 그 외의 경우에는 카운터(`DAT_030000d4`)를 확인하고 증가시킵니다.\
  카운터가 8보다 작은 동안 눌린 키의 값이 `DAT_030000d8`에 누적됩니다.

따라서 이 챌린지에서는 버튼 값을 알고 있다면, 길이가 8보다 짧으면서 합계가 0xf3이 되는 **조합을 눌러야 합니다.**

**이 튜토리얼의 참고 자료:** [Nostalgia 챌린지 writeup 아카이브](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [3] [Rust 문자열 디코딩하기 - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - Rust 문자열](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing 튜토리얼 (아카이브)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI 지원 reverse engineering 무력화하기, 또는 적어도 시도하기](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Basic Block 매칭 기반 Control Flow Graph 비교 접근법](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver 저장소](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble 난독화 메커니즘](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Control-Flow Graph 유사성을 사용해 Golang 바이너리 자동으로 난독화 해제하기](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor 저장소](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity Golang 도구 업데이트](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: 무엇이든 Reverse Engineer하기](https://github.com/morluto/rea)
- [17] [REA managed-code 분석](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI 및 Evidence 가이드](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Binary Ninja control-flow unflattening 워크플로](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF 제로데이 침입, Java Loader, Web Shell 및 AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [IDA bridge 서버 구현](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Ghidra bridge 서버 구현](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int)는 와일드카드 주소에 바인딩됨](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: Godot reverse engineering 툴킷](https://github.com/figurophobia/gore)
- [26] [gore 키 복구 구현](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [gore 암호화 blob 형식](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [gore 명령 및 복구 구현](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
