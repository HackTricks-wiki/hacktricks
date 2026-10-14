# 타깃 지정 계측을 위한 WinDbg 자동화

{{#include ../../banners/hacktricks-training.md}}

WinDbg와 WinDbgX는 시작 시, 예외 발생 시, 중단점이 트리거될 때 debugger 명령을 실행할 수 있습니다. 이를 통해 퍼징이나 reversing 세션에서 모든 이벤트마다 수동으로 멈추는 대신, 입력으로 유도된 경로 주변의 상태만 수집할 수 있습니다.<sup>[[1]](#references)</sup>

## 유용한 예외에서 시작하기

`-c`는 debugger의 첫 중단 시 명령을 실행합니다. 설정을 마친 뒤 다시 실행하려면 끝에 `;g`를 추가합니다. WinDbg Classic을 무인 실행할 때 `-logo`는 명령 창 출력을 로그에 기록하고, `-Q`는 자동 workspace 저장을 비활성화하며, `-G`는 마지막 중단점을 무시해 타깃이 종료되면 세션을 끝냅니다. WinDbgX도 `-c`를 지원하며, 그 뒤에 설정된 Startup commands가 실행됩니다.<sup>[[1]](#references)[[7]](#references)</sup>

```text
windbg.exe -c "sxd av;g" -logo C:\logs\triage.txt C:\path\target.exe
```

Access violation의 경우, **`sxe av`는 first chance에서 중단하고**, **`sxd av`는 first chance를 건너뛰지만 처리되지 않은 second chance에서 중단하며**, **`sxi av`는 두 기회 모두 무시합니다**. 이 글의 `sxi`/`sxd` 설명은 서로 뒤바뀌어 있습니다. Microsoft 문서에 따르면 `sxd`는 second-chance 필터이고 `sxi`는 무시입니다. first-chance 명령에는 `-c`를, second-chance 명령에는 `-c2`를 사용하세요. 필터가 `sxd`라고 해서 first-chance `-c` 핸들러가 second-chance 핸들러로 바뀌지는 않습니다. `sx`로 활성 필터를 확인하세요.<sup>[[1]](#references)[[2]](#references)</sup>

```text
sxd -c2 "r;kv;!analyze -v" av
sxe -c "lm" ld
```

첫 번째 명령은 처리되지 않은 액세스 위반이 발생한 경우에만 레지스터, 스택 추적, 예외 분석을 수집합니다. 두 번째 명령은 모듈이 로드될 때 `lm`을 실행합니다. 중단점(`bp`), 모듈 로드(`ld`), 액세스 위반(`av`) 이벤트는 수명 주기가 서로 다르므로, 디버거 중단점에 의존할 때 `bp`를 전역적으로 무시하지 마세요.<sup>[[1]](#references)[[2]](#references)</sup>

## 제어 가능한 트리거로 비용이 큰 중단점 활성화하기

관심 경로에 진입하기 직전에 호출할 수 있는 스크립트에서 확인 가능하거나, 그 밖의 방식으로 입력을 제어할 수 있는 함수를 선택하세요. 확인할 할당자, 파서 또는 API 호출에 **action breakpoints**를 설정합니다. `bd`를 사용해 ID별로 비활성화하세요. 연결된 명령에서 해당 ID를 `be`로 활성화한 뒤 `g`로 실행을 재개하는 **trigger breakpoint**를 설정합니다. 두 번째로 제어 가능한 트리거를 설정해 다시 비활성화할 수도 있습니다. 트리거를 연결하기 전에 `bl`로 ID를 확인하세요. ID는 중단점 생성 순서에 따라 달라집니다. 이렇게 하면 비용이 적은 제어 지점과 비용이 큰 추적을 분리하고, 대상의 타이밍과 힙 레이아웃에 미치는 변화를 최소화할 수 있습니다.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

두 심볼을 확인한 뒤 사용할 명령 패턴은 다음과 같습니다. 대괄호로 표시된 심볼과 `bl`이 반환한 action breakpoint ID를 바꾸세요. ID가 0이라고 가정하지 마세요.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```text
bp <action-symbol> "r;g"
bl
bd <action-id>
bp <trigger-symbol> "be <action-id>;g"
```

Action breakpoint 명령은 `@$ip`와 `%y`(symbolized address)를 출력하고, 선택한 인수나 메모리를 덤프한 다음 계속 실행할 수 있습니다. 조건부 breakpoint가 선택한 범위의 포인터만 기록한다면, 먼저 그 범위가 테스트 입력을 실제로 포함하는지 확인하세요. 조건이 잘못되면 증거가 조용히 누락됩니다.<sup>[[1]](#references)</sup>

### 심볼로 트리거 찾기

구현 모듈을 모르는 경우 로드된 모든 모듈을 검색하세요. `bm`은 일치하는 모든 심볼에 breakpoint를 설정합니다. 스크립트에서 접근 가능한 함수를 호출하고 어떤 breakpoint가 발생하는지 확인하세요. 예를 들어, 디버깅 중인 renderer에서 소스가 `Math.cos(0)`을 실행하도록 해야 하며, 아무 브라우저 프로세스에서나 실행하는 것이 아닙니다.<sup>[[1]](#references)[[5]](#references)</sup>

```text
x *!*math*cos*
bm *edge*!*math*cos* ".printf \"%y called\n\", @$ip;g"
g
```

히트가 정확한 함수를 식별하면 `lm a <symbol>`을 사용해 해당 함수가 속한 이미지를 확인하고, `? <symbol> - <module>`을 사용해 모듈 기준 오프셋을 계산합니다. WinDbg는 실행 파일과 DLL에 대해 동일한 짧은 모듈 이름을 표시할 수 있으므로, 다른 프로세스에서 오프셋을 사용하기 전에 이미지 경로를 확인하세요. 오버헤드를 줄이려면 와일드카드 breakpoint를 확인된 심볼로 좁히세요.<sup>[[1]](#references)</sup>

### 심볼 없이 후보 찾기

Corelan의 Frida 기반 `corelan_trigscan.py`는 선택한 프로세스 모듈에서 부동 소수점, SSE, AVX 및 삼각 함수 명령어 패턴을 검색합니다. 이 도구는 WinDbg breakpoint 명령을 `corelan_trigscan.bps`와 번호가 붙은 더 작은 `.bps` 파일에 출력합니다. Python과 `frida-tools`를 사용해 대상에서 실행하되, **다른 debugger가 연결되지 않은 상태로** 실행하세요. 그런 다음 WinDbg를 동일한 프로세스/모듈에 연결하고, 관리하기 적절한 breakpoint 묶음을 로드하세요.<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.5 --min-relevant 50 --min-total 20 --min-trig 1
$$><C:\logs\msedge.dll\corelan_trigscan_0001.bps
```

알려진 모듈 기준 오프셋의 경우, 출력된 모든 중단점을 가져오기 전에 해당 오프셋이 임계값을 통과하는지 확인합니다:<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.15 --min-relevant 8 --min-total 45 --check-offset 00e13dc0 --min-icall 1
```

`--min-density`는 관련 명령어 밀도이고, `--min-relevant`와 `--min-total`은 명령어 개수의 하한을 설정하며, `--min-trig`는 강한 trig 유사 신호를 요구합니다. 알려진 함수를 찾지 못했다면 해당 함수의 **모듈 기준** 오프셋을 `--check-offset`에 전달해 프롤로그, 밀도, 개수, 간접 호출을 확인하세요. 얇은 래퍼는 밀도가 낮고 trig 명령어가 없을 수 있습니다. 임계값을 낮추고 래퍼를 찾는 경우 스크립트에서 실제로 지원하는 `--min-icall 1` 옵션을 사용하세요(`--min-ical`이 아님). 직접 호출되는 함수는 분석되지만 간접 대상은 안정적으로 추적할 수 없습니다. 생성된 중단점이 많아 WinDbg가 느려질 때는 더 작은 `--splitsize` 배치가 도움이 됩니다. 의도한 입력으로 중단점이 실행되기 전까지 후보는 검증된 것이 아닙니다.<sup>[[1]](#references)[[6]](#references)</sup>

## 소규모 디버거 프로그램과 PyKD

조건이 신뢰할 수 있으면 `.if`를, 공백으로 구분된 출력을 반복 처리하려면 `.foreach`를, 의사 레지스터를 사용해 메모리나 구조체를 순회하려면 `.for`를 사용하세요. `.foreach`는 **열 구성을 유지하지 않습니다**. 예를 들어 열 너비가 가변적인 `lm` 출력은 입력으로 적합하지 않지만, `lm 1m`은 토큰마다 모듈 이름 하나를 출력합니다. 추측한 조건이 실패 경로를 숨길 수 있다면 먼저 필터링하지 않은 데이터를 기록하세요.<sup>[[1]](#references)</sup>

```text
.foreach (mod { lm 1m }) { .echo ${mod} }
r $t0 = 0
.for ( ; @$t0 < 5 ; r $t0 = @$t0 + 1 ) { .printf "i = %d\n", @$t0 }
```

`as name value`로 만든 alias는 타입이 지정된 변수가 아니라 텍스트 치환입니다. `al`은 alias 목록을 표시하고, `ad name`은 alias를 삭제하며, `${name}`은 모호하지 않게 확장합니다. alias가 기본 제공 명령을 가리지 않도록 `bp`, `x`, `r` 같은 이름은 피하세요. MASM 표현식은 `poi(@$t0)`와 같은 포인터 연산에 적합하며, 심볼이 있으면 `@@c++(...)`를 사용해 타입이 지정된 필드에 접근할 수 있어 구조체 오프셋을 하드코딩하지 않아도 됩니다.<sup>[[1]](#references)</sup>

긴 명령 시퀀스는 command file에 넣으세요. `$$><filename`은 여러 줄을 하나의 명령 블록으로 결합하며, 뒤에 세미콜론으로 구분된 debugger 명령을 이어 쓸 수 있습니다. 여러 줄 제어 구조는 여전히 취약할 수 있으므로 각 `.if` 또는 `.for` 문을 한 줄로 작성하세요. 시작 시 `-c`에서 같은 파일을 실행할 수도 있습니다.<sup>[[1]](#references)[[8]](#references)</sup>

명령어로 처리하기 까다로운 로직에는 PyKD를 사용하면 Python에서 타입이 지정된 구조체, 레지스터, 메모리 및 debugger 출력을 다룰 수 있습니다. 예를 들어 `pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())`는 PEB 필드에 접근하고, `pykd.loadBytes(address, size)`는 메모리를 읽으며, `pykd.dbgCommand("lm")`은 파싱할 debugger 출력을 반환합니다. 종료 문자가 없을 수 있는 데이터를 읽을 때는 길이 제한이 없는 문자열 읽기보다 길이가 제한된 `loadChars`/`loadWChars`를 사용하세요. PyKD의 `disasm(address).asm(instruction)`은 **해당 주소에 어셈블된 바이트를 기록**하므로, 실행 중인 프로세스에서 opcode를 얻기 위해 이 기능을 사용한다면 원래 메모리를 보존하고 복원하세요.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Corelan: 디버깅 - WinDBG(X) 자동화 및 스크립팅 - 1부](https://corelan.be/index.php/2026/04/17/debugging-windbgx-automation-scripting-part-1)
- [2] [Microsoft: sx, sxd, sxe, sxi, sxn, sxr, sx- (예외 설정)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [3] [Microsoft: be (중단점 활성화)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/be--breakpoint-enable-)
- [4] [Microsoft: bd (중단점 비활성화)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bd--breakpoint-disable-)
- [5] [Microsoft: bp, bu, bm (중단점 설정)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
- [6] [Corelan trigscan 소스 코드](https://github.com/corelan/blogposts/blob/main/debugging/scripts/frida/corelan_trigscan.py)
- [7] [Microsoft: WinDbg 명령줄 옵션](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options)
- [8] [Microsoft: 스크립트 파일 실행](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)
