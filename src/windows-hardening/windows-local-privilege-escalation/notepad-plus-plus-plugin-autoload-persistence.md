# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++는 실행 시 `plugins` 하위 폴더에 있는 **모든 plugin DLL을 자동으로 로드**합니다. **쓰기 가능한 Notepad++ 설치 경로**에 악성 plugin을 추가하면 편집기가 시작될 때마다 `notepad++.exe` 내부에서 code execution이 발생하며, 이를 **persistence**, 은밀한 **initial execution**, 또는 편집기가 elevated 권한으로 실행되는 경우 **in-process loader**로 악용할 수 있습니다.<sup>[[1]](#references)</sup>

**Notepad++ 7.6+**에서는 수동 설치 시 일반적으로 **plugin마다 하나의 하위 폴더**를 사용하는 레이아웃이 필요합니다(`plugins\<PluginName>\<PluginName>.dll`). **portable mode**에서는 `notepad++.exe` 옆에 `doLocalConf.xml`이 존재하므로 전체 애플리케이션 트리가 해당 디렉터리에 로컬로 유지됩니다. 따라서 복사된 관리자 도구 번들이 사용자 쓰기 가능한 간편한 실행 표면으로 변하는 경우가 많습니다.<sup>[[2]](#references)</sup>

## 쓰기 가능한 plugin 위치

- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (일반적으로 쓰기 권한을 얻으려면 admin 권한이 필요함).<sup>[[1]](#references)</sup>
- low-privileged operator를 위한 쓰기 가능한 옵션:<sup>[[1]](#references)</sup>
- **portable Notepad++ build**를 사용자 쓰기 가능한 폴더에서 사용합니다.
- `C:\Program Files\Notepad++`를 사용자 제어 경로(예: `%LOCALAPPDATA%\npp\`)에 복사한 다음 해당 위치에서 `notepad++.exe`를 실행합니다.
- 이미 `doLocalConf.xml`을 포함하고 있으며 `Program Files` 외부에 있는 **admin tool bundle**, 압축 해제된 zip 복사본 또는 help-desk toolkit을 찾습니다.
- 각 plugin은 `plugins` 아래에 자체 하위 폴더를 가지며 시작 시 자동으로 로드됩니다. 메뉴 항목은 **Plugins** 아래에 표시됩니다.<sup>[[2]](#references)</sup>

빠른 점검:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## 플러그인 로드 지점 (execution primitives)
Notepad++는 특정 **exported functions**를 요구합니다. 이러한 함수는 모두 initialization 중에 호출되므로, 여러 execution surface를 제공합니다:<sup>[[1]](#references)</sup>
- **`DllMain`** — DLL load 시 즉시 실행됩니다 (첫 번째 execution point).
- **`setInfo(NppData)`** — load 시 한 번 호출되어 Notepad++ handles를 제공합니다. menu items를 등록하는 일반적인 위치입니다.
- **`getName()`** — menu에 표시되는 plugin name을 반환합니다.
- **`getFuncsArray(int *nbF)`** — menu commands를 반환합니다. 비어 있더라도 startup 중에 호출됩니다.
- **`beNotified(SCNotification*)`** — Notepad++ / Scintilla events를 수신합니다 (user action 또는 editor event까지 payloads를 defer하는 데 유용).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler이며, 더 큰 data exchanges에 유용합니다.
- **`isUnicode()`** — load 시 확인되는 compatibility flag입니다.

대부분의 exports는 **stubs**로 구현할 수 있으며, autoload 중 `DllMain` 또는 위 callback에서 execution이 발생할 수 있습니다.

## Minimal malicious plugin skeleton
예상되는 exports를 포함한 DLL을 compile한 다음, writable Notepad++ folder 아래의 `plugins\\MyNewPlugin\\MyNewPlugin.dll`에 배치합니다:<sup>[[1]](#references)</sup>
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
2. `plugins` 아래에 plugin 하위 폴더를 만들고 DLL을 넣습니다.
3. Notepad++를 재시작합니다. DLL이 자동으로 로드되어 `DllMain`과 이후 callbacks를 실행합니다.

## `beNotified`를 통한 low-noise trigger pattern
OPSEC를 위해 많은 payload는 **`DllMain`에서 실행되지 않아야 합니다**. 더 조용한 pattern은 plugin이 정상적으로 로드되도록 한 다음, **startup complete**, **buffer activation** 또는 **first typed character**와 같은 현실적인 editor event 이후에만 실행하는 것입니다.
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
이 내용은 시끄러운 `DllMain` beacon보다 공개 offensive research에 더 잘 부합합니다. DLL은 시작 시 여전히 autoload되지만, 악성 동작은 Notepad++가 실제로 사용 중인 것으로 보일 때까지 지연됩니다.

## plugin config directory를 secondary storage로 사용
Notepad++는 **current user's plugin configuration directory**를 반환하는 `NPPM_GETPLUGINSCONFIGDIR`을 노출합니다.<sup>[[3]](#references)</sup> 악성 plugin은 이를 사용해 디스크에 저장되는 DLL은 최소화하고, 일반적인 plugin 상태에 자연스럽게 섞이는 경로에 encrypted config, staged payloads 또는 tasking files를 저장할 수 있습니다.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
운영 측면에서 다음과 같은 경우에 유용합니다:
- 작은 autoloaded bootstrap DLL이 필요한 경우;
- 메인 plugin binary를 다시 건드리지 않고 per-user tasking을 수행하려는 경우;
- **autoload trigger**를 더 무거운 second stage와 분리하려는 경우.

## Reflective loader plugin pattern
무기화된 plugin은 Notepad++를 **reflective DLL loader**로 전환할 수 있습니다:<sup>[[1]](#references)</sup>
- 최소한의 UI/menu 항목(예: "LoadDLL")을 표시합니다.
- **file path** 또는 **URL**을 받아 payload DLL을 가져옵니다.
- DLL을 현재 process에 reflectively map하고 exported entry point(예: 가져온 DLL 내부의 loader function)를 호출합니다.
- 이점: 새로운 loader를 생성하는 대신 정상적으로 보이는 GUI process를 재사용하며, payload는 `notepad++.exe`의 integrity level을 상속합니다( elevated context 포함).
- 단점: 디스크에 **unsigned plugin DLL**을 남기는 것은 흔적이 큽니다. 실용적인 변형 방식은 autoloaded plugin을 stub으로만 사용하고 실제 implant는 다른 위치에 암호화된 상태로 저장하거나 staged 방식으로 유지하는 것입니다.

## Detection and hardening notes
- **Notepad++ plugin directories**에 대한 쓰기를 차단하거나 모니터링합니다(user profile 내 portable copy 포함). controlled folder access 또는 application allowlisting을 활성화합니다.
- `plugins` 아래의 **new unsigned DLL**, portable Notepad++ tree의 변경, `notepad++.exe`에서 발생하는 비정상적인 **child processes/network activity**를 alert 대상으로 설정합니다.
- 정상적인 plugin을 baseline으로 설정하고, 일반적인 Notepad++ plugin interface를 export하면서 동시에 shell, PowerShell 또는 network beacon을 생성하는 새 DLL을 조사합니다.
- plugin 설치는 **Plugins Admin**을 통해서만 수행하도록 강제하고, 신뢰할 수 없는 경로에서 portable copy가 실행되지 않도록 제한합니다.

## 참고 자료

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
