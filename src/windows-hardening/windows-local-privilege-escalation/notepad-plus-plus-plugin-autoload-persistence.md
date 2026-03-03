# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++는 시작 시 **`plugins` 하위 폴더에서 발견되는 모든 plugin DLL을 autoload**합니다. 쓰기 가능한 Notepad++ 설치 폴더에 악성 플러그인을 넣으면 에디터가 시작될 때마다 `notepad++.exe` 내부에서 코드 실행이 발생하며, 이는 **persistence**, 은밀한 **initial execution**, 또는 에디터가 elevated로 실행될 경우 **in-process loader**로 악용될 수 있습니다.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (일반적으로 쓰려면 admin 권한 필요).
- Writable options for low-privileged operators:
- Use the **portable Notepad++ build** in a user-writable folder.
- Copy `C:\Program Files\Notepad++` to a user-controlled path (e.g., `%LOCALAPPDATA%\npp\`) and run `notepad++.exe` from there.
- Each plugin gets its own subfolder under `plugins` and is loaded automatically at startup; menu entries appear under **Plugins**.

## Plugin load points (execution primitives)
Notepad++는 특정 **exported functions**를 기대합니다. 초기화 중 이들 함수가 모두 호출되어 여러 실행 지점이 생깁니다:
- **`DllMain`** — DLL 로드 즉시 실행됩니다 (첫 번째 실행 지점).
- **`setInfo(NppData)`** — 로드 시 한 번 호출되어 Notepad++ 핸들을 제공; 보통 메뉴 항목 등록에 사용됩니다.
- **`getName()`** — 메뉴에 표시될 플러그인 이름을 반환합니다.
- **`getFuncsArray(int *nbF)`** — 메뉴 명령을 반환합니다; 비어 있어도 시작 시 호출됩니다.
- **`beNotified(SCNotification*)`** — 편집기 이벤트(파일 열기/변경, UI 이벤트 등)를 수신하여 지속적인 트리거로 사용됩니다.
- **`messageProc(UINT, WPARAM, LPARAM)`** — 메시지 핸들러로, 대용량 데이터 교환에 유용합니다.
- **`isUnicode()`** — 로드 시 확인되는 호환성 플래그입니다.

대부분의 exports는 **stubs**로 구현할 수 있으며; autoload 동안 `DllMain`이나 위의 콜백들 어디에서나 실행이 발생할 수 있습니다.

## Minimal malicious plugin skeleton
기대되는 exports를 포함한 DLL을 컴파일하고 쓰기 가능한 Notepad++ 폴더의 `plugins\\MyNewPlugin\\MyNewPlugin.dll`에 배치하세요:
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
2. `plugins` 아래에 plugin 하위 폴더를 만들고 DLL을 그 안에 넣습니다.
3. Notepad++를 재시작하면 DLL이 자동으로 로드되어 `DllMain` 및 이후 콜백이 실행됩니다.

## Reflective loader plugin pattern
악용된 plugin은 Notepad++을 **reflective DLL loader**로 만들 수 있습니다:
- 최소한의 UI/메뉴 항목을 제공합니다(예: "LoadDLL").
- 페이로드 DLL을 가져오기 위해 **file path** 또는 **URL**을 받습니다.
- DLL을 현재 프로세스에 reflectively map하고 export된 entry point(예: 가져온 DLL 내부의 loader function)를 호출합니다.
- 이점: 새로운 로더를 생성하는 대신 정상으로 보이는 GUI 프로세스를 재사용할 수 있으며, 페이로드는 `notepad++.exe`의 무결성(권한 상승된 컨텍스트 포함)을 계승합니다.
- 단점: 디스크에 **unsigned plugin DLL**을 떨어뜨리는 것은 소음이 크므로, 가능하면 기존의 신뢰된 플러그인에 piggybacking하는 것을 고려하세요.

## 탐지 및 하드닝 노트
- **writes to Notepad++ plugin directories**를 차단하거나 모니터링하세요(사용자 프로필의 portable 복사본 포함); Controlled Folder Access 또는 애플리케이션 allowlisting을 활성화하세요.
- `plugins` 아래의 **new unsigned DLLs**에 대해 경보를 설정하고, `notepad++.exe`에서 발생하는 이상한 **child processes/network activity**를 모니터링하세요.
- 플러그인 설치는 **Plugins Admin**을 통해서만 허용하고, 신뢰할 수 없는 경로에서의 portable 복사본 실행을 제한하세요.

## 참고자료
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
