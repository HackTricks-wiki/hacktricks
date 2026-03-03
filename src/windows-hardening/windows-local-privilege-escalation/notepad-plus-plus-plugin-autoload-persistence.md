# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ は起動時に `plugins` サブフォルダ内で見つかったすべてのプラグイン DLL を **autoload** します。書き込み可能な Notepad++ インストール先に悪意あるプラグインを置くと、エディタ起動時に毎回 `notepad++.exe` 内でコードが実行されます。これを利用して **persistence**、ステルスな **initial execution**、またはエディタが昇格して起動された場合の **in-process loader** として悪用できます。

## 書き込み可能なプラグインの場所
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (通常、書き込みには管理者権限が必要です)。
- 低権限ユーザ向けの書き込みオプション:
- ユーザーが書き込み可能なフォルダに **portable Notepad++ build** を使う。
- `C:\Program Files\Notepad++` をユーザー管理下のパス（例: `%LOCALAPPDATA%\npp\`）にコピーし、そこから `notepad++.exe` を実行する。
- 各プラグインは `plugins` の下に独自のサブフォルダを持ち、起動時に自動で読み込まれます。メニュー項目は **Plugins** に表示されます。

## Plugin load points (execution primitives)
Notepad++ は特定の **exported functions** を期待します。これらは初期化時にすべて呼ばれ、複数の実行サーフェスを提供します:
- **`DllMain`** — DLL がロードされた直後に実行されます（最初の実行ポイント）。
- **`setInfo(NppData)`** — ロード時に一度呼ばれ、Notepad++ のハンドルを渡します。通常メニュー項目の登録場所です。
- **`getName()`** — メニューに表示されるプラグイン名を返します。
- **`getFuncsArray(int *nbF)`** — メニューコマンドを返します。空でも起動時に呼ばれます。
- **`beNotified(SCNotification*)`** — 編集イベント（ファイルの開閉/変更、UI イベントなど）を受け取り、継続的なトリガーに使えます。
- **`messageProc(UINT, WPARAM, LPARAM)`** — メッセージハンドラで、大きなデータ交換に有用です。
- **`isUnicode()`** — ロード時にチェックされる互換性フラグです。

ほとんどのエクスポートは **stubs** として実装できます。autoload 時の実行は `DllMain` または上記の任意のコールバックから発生させることができます。

## Minimal malicious plugin skeleton
期待されるエクスポートを持つ DLL をコンパイルし、書き込み可能な Notepad++ フォルダの `plugins\\MyNewPlugin\\MyNewPlugin.dll` に配置してください:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. DLLをビルドする (Visual Studio/MinGW).
2. `plugins` の下に plugin サブフォルダを作成し、DLLを配置する。
3. Notepad++ を再起動する。DLLが自動的にロードされ、`DllMain` とその後のコールバックが実行される。

## Reflective loader plugin pattern
A weaponized plugin can turn Notepad++ into a **reflective DLL loader**:
- 最小限の UI/メニュー項目（例: "LoadDLL"）を表示する。
- **file path** または **URL** を受け取り、ペイロードDLLを取得する。
- Reflectively map the DLL into the current process and invoke an exported entry point（例: 取得したDLL内の loader function）。
- 利点: 新しいローダーを起動する代わりに見た目が無害なGUIプロセスを再利用できる。ペイロードは `notepad++.exe` の整合性を継承する（昇格されたコンテキストを含む）。
- トレードオフ: 署名無しの **unsigned plugin DLL** をディスクに配置するのはノイズが大きい。存在する場合は既存の信頼されたプラグインに乗っかることを検討する。

## Detection and hardening notes
- **writes to Notepad++ plugin directories**（ユーザープロファイル内のポータブルコピーを含む）への書き込みをブロックまたは監視する。Controlled Folder Access を有効にするか、アプリケーションの allowlisting を実施する。
- `plugins` 以下の **new unsigned DLLs** や、`notepad++.exe` からの異常な **child processes/network activity** にアラートを出す。
- インストールは **Plugins Admin** 経由のみに制限し、信頼されていないパスからのポータブルコピーの実行を制限する。

## References
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
