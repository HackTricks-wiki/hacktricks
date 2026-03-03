# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ は起動時に `plugins` サブフォルダ内で見つかったすべてのプラグイン DLL を自動的に読み込みます。悪意のあるプラグインを書き込み可能な Notepad++ インストールに配置すると、エディタの起動時に毎回 `notepad++.exe` 内でコードが実行されます。これは **persistence**, ステルスな **initial execution**, またはエディタが昇格して起動された場合の **in-process loader** として悪用できます。

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (通常は書き込みに管理者権限が必要).
- Writable options for low-privileged operators:
- Use the **portable Notepad++ build** in a user-writable folder.
- Copy `C:\Program Files\Notepad++` to a user-controlled path (e.g., `%LOCALAPPDATA%\npp\`) and run `notepad++.exe` from there.
- Each plugin gets its own subfolder under `plugins` and is loaded automatically at startup; menu entries appear under **Plugins**.

## Plugin load points (execution primitives)
Notepad++ は特定の **exported functions** を期待します。これらは初期化時にすべて呼ばれ、複数の実行サーフェスを提供します:
- **`DllMain`** — DLL ロード時に直ちに実行される（最初の実行ポイント）。
- **`setInfo(NppData)`** — ロード時に一度呼ばれ、Notepad++ のハンドルを渡す。メニュー項目登録の典型的な場所。
- **`getName()`** — メニューに表示されるプラグイン名を返す。
- **`getFuncsArray(int *nbF)`** — メニューコマンドを返す。空であっても起動時に呼ばれる。
- **`beNotified(SCNotification*)`** — ファイルのオープン/変更や UI イベントなど、継続的なトリガ用のエディタイベントを受け取る。
- **`messageProc(UINT, WPARAM, LPARAM)`** — メッセージハンドラ。大きなデータ交換に便利。
- **`isUnicode()`** — ロード時にチェックされる互換性フラグ。

ほとんどの export は **スタブ（stubs）** として実装可能で、autoload 中は `DllMain` や上記のいずれかのコールバックから実行が発生します。

## Minimal malicious plugin skeleton
期待される exports を持つ DLL をコンパイルし、書き込み可能な Notepad++ フォルダの `plugins\\MyNewPlugin\\MyNewPlugin.dll` に配置してください:
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
2. `plugins` 配下に plugin サブフォルダを作成し、DLL をその中に置く。
3. Notepad++ を再起動すると DLL が自動的にロードされ、`DllMain` および以降のコールバックが実行される。

## Reflective loader plugin pattern
攻撃用に改変されたプラグインは Notepad++ を **reflective DLL loader** に変えることができる：
- 最小限の UI/メニュー項目を表示する（例: "LoadDLL"）。
- ペイロード DLL を取得するための **file path** や **URL** を受け取る。
- 現在のプロセスに DLL をリフレクティブにマップし、エクスポートされたエントリポイントを呼び出す（例: 取得した DLL 内のローダ関数）。
- 利点: 新しいローダーを生成する代わりに一見無害な GUI プロセスを再利用でき、ペイロードは `notepad++.exe` の整合性を継承する（昇格されたコンテキストを含む）。
- トレードオフ: ディスクに **unsigned plugin DLL** を置くことは目立つので、存在する信頼されたプラグインに寄生することを検討する。

## Detection and hardening notes
- Notepad++ plugin ディレクトリへの書き込み（ユーザープロファイル内のポータブルコピーを含む）をブロックまたは監視する；controlled folder access や application allowlisting を有効にする。
- `plugins` 配下の **新しい unsigned DLL** や、`notepad++.exe` からの異常な **child processes/network activity** を検出してアラートする。
- プラグインのインストールは **Plugins Admin** 経由のみに限定し、信頼できないパスからのポータブルコピーの実行を制限する。

## References
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
