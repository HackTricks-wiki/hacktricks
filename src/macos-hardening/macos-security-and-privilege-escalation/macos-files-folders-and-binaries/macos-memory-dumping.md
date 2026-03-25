# macOS メモリダンプ

{{#include ../../../banners/hacktricks-training.md}}

## メモリアーティファクト

### スワップファイル

Swap files, such as `/private/var/vm/swapfile0`, serve as **caches when the physical memory is full**. When there's no more room in physical memory, its data is transferred to a swap file and then brought back to physical memory as needed. Multiple swap files might be present, with names like swapfile0, swapfile1, and so on.

### ハイバネーションイメージ

The file located at `/private/var/vm/sleepimage` is crucial during **hibernation mode**. **Data from memory is stored in this file when OS X hibernates**. Upon waking the computer, the system retrieves memory data from this file, allowing the user to continue where they left off.

It's worth noting that on modern MacOS systems, this file is typically encrypted for security reasons, making recovery difficult.

- To check if encryption is enabled for the sleepimage, the command `sysctl vm.swapusage` can be run. This will show if the file is encrypted.

### メモリプレッシャーログ

Another important memory-related file in MacOS systems is the **memory pressure log**. These logs are located in `/var/log` and contain detailed information about the system's memory usage and pressure events. They can be particularly useful for diagnosing memory-related issues or understanding how the system manages memory over time.

## osxpmem を使ったメモリダンプ

In order to dump the memory in a MacOS machine you can use [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**注意**: これは主に**レガシーワークフロー**です。`osxpmem` はカーネル拡張のロードに依存しており、[Rekall](https://github.com/google/rekall) プロジェクトはアーカイブされていて、最新リリースは **2017** 年のもので、公開バイナリは **Intel Macs** をターゲットにしています。現在の macOS リリース、特に **Apple Silicon** では、kext ベースの full-RAM acquisition はモダンなカーネル拡張制限、SIP、および platform-signing requirements によって通常ブロックされます。実際には、最新のシステムでは全RAMイメージを取得する代わりに、より頻繁に **process-scoped dump** を行うことになります。
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
このエラーが発生した場合: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` 次の方法で修正できます:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**その他のエラー** は "Security & Privacy --> General" で **kext の読み込みを許可すること** によって修正されることがあります。単に **allow** してください。

この **oneliner** を使ってアプリケーションをダウンロードし、kext をロードしてメモリをダンプすることもできます:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDB を使ったライブプロセスのダンプ

**最近の macOS バージョン** では、全ての物理メモリをイメージ化しようとする代わりに、通常は **特定のプロセス** のメモリをダンプする方が実用的です。

LLDB はライブターゲットから Mach-O コアファイルを保存できます:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
デフォルトでは通常これは**スキニーコア**を作成します。LLDBにマップされたすべてのプロセスメモリを含めるよう強制するには：
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
dumping の前の有用なフォローアップコマンド:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
次の目的で回復する場合、通常これで十分です：

- 復号済みの構成ブロブ
- メモリ内のトークン、クッキー、または認証情報
- 保存時のみ保護されている平文の秘密情報
- unpacking / JIT / runtime patching の後の復号済み Mach-O ページ

If the target is protected by the **hardened runtime**, or if `taskgated` denies the attach, you typically need one of these conditions:

- The target carries **`get-task-allow`**
- Your debugger is signed with the proper **debugger entitlement**
- You are **root** and the target is a non-hardened third-party process

For more background on obtaining a task port and what can be done with it:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## Frida または userland リーダーを使った選択的ダンプ

フルコアがノイズ過多な場合、**interesting readable ranges** のみをダンプする方が速いことが多いです。Frida はプロセスにアタッチできれば、**targeted extraction** に特に有用です。

Example approach:

1. 読み取り/書き込み可能な範囲を列挙する
2. モジュール、ヒープ、スタック、または匿名メモリでフィルタリングする
3. 候補となる文字列、キー、protobuf、plist/XML ブロブ、または復号済みコード/データを含む領域のみをダンプする

読み取り可能な全ての匿名領域をダンプするための最小限の Frida 例:
```javascript
Process.enumerateRanges({ protection: 'rw-', coalesce: true }).forEach(function (range) {
try {
if (range.file) return;
var dump = range.base.readByteArray(range.size);
var f = new File('/tmp/' + range.base + '.bin', 'wb');
f.write(dump);
f.close();
} catch (e) {}
});
```
これは巨大なコアファイルを避け、次だけを収集したい場合に有用です:

- アプリのヒープチャンク（秘密を含むもの）
- カスタムパッカーやローダーによって作成された匿名領域
- 保護を変更した後の JIT / アンパック済みコードページ

古いユーザーランドツール（例: [`readmem`](https://github.com/gdbinit/readmem)）も存在しますが、これらは主に直接 `task_for_pid`/`vm_read` スタイルのダンプの**ソース参照**として有用であり、現代の Apple Silicon ワークフローには十分にメンテされていません。

## 簡易トリアージのメモ

- `sysctl vm.swapusage` は、**スワップ使用量**およびスワップが**暗号化されているか**を素早く確認する方法として依然有効です。
- `sleepimage` は主に **hibernate/safe sleep** シナリオで関連しますが、現代のシステムでは通常保護されているため、信頼できる収集経路としてではなく、確認すべき **アーティファクトのソース** として扱うべきです。
- 最近の macOS リリースでは、ブートポリシー、SIP 状態、kext の読み込みを制御できない限り、**プロセスレベルのダンプ**の方が一般的に**フル物理メモリイメージ化**より現実的です。

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
