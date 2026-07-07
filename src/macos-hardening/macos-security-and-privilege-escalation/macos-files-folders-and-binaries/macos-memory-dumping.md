# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Swap files, 例えば `/private/var/vm/swapfile0` は、**物理メモリがいっぱいになったときのキャッシュ**として機能します。物理メモリに空きがなくなると、そのデータは swap file に移され、必要に応じて再び物理メモリに戻されます。swapfile0、swapfile1 などの名前で、複数の swap file が存在することがあります。

### Hibernate Image

`/private/var/vm/sleepimage` にあるファイルは、**ハイバネーションモード**中に重要です。**OS X が hibernates すると、メモリ内のデータがこのファイルに保存されます**。コンピュータが復帰すると、システムはこのファイルからメモリデータを取得し、ユーザーは中断したところから作業を続けられます。

現代の MacOS システムでは、セキュリティ上の理由からこのファイルは通常暗号化されており、復旧は困難です。

- sleepimage の暗号化が有効か確認するには、`sysctl vm.swapusage` を実行できます。これにより、そのファイルが暗号化されているかどうかが表示されます。

### Memory Pressure Logs

MacOS システムで別の重要なメモリ関連ファイルは、**memory pressure log** です。これらのログは `/var/log` にあり、システムのメモリ使用状況や pressure event に関する詳細情報を含んでいます。メモリ関連の問題を診断したり、システムが時間の経過とともにメモリをどのように管理しているかを理解するのに特に役立ちます。

## Dumping memory with osxpmem

MacOS マシンでメモリを dump するには、[**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) を使えます。

**Note**: これは今では主に **legacy workflow** です。`osxpmem` は kernel extension の読み込みに依存しており、[Rekall](https://github.com/google/rekall) プロジェクトは archived です。最新リリースは **2017** 年で、公開されている binary は **Intel Macs** 向けです。現在の macOS リリース、特に **Apple Silicon** では、kext ベースの full-RAM acquisition は、最新の kernel-extension 制限、SIP、platform-signing 要件によって通常ブロックされます。実際には、現代のシステムでは whole-RAM image ではなく、**process-scoped dump** を行うことが多くなります。
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
`osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` というエラーが出た場合は、次の方法で修正できます:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Other errors** は、"Security & Privacy --> General" で **kext の読み込みを許可** することで修正できる場合があります。単に **allow** してください。

また、この **oneliner** を使ってアプリケーションをダウンロードし、kext を読み込み、メモリをダンプすることもできます:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDB を使ったライブプロセスダンピング

**最近の macOS バージョン**では、通常、すべての物理メモリをイメージ化しようとするよりも、**特定のプロセス**のメモリをダンプする方が実用的です。

LLDB は、ライブターゲットから Mach-O core file を保存できます:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
デフォルトでは、通常これは **skinny core** を作成します。LLDB にマッピング済みのプロセスメモリをすべて含めさせるには:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
ダンプする前に使える便利なフォローアップコマンド:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
これは通常、以下を復元するのに十分です:

- 復号済みの configuration blobs
- in-memory の tokens, cookies, または credentials
- at rest でのみ保護されている plaintext secrets
- unpacking / JIT / runtime patching 後の復号済み Mach-O pages

target が **hardened runtime** で保護されている場合、または `taskgated` が attach を拒否する場合は、通常、次のいずれかの条件が必要です:

- target が **`get-task-allow`** を持っている
- あなたの debugger が適切な **debugger entitlement** で署名されている
- あなたが **root** で、target が non-hardened の third-party process である

task port の取得方法と、それで何ができるかについての背景は、こちらを参照してください:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

LLDB/Frida に時間を費やす前に、target が現実的に **dumpable** かどうかをすばやく確認します:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
運用上、これは通常次の意味になります:

- **`get-task-allow`** を付けて出荷されたサードパーティアプリは、LLDB で直接ダンプできることが多く、その結果のダンプには、アプリがすでにアクセスした TCC 保護データが含まれる場合があります。
- **hardened** な対象で `get-task-allow` がない場合、関連するデバッガの entitlements / policy パスを制御していない限り、通常は `root` でも attach を拒否します。
- unhardened なサードパーティプロセスは、`lldb`、`vmmap`、Frida、または独自の `task_for_pid`/`vm_read` リーダーを使うのに、今でも最も簡単な対象です。

## Frida または userland readers を使った選択的ダンプ

フル core がノイズ過多な場合、**興味のある readable ranges** だけをダンプする方が、しばしば高速です。Frida は、プロセスに attach できるようになった後の **targeted extraction** に特に有用です。

例:

1. readable/writable ranges を列挙する
2. module、heap、stack、または anonymous memory でフィルタする
3. 候補の文字列、keys、protobufs、plist/XML blobs、または復号済みの code/data を含む領域だけをダンプする

すべての readable anonymous ranges をダンプする最小限の Frida 例:
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
これは、巨大な core file を避けて、次だけを収集したいときに有用です:

- secrets を含む App heap chunks
- custom packers や loaders によって作成された anonymous regions
- protection を変更した後の JIT / unpacked code pages

[`readmem`](https://github.com/gdbinit/readmem) のような古い userland tools も存在しますが、主に direct `task_for_pid`/`vm_read` 形式の dumping の **source references** として有用であり、現代の Apple Silicon workflows 向けにはあまりメンテナンスされていません。

## Heap / VM snapshots with `.memgraph`

主に **heap objects**、**allocation provenance**、または別のマシンへ移動できる snapshot を重視するなら、`.memgraph` は巨大な Mach-O core よりもしばしば実用的です。`leaks` tooling は live process からこれを生成できます:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
その後、標準のAppleツールでオフラインでトリアージします:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` は、`-fullContent` capture を保持しておく主な理由です。なぜなら、メモリ内容を説明するラベルは、最小限の `.memgraph` からは省かれるからです。

これは特に次のような場合に有用です:

- フル core ではなく、**より小さく共有しやすい snapshot** が欲しいとき
- `MallocStackLogging` が有効で、**allocation backtraces** が欲しいとき
- すでに **興味深い heap address** を把握していて、`malloc_history` で pivot したいとき
- フル dump がそのノイズに見合うか判断する前に、素早く **VM/heap breakdown** を確認したいとき

## Swift-heavy targets: `swift-inspect`

**Swift runtime objects** の中に高価値データを保持しているアプリケーションでは、`swift-inspect` は LLDB や Frida のよい補完になります。まず全部を dump する代わりに、live process から特定の Swift runtime structures を query できます:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
これは、以下を特定するのに便利です:

- 大きな Swift arrays が興味深いデータをバッファリングしている
- runtime で読み込まれた type を明らかにする metadata allocations
- より対象を絞った dump を行う前の Swift concurrency state (`Task`, actor, thread relationships)

プロセスをすでに inspect できる場合の、object-level の runtime triage については、[メモリ内の objects に関する専用ページ](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)を確認してください。

## Quick triage notes

- `sysctl vm.swapusage` は、**swap usage** と swap が **encrypted** かどうかを確認するための、今でも手早い方法です。
- `sleepimage` は主に **hibernate/safe sleep** のシナリオで依然として関連性がありますが、現代のシステムでは通常これが保護されるため、信頼できる acquisition path ではなく、**確認すべき artifact source** として扱うべきです。
- 最近の macOS リリースでは、**process-level dumping** は、boot policy、SIP state、kext loading を制御していない限り、一般に **full physical memory imaging** より現実的です。

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
