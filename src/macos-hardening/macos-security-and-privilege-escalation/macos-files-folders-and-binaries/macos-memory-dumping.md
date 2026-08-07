# macOS メモリダンプ

{{#include ../../../banners/hacktricks-training.md}}

## メモリアーティファクト

### Swap ファイル

`/private/var/vm/swapfile0` などの Swap ファイルは、**物理メモリが一杯になった際のキャッシュとして機能します**。物理メモリに空きがなくなると、そのデータは Swap ファイルに移され、必要に応じて物理メモリに戻されます。複数の Swap ファイルが存在する場合があり、swapfile0、swapfile1 などの名前が付けられます。

### Hibernate イメージ

`/private/var/vm/sleepimage` にあるファイルは、**Hibernate mode** の間に重要な役割を果たします。**OS X が hibernate すると、メモリ上のデータがこのファイルに保存されます**。コンピューターを復帰させると、システムはこのファイルからメモリデータを取得し、ユーザーが中断した時点から作業を続行できるようにします。

なお、最新の MacOS システムでは、セキュリティ上の理由から通常このファイルは暗号化されているため、復元は困難です。

- sleepimage の暗号化が有効になっているか確認するには、`sysctl vm.swapusage` コマンドを実行します。これにより、ファイルが暗号化されているかどうかが表示されます。

### メモリプレッシャーログ

MacOS システムにおける、メモリに関連するもう 1 つの重要なファイルは、**メモリプレッシャーログ**です。これらのログは `/var/log` に保存され、システムのメモリ使用量とメモリプレッシャーイベントに関する詳細情報が含まれています。メモリ関連の問題を診断したり、システムが時間の経過に伴ってメモリをどのように管理しているかを把握したりする際に、特に役立ちます。

## osxpmem によるメモリのダンプ

MacOS マシンのメモリをダンプするには、[**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) を使用できます。

**注**: 現在、これは主に **legacy workflow** です。`osxpmem` は kernel extension のロードに依存しており、[Rekall](https://github.com/google/rekall) プロジェクトはアーカイブされ、最新のリリースは **2017 年**のもので、公開されているバイナリは **Intel Mac** を対象としています。現在の macOS リリース、特に **Apple Silicon** では、kext ベースのフル RAM acquisition は、現代の kernel extension 制限、SIP、プラットフォーム署名要件によって通常ブロックされます。実際には、現代のシステムでは、RAM 全体のイメージではなく、より頻繁に**プロセス単位の dump**を行うことになります。
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
次のエラーが表示された場合: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` 以下を実行して修正できます:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**その他のエラー**は、「Security & Privacy --> General」で**kext のロードを許可**すると修正できる場合があります。**許可**してください。

次の **oneliner** を使用して、application をダウンロードし、kext をロードしてメモリを dump することもできます。
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDBによる実行中プロセスのダンプ

**recent macOS versions** では、物理メモリ全体のイメージを取得しようとするよりも、通常は**特定のプロセス**のメモリをダンプする方が実用的です。

LLDBは実行中のターゲットからMach-O core fileを保存できます:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
デフォルトでは、通常 **skinny core** が作成されます。LLDB にマッピングされたプロセスメモリをすべて含めるには:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
ダンプ前に役立つ follow-up commands:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
これは通常、以下の情報の復元が目的であれば十分です。

- 復号された設定 blob
- メモリ上の token、cookie、または credential
- at rest の状態でのみ保護されている平文の secret
- unpacking / JIT / runtime patching 後に復号された Mach-O ページ

対象が **hardened runtime** によって保護されている場合、または `taskgated` が attach を拒否する場合は、通常、以下のいずれかの条件が必要です。

- 対象に **`get-task-allow`** が付与されている
- debugger が適切な **debugger entitlement** 付きで署名されている
- **root** であり、対象が hardened ではないサードパーティ製プロセスである

task port の取得方法と、それを使って可能な操作の詳細については、以下を参照してください。

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### attach 前の簡易チェック

LLDB/Frida に時間をかける前に、対象が現実的に **ダンプ可能** かどうかを簡単に確認します。
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
実際の運用では、通常次のことを意味します。

- **`get-task-allow`** 付きで配布されたサードパーティ製アプリは、LLDB で直接 dump できることが多く、その dump から、アプリがすでにアクセスした TCC-protected data が露出する可能性があります。<sup>[[1]](#references)</sup>
- **hardened** な target は、**`root`** であっても、関連する debugger entitlements / policy path を制御していない限り、attach を拒否することが一般的です。
- unhardened なサードパーティ製プロセスは、依然として `lldb`、`vmmap`、Frida、またはカスタムの `task_for_pid`/`vm_read` reader を使用するのに最も適した場所です。

### dump可能な nested helpers を探す

notarized macOS apps に関する最近の research では、main GUI binary ではなく nested helpers 内に **`get-task-allow`** が見つかるケースが繰り返し報告されています。top-level app が hardened に見える場合でも、諦める前に、その **XPC services**、**login items**、**helper tools**、および bundled CLIs を列挙してください。
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
`get-task-allow` を持つネストされた executable は、メインアプリがより堅牢に hardening されている場合でも、`lldb` で attach したり、core を dump したり、カスタムの `task_for_pid` client で memory を取得したりするのに適した、最も簡単な場所であることがよくあります。

## Frida または userland readers による選択的な dump

完全な core が情報過多になる場合、**興味深い readable ranges のみ**を dump すると、処理が速くなることがよくあります。Frida は、process に attach できるようになった後の **targeted extraction** に特に役立ちます。

アプローチの例:

1. readable/writable ranges を列挙する
2. module、heap、stack、または anonymous memory で filter する
3. candidate strings、keys、protobufs、plist/XML blobs、または decrypted code/data を含む regions のみを dump する

すべての readable anonymous ranges を dump する最小限の Frida の例:
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
これは巨大な core ファイルを避け、以下のみを収集したい場合に有用です。

- secrets を含む App heap chunks
- custom packers または loaders によって作成された Anonymous regions
- protections の変更後の JIT / unpacked code pages

ターゲットが dump 中も **allocating / freeing** を続ける場合、不安定な範囲には `readByteArray()` よりも Frida の **`readVolatile()`** primitive を優先してください。処理は遅くなりますが、読み取りの途中で page が unreadable になっても、ターゲットを停止させずに済みます。より大規模な acquisition では、`send(..., data)` を使って chunks を返し、ターゲット内に数千個の小さなファイルを作成する代わりに controller 側で compress するほうが、よりクリーンな場合もあります。

[`readmem`](https://github.com/gdbinit/readmem) などの古い userland tools も存在しますが、主に直接的な `task_for_pid`/`vm_read` style dumping の **source references** として有用であり、modern Apple Silicon workflows 向けには十分に保守されていません。

## `.memgraph` による Heap / VM snapshots

主に **heap objects**、**allocation provenance**、または別の machine に移動できる snapshot を重視する場合、`.memgraph` は巨大な Mach-O core より実用的なことがよくあります。`leaks` tooling を使用すると、live process から生成できます。<sup>[[2]](#references)</sup>
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
その後、標準の Apple ツールを使ってオフラインでトリアージします：
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` は `-fullContent` capture を保持しておく主な理由です。これは、memory contents を説明する labels が最小限の `.memgraph` では省略されるためです。

これは、次のような場合に特に便利です。

- full core ではなく、**より小さく共有可能な snapshot** が必要な場合
- `MallocStackLogging` が有効で、**allocation backtraces** が必要な場合
- すでに **興味深い heap address** が分かっており、`malloc_history` で pivot したい場合
- full dump によるノイズを許容する価値があるか判断する前に、簡単な **VM/heap breakdown** が必要な場合

### Differential memgraph triage

target の起動方法を制御できる場合は、launch 前に **historical allocation logging** を有効にして、後続の snapshots で有用な alloc/free backtraces が保持されるようにします。
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
その後、興味深いアクションの前後でスナップショットを取得し、オフラインで差分を確認します。
```bash
# Baseline before login / decrypt / unpack
leaks <pid> -outputGraph /tmp/pre.memgraph -fullContent -fullStackHistory

# Snapshot after the sensitive action
leaks <pid> -outputGraph /tmp/post.memgraph -fullContent -fullStackHistory

# Show only new leaks introduced after the baseline
leaks /tmp/post.memgraph -diffFrom=/tmp/pre.memgraph

# Walk from roots to one candidate allocation, or filter the whole tree by class / VM type
leaks /tmp/post.memgraph -traceTree 0xADDR
leaks /tmp/post.memgraph -referenceTree='CFData[50k+]'

# Pivot into the preserved stack history at the interesting high-water mark
malloc_history /tmp/post.memgraph -callTree -highWaterMark
```
これは、復号、unpacking、または secret-retrieval の段階後にのみ現れる **post-authentication objects**、**large `CFData` buffers**、または **anonymous VM regions** を分離する実用的な方法です。

## Swift-heavy targets: `swift-inspect`

高価値なデータを **Swift runtime objects** 内に保持するアプリケーションでは、`swift-inspect` は LLDB や Frida を補完する有効な手段になります。最初にすべてを dump するのではなく、実行中のプロセスから特定の Swift runtime structures をクエリできます。
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
これは、以下の特定に役立ちます。

- 興味深いデータをバッファリングしている大きな Swift 配列
- runtime でロードされた型を明らかにする Metadata allocations
- より対象を絞った dump を行う前の Swift concurrency の状態（`Task`、actor、thread の関係）

すでに process を inspect できる状態で、より object-level の runtime triage を行う場合は、[memory 内の objects に関する専用ページ](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)を確認してください。

## Quick triage notes

- `sysctl vm.swapusage` は、**swap usage** と swap が **encrypted** されているかを確認する簡単な方法として、現在も利用できます。
- `sleepimage` は主に **hibernate/safe sleep** のシナリオで依然として関連しますが、modern systems では一般的に保護されているため、信頼できる acquisition path ではなく、**確認すべき artifact source** として扱う必要があります。
- recent macOS releases では、**full physical memory imaging** よりも **process-level dumping** の方が一般的に現実的です。ただし、boot policy、SIP state、kext loading を制御できる場合は除きます。

## References

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
