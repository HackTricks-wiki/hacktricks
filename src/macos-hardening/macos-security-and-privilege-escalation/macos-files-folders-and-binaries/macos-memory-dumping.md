# macOSメモリダンプ

{{#include ../../../banners/hacktricks-training.md}}

## メモリアーティファクト

### スワップファイル

`/private/var/vm/swapfile0` などのスワップファイルは、**物理メモリがいっぱいになったときのキャッシュとして機能します**。物理メモリに空きがなくなると、そのデータはスワップファイルに移され、必要に応じて物理メモリに戻されます。複数のスワップファイルが存在する場合があり、swapfile0、swapfile1 などの名前が付けられます。

### Hibernateイメージ

`/private/var/vm/sleepimage` にあるファイルは、**ハイバネーションモード**中に重要な役割を果たします。**OS Xがハイバネーションすると、メモリ内のデータがこのファイルに保存されます**。コンピューターのスリープから復帰すると、システムはこのファイルからメモリデータを取得し、ユーザーが中断したところから作業を続けられるようにします。

なお、最近のMacOSシステムでは、セキュリティ上の理由からこのファイルは通常暗号化されているため、復元は困難です。

- sleepimageの暗号化が有効かどうかを確認するには、`sysctl vm.swapusage` コマンドを実行します。これにより、ファイルが暗号化されているかどうかが表示されます。

### メモリプレッシャーログ

MacOSシステムにおける、メモリ関連のもう1つの重要なファイルは、**メモリプレッシャーログ**です。これらのログは `/var/log` に保存され、システムのメモリ使用量とプレッシャーイベントに関する詳細な情報が含まれています。メモリ関連の問題を診断したり、システムが時間の経過とともにメモリをどのように管理しているかを把握したりする際に、特に役立ちます。

## osxpmemでメモリをダンプする

MacOSマシンのメモリをダンプするには、[**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) を使用できます。

**注**: 現在では、これは主に**legacyなworkflow**です。`osxpmem` はkernel extensionのロードに依存しており、[Rekall](https://github.com/google/rekall) projectはarchivedになっています。latest releaseは**2017年**で、公開されているbinaryは**Intel Mac**を対象としています。current macOS releases、特に**Apple Silicon**では、kextベースのfull-RAM acquisitionは、現代のkernel-extension restrictions、SIP、platform-signing requirementsによって通常ブロックされます。実際には、modern systemsではwhole-RAM imageではなく、**process-scoped dump**を行うことのほうが多くなります。
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
次のエラーが表示された場合:

`osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)`

以下を実行して修正できます:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Other errors** は、"Security & Privacy --> General" で **kext の読み込みを許可** することで修正できる場合があります。**allow** をクリックしてください。

次の **oneliner** を使用して、アプリケーションをダウンロードし、kext を読み込み、メモリを dump することもできます。
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDBによる実行中プロセスのダンプ

**recent macOS versions**では、物理メモリ全体のイメージングを試みるよりも、通常は**特定のプロセス**のメモリをダンプする方法が最も実用的です。

LLDBは、実行中のtargetからMach-O core fileを保存できます：
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
デフォルトでは、通常 **skinny core** が作成されます。LLDB にプロセスのマッピング済みメモリをすべて含めるには：
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
ダンプ前に役立つ追加コマンド:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
これは通常、以下の情報を復元することが目的であれば十分です。

- 復号済みの設定 blob
- メモリ上の token、cookie、または credential
- 保存時にのみ保護されている plaintext の secret
- unpacking / JIT / runtime patching 後に復号された Mach-O page

対象が **hardened runtime** によって保護されている場合、または `taskgated` が attach を拒否する場合は、通常、以下のいずれかの条件が必要です。

- 対象に **`get-task-allow`** が付与されている
- debugger が適切な **debugger entitlement** で署名されている
- 自分が **root** で、対象が hardened ではないサードパーティ製 process である

task port の取得方法と、それを使って実行できる操作の詳細については、以下を参照してください。

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### attach 前の簡易チェック

LLDB/Frida に時間をかける前に、対象が現実的に **dump 可能** かどうかを簡単に確認します。
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
実際の運用では、通常、次のことを意味します。

- **`get-task-allow`** とともに出荷された third-party app は、LLDB で直接 dump できることが多く、生成された dump から、その app がすでにアクセスしていた TCC-protected data が露出する可能性があります。<sup>[[1]](#references)</sup>
- **hardened** target で **`get-task-allow`** がない場合、関連する debugger entitlements / policy path を制御していない限り、`root` であっても attach を拒否されるのが一般的です。
- Unhardened third-party processes は、依然として `lldb`、`vmmap`、Frida、またはカスタムの `task_for_pid`/`vm_read` readers を使用する最も簡単な場所です。

### dump 可能な nested helpers を探す

notarized macOS apps に関する最近の research では、main GUI binary ではなく、nested helpers 内で **`get-task-allow`** が見つかるケースが相次いでいます。top-level app が hardened に見える場合でも、諦める前に、その **XPC services**、**login items**、**helper tools**、および bundled CLIs を列挙してください。
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
`get-task-allow` を持つ nested executable は、メインアプリの防御がより強固な場合でも、`lldb` で attach したり、core を dump したり、カスタムの `task_for_pid` client で memory を取得したりする最も簡単な対象になることがよくあります。

## Frida または userland readers を使った選択的な dump

full core がノイズの多すぎる場合、**interesting readable ranges** だけを dump する方が速いことがよくあります。Frida は、プロセスに attach できる場合に **targeted extraction** に適しているため、特に便利です。

アプローチの例:

1. readable/writable ranges を列挙する
2. module、heap、stack、または anonymous memory で filter する
3. candidate strings、keys、protobufs、plist/XML blobs、または decrypted code/data を含む regions だけを dump する

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
これは巨大な core ファイルを避け、以下のみを収集したい場合に便利です。

- secrets を含む App heap chunks
- custom packers または loaders によって作成された Anonymous regions
- protections の変更後に存在する JIT / unpacked code pages

対象が dump 中も **allocating / freeing** を続ける場合、不安定な範囲には `readByteArray()` よりも Frida の **`readVolatile()`** primitive を優先してください。速度は遅くなりますが、読み取りの途中で page が unreadable になった場合でも、target が kill されるのを防げます。より大規模な acquisition では、`send(..., data)` を使用して chunks を返し、target 内に数千個の小さなファイルを作成する代わりに controller 側で compress するほうが、よりクリーンな場合もあります。

[`readmem`](https://github.com/gdbinit/readmem) のような古い userland tools も存在しますが、これらは主に、直接的な `task_for_pid`/`vm_read` 形式の dumping における **source references** として役立つものであり、modern Apple Silicon workflows 向けには十分に保守されていません。

## `.memgraph` による Heap / VM snapshots

主に **heap objects**、**allocation provenance**、または別の machine に移動できる snapshot を重視する場合、`.memgraph` は巨大な Mach-O core より実用的なことが多くあります。`leaks` tooling を使用すると、live process から生成できます。
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
次に、標準のApple toolingを使ってオフラインでtriageします：
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` は `-fullContent` capture を保持しておく主な理由です。これは、memory contents を説明する labels が最小構成の `.memgraph` では省略されるためです。

これは特に次のような場合に役立ちます。

- full core の代わりに、**より小さく共有可能な snapshot** が必要な場合
- `MallocStackLogging` が有効で、**allocation backtraces** が必要な場合
- すでに **興味深い heap address** が分かっており、`malloc_history` で pivot したい場合
- full dump によるノイズを許容する価値があるか判断する前に、簡単な **VM/heap breakdown** が必要な場合

### Differential memgraph triage

target の起動方法を制御できる場合は、launch 前に **historical allocation logging** を有効にしてください。これにより、後の snapshots に有用な alloc/free backtraces が保持されます。
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
その後、注目すべきアクションの前後でスナップショットを取得し、オフラインで差分を比較します。
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
これは、復号、unpacking、または secret-retrieval stage の後にのみ現れる **post-authentication objects**、**large `CFData` buffers**、または **anonymous VM regions** を分離する実用的な方法です。

## Swift-heavy targets: `swift-inspect`

**Swift runtime objects** 内に価値の高いデータを保持するアプリケーションでは、`swift-inspect` は LLDB や Frida を補完する有効な手段になります。最初にすべてを dump するのではなく、実行中のプロセスから特定の Swift runtime structures を照会できます。
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
これは以下の識別に役立ちます。

- 興味深いデータをバッファリングしている大きな Swift 配列
- 実行時にロードされた型を明らかにする Metadata の割り当て
- より対象を絞った dump を実行する前の Swift concurrency の状態（`Task`、actor、thread の関係）

すでに process を inspect できる状態で、より object-level の runtime triage を行う場合は、[メモリ内の objects に関する専用ページ](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)を確認してください。

## Quick triage notes

- `sysctl vm.swapusage` は、**swap usage** と swap が**暗号化**されているかを確認する簡単な方法として、現在も有効です。
- `sleepimage` は主に **hibernate/safe sleep** のシナリオで引き続き関連しますが、現代のシステムでは一般的に保護されているため、信頼できる acquisition path ではなく、**確認すべき artifact source** として扱う必要があります。
- 最近の macOS リリースでは、boot policy、SIP の状態、kext のロードを制御できない限り、**full physical memory imaging** よりも **process-level dumping** の方が一般的に現実的です。

## References

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
