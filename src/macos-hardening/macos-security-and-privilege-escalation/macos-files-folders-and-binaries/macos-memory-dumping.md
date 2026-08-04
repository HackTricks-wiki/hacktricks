# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## メモリのアーティファクト

### Swap Files

`/private/var/vm/swapfile0` などの Swap files は、**物理メモリが一杯になったときのキャッシュとして機能します**。物理メモリに空きがなくなると、そのデータは swap file に転送され、必要に応じて物理メモリに戻されます。swap file は複数存在する場合があり、swapfile0、swapfile1 などの名前が付けられます。

### Hibernate Image

`/private/var/vm/sleepimage` にあるファイルは、**hibernation mode** 中に重要な役割を果たします。**OS X が hibernate すると、メモリのデータがこのファイルに保存されます**。コンピューターを起動すると、システムはこのファイルからメモリデータを取得し、ユーザーが中断したところから再開できるようにします。

なお、最新の MacOS システムでは、セキュリティ上の理由からこのファイルは通常暗号化されているため、復元は困難です。

- sleepimage の暗号化が有効かどうかを確認するには、`sysctl vm.swapusage` コマンドを実行します。これにより、ファイルが暗号化されているかどうかが表示されます。

### Memory Pressure Logs

MacOS システムにおける、メモリに関連するもう1つの重要なファイルは、**memory pressure log** です。これらのログは `/var/log` にあり、システムのメモリ使用量とメモリプレッシャーイベントに関する詳細な情報が含まれています。メモリ関連の問題を診断したり、システムが時間の経過とともにメモリをどのように管理しているかを把握したりする際に、特に役立ちます。

## osxpmem によるメモリのダンプ

MacOS マシンのメモリをダンプするには、[**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) を使用できます。

**注**: 現在では、これは主に **legacy workflow** です。`osxpmem` は kernel extension のロードに依存しており、[Rekall](https://github.com/google/rekall) プロジェクトはアーカイブされ、最新リリースは **2017** 年のものです。また、公開されている binary は **Intel Mac** を対象としています。現在の macOS リリース、特に **Apple Silicon** では、kext ベースの full-RAM acquisition は、最新の kernel-extension restrictions、SIP、platform-signing requirements によって通常ブロックされます。実際には、最新のシステムでは whole-RAM image ではなく、**process-scoped dump** を実行することのほうが多くなります。
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
このエラーが表示された場合: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` 以下の手順で修正できます:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**その他のエラー**は、「Security & Privacy --> General」で **kext のロードを許可**することで解決できる場合があります。単に **許可**してください。

次の **oneliner** を使用して、アプリケーションをダウンロードし、kext をロードしてメモリをダンプすることもできます。
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDBによる実行中プロセスのダンプ

**最近のmacOSバージョン**では、物理メモリ全体のイメージを取得しようとするよりも、通常は**特定のプロセス**のメモリをダンプする方が実用的です。

LLDBは、実行中のターゲットからMach-O core fileを保存できます:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
デフォルトでは、通常 **skinny core** が作成されます。LLDB にプロセスのマッピング済みメモリをすべて含めさせるには:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
ダンプ前に役立つフォローアップコマンド:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
これは通常、以下の情報を復元することが目的であれば十分です。

- Decrypted configuration blobs
- メモリ上の tokens、cookies、または credentials
- 保存時にのみ保護されている plaintext secrets
- unpacking / JIT / runtime patching 後の Decrypted Mach-O pages

対象が **hardened runtime** によって保護されている場合、または `taskgated` が attach を拒否する場合、通常は以下のいずれかの条件が必要です。

- 対象が **`get-task-allow`** を保持している
- debugger が適切な **debugger entitlement** で署名されている
- **root** であり、対象が hardened ではないサードパーティ製 process である

task port の取得方法と、それを使って可能な操作の詳細については、以下を参照してください。

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### attach 前の簡易チェック

LLDB/Frida に時間をかける前に、対象が現実的に **dumpable** かどうかをすばやく確認します。
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
実運用上、通常は次のことを意味します。

- **`get-task-allow`** 付きで配布されたサードパーティ製アプリは、LLDB で直接ダンプできることが多く、そのダンプからアプリがすでにアクセスした TCC 保護データが漏洩する可能性があります。
- **hardened** 対象は、関連する debugger entitlements / policy path を制御していない限り、`root` であっても attach を拒否するのが一般的です。
- Unhardened なサードパーティ製プロセスは、`lldb`、`vmmap`、Frida、またはカスタムの `task_for_pid`/`vm_read` reader を使用するのに、依然として最も容易な対象です。

### dump 可能な nested helpers を探す

notarized macOS アプリに関する最近の research では、メイン GUI バイナリではなく、nested helpers 内に **`get-task-allow`** が見つかるケースが相次いでいます。トップレベルのアプリが hardened に見える場合でも、諦める前にその **XPC services**、**login items**、**helper tools**、および bundled CLIs を列挙してください。
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
`get-task-allow`を持つネストされた実行ファイルは、メインアプリのhardeningがより強固な場合でも、`lldb`でattachしたり、coreをdumpしたり、カスタムの`task_for_pid` clientでmemoryを取得したりするのに最適な場所となることがよくあります。

## Fridaまたはuserland readersによる選択的なdump

full coreがノイズの多すぎる場合、**興味深いreadable rangesのみ**をdumpする方が高速なことがよくあります。Fridaは、processにattachできるようになった後の**targeted extraction**に特に有用です。

アプローチの例:

1. readable/writable rangesを列挙する
2. module、heap、stack、またはanonymous memoryでfilterする
3. candidate strings、keys、protobufs、plist/XML blobs、またはdecrypted code/dataを含むregionsのみをdumpする

すべてのreadable anonymous rangesをdumpする最小限のFrida例:
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
- custom packer または loader によって作成された Anonymous regions
- protections の変更後の JIT / unpacked code pages

対象が dump 中も **allocating / freeing** を続ける場合、不安定な範囲には `readByteArray()` よりも Frida の **`readVolatile()`** primitive を優先してください。速度は遅くなりますが、読み取りの途中で page が unreadable になっても対象を kill せずに済みます。より大規模な acquisition では、`send(..., data)` を使って chunks をストリームで返し、対象内に数千個の小さなファイルを作成する代わりに controller 側で compress するほうが、より整理された方法になる場合もあります。

[`readmem`](https://github.com/gdbinit/readmem) などの古い userland tools も存在しますが、主に `task_for_pid`/`vm_read` スタイルの直接的な dumping の **source references** として有用であり、modern Apple Silicon workflows 向けには十分に保守されていません。

## `.memgraph` による Heap / VM snapshots

主に **heap objects**、**allocation provenance**、または別のマシンへ移動できる snapshot を重視する場合、`.memgraph` は巨大な Mach-O core よりも実用的なことがよくあります。`leaks` tooling は、実行中の process から `.memgraph` を生成できます。
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
その後、Apple標準のツールを使ってオフラインでトリアージします：
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` は、`-fullContent` capture を保持しておく主な理由です。最小構成の `.memgraph` では、メモリ内容を説明するラベルが省略されるためです。

これは、次のような場合に特に役立ちます。

- full core ではなく、**より小さく共有しやすい snapshot** が必要な場合
- `MallocStackLogging` が有効で、**allocation backtrace** が必要な場合
- すでに **興味深い heap address** がわかっており、`malloc_history` で調査を進めたい場合
- full dump がノイズに見合うか判断する前に、簡単な **VM/heap breakdown** が必要な場合

### Differential memgraph triage

target の起動方法を制御できる場合は、launch 前に **historical allocation logging** を有効にしてください。これにより、後の snapshot に有用な alloc/free backtrace が保持されます。
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
次に、興味深いアクションの前後でスナップショットを取得し、オフラインで差分を比較します：
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
これは、**post-authentication objects**、大容量の `CFData` バッファ、または復号、unpacking、secret-retrieval の段階後にのみ出現する **anonymous VM regions** を分離する実用的な方法です。

## Swift を多用する target: `swift-inspect`

高価値なデータを **Swift runtime objects** 内に保持するアプリケーションでは、`swift-inspect` は LLDB や Frida を補完する有効なツールです。最初にすべてを dump するのではなく、実行中の process から特定の Swift runtime structures をクエリできます。
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
これは、次の特定に役立ちます。

- 興味深いデータをバッファリングしている大きな Swift 配列
- runtime でロードされた型を明らかにする metadata allocations
- より対象を絞った dump を行う前の、Swift concurrency の状態（`Task`、actor、thread の関係）

プロセスをすでに inspect できる状態で、object-level の runtime triage をさらに行う場合は、[memory 内の objects に関する専用ページ](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)を確認してください。

## Quick triage notes

- `sysctl vm.swapusage` は、**swap usage** と swap が **encrypted** かどうかを確認する簡単な方法です。
- `sleepimage` は主に **hibernate/safe sleep** のシナリオで引き続き関連しますが、modern systems では一般的に保護されているため、信頼できる acquisition path ではなく、**確認すべき artifact source** として扱う必要があります。
- recent macOS releases では、boot policy、SIP state、kext loading を制御できない限り、一般的に **full physical memory imaging** よりも **process-level dumping** の方が現実的です。

## References

- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [https://keith.github.io/xcode-man-pages/leaks.1.html](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
