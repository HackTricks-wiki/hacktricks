# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

`/private/var/vm/swapfile0` などのSwap filesは、**物理メモリが一杯になったときのcache**として機能します。物理メモリに空きがなくなると、そのデータはswap fileに転送され、必要に応じて物理メモリへ戻されます。swapfile0、swapfile1などの名前を持つ複数のswap filesが存在する場合があります。

### Hibernate Image

`/private/var/vm/sleepimage`にあるファイルは、**hibernation mode**で重要な役割を果たします。**OS Xがhibernateすると、メモリのデータがこのファイルに保存されます**。コンピューターのwake時に、システムはこのファイルからメモリデータを取得し、ユーザーが中断したところから作業を続けられるようにします。

なお、modern MacOS systemsでは、security上の理由からこのファイルは通常encryptedされているため、recoveryは困難です。

- sleepimageのencryptionが有効か確認するには、`sysctl vm.swapusage`コマンドを実行します。これにより、ファイルがencryptedされているかどうかを確認できます。

### Memory Pressure Logs

MacOS systemsにおけるもう1つの重要なmemory-related fileは、**memory pressure log**です。これらのlogsは`/var/log`にあり、systemのmemory usageとpressure eventsに関する詳細情報が含まれています。memory-related issuesのdiagnosisや、systemが時間の経過とともにmemoryをどのように管理しているかを理解する際に特に役立ちます。

## osxpmemによるmemoryのdump

MacOS machineのmemoryをdumpするには、[**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip)を使用できます。

**Note**: 現在では、これは主に**legacy workflow**です。`osxpmem`はkernel extensionのloadingに依存しており、[Rekall](https://github.com/google/rekall) projectはarchivedされ、latest releaseは**2017**年のものです。また、公開されているbinaryは**Intel Macs**を対象としています。current macOS releases、特に**Apple Silicon**では、kext-based full-RAM acquisitionはmodern kernel-extension restrictions、SIP、platform-signing requirementsによって通常blockedされます。実際には、modern systemsではwhole-RAM imageではなく、**process-scoped dump**を行うことのほうが多くなります。
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
次のエラーが表示された場合: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)`、以下を実行して修正できます:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Other errors** は、"Security & Privacy --> General" で **kext の load を許可**することで修正できる場合があります。単に **allow** してください。

次の **oneliner** を使用して、application を download し、kext を load して memory を dump することもできます。
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDBを使用した実行中プロセスのダンプ

**recent macOS versions** では、物理メモリ全体のイメージ取得を試みるよりも、通常は**特定のプロセス**のメモリをダンプする方が実用的です。

LLDBは、実行中のターゲットからMach-O core fileを保存できます。
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
デフォルトでは、通常 **skinny core** が作成されます。LLDB にマップされたプロセスメモリをすべて含めさせるには:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
ダンプを実行する前に役立つ追加コマンド:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
これは通常、以下の情報を復元することが目的であれば十分です。

- 復号された設定 blob
- メモリ上の token、cookie、または credential
- at rest の状態でのみ保護されている plaintext の secret
- unpacking / JIT / runtime patching 後に復号された Mach-O のページ

対象が **hardened runtime** によって保護されている場合、または `taskgated` が attach を拒否する場合は、通常、以下のいずれかの条件が必要です。

- 対象が **`get-task-allow`** を保持している
- debugger が適切な **debugger entitlement** 付きで署名されている
- **root** であり、対象が hardened ではないサードパーティ製プロセスである

task port の取得方法と、それを使って実行できることの詳細については、以下を参照してください。

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
実運用上、これは通常、次を意味します。

- **`get-task-allow`** とともに出荷された third-party app は、LLDB で直接ダンプできることが多く、その結果得られるダンプには、アプリがすでにアクセスした TCC-protected data が露出する可能性があります。<sup>[1]</sup>
- **hardened** target は、関連する debugger entitlements / policy path を制御していない限り、`root` であっても attach を拒否することが一般的です。
- Unhardened third-party processes は、依然として `lldb`、`vmmap`、Frida、またはカスタムの `task_for_pid`/`vm_read` readers を使用するのに最も簡単な対象です。

### ダンプ可能な nested helpers を探す

notarized macOS apps に関する最近の research では、main GUI binary ではなく nested helpers 内に **`get-task-allow`** が見つかるケースが繰り返し報告されています。top-level app が hardened に見える場合でも、諦める前にその **XPC services**、**login items**、**helper tools**、および bundled CLIs を列挙してください。
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
`get-task-allow` を持つネストされた executable は、メインアプリがより強固に hardening されている場合でも、`lldb` で attach したり、core を dump したり、カスタムの `task_for_pid` client で memory を取得したりするのに最適な場所であることがよくあります。

## Frida または userland readers による選択的な dump

完全な core がノイズの多すぎるものになる場合、**興味深い readable ranges** のみを dump すると、より高速になることがよくあります。Frida は、プロセスに attach できるようになった後の **targeted extraction** に特に役立ちます。

アプローチの例:

1. readable/writable ranges を列挙する
2. module、heap、stack、または anonymous memory でフィルタリングする
3. candidate strings、keys、protobufs、plist/XML blobs、または decrypted code/data を含む region のみを dump する

すべての readable anonymous ranges を dump する最小限の Frida 例:
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
- protections を変更した後の JIT / unpacked code pages

target が dump 中も **allocating / freeing** を続ける場合、不安定な範囲には `readByteArray()` よりも Frida の **`readVolatile()`** primitive を優先してください。速度は遅くなりますが、読み取り途中で page が unreadable になっても target が終了するのを防げます。より大規模な acquisition では、target 内に何千もの小さなファイルを作成する代わりに、`send(..., data)` で chunks を stream して controller 側で compress するほうが、よりクリーンな場合もあります。

[`readmem`](https://github.com/gdbinit/readmem) などの古い userland tools も存在しますが、主に直接的な `task_for_pid`/`vm_read` style dumping の **source references** として有用であり、modern Apple Silicon workflows 向けには十分に保守されていません。

## `.memgraph` による Heap / VM snapshots

主に **heap objects**、**allocation provenance**、または別の machine に移動できる snapshot を重視する場合、`.memgraph` は巨大な Mach-O core より実用的なことが多くあります。`leaks` tooling を使用すると、live process から生成できます。
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
その後、Apple標準ツールを使用してオフラインでトリアージします：
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` は、`-fullContent` capture を保持しておく主な理由です。最小構成の `.memgraph` では、memory contents を説明するラベルが省略されるためです。

これは、特に次のような場合に便利です。

- full core ではなく、**より小さく共有しやすい snapshot** が必要な場合
- `MallocStackLogging` が有効で、**allocation backtraces** が必要な場合
- すでに **興味深い heap address** が判明しており、`malloc_history` で pivot したい場合
- full dump によるノイズに見合う価値があるか判断する前に、簡単な **VM/heap breakdown** が必要な場合

### Differential memgraph triage

target の起動方法を制御できる場合は、launch 前に **historical allocation logging** を有効にしてください。これにより、後続の snapshot に有用な alloc/free backtraces が保持されます。
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
その後、注目すべき操作の前後でスナップショットを取得し、オフラインで差分を比較します：
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
これは、復号、unpacking、または secret-retrieval の段階後にのみ現れる **post-authentication objects**、**large `CFData` buffers**、または **anonymous VM regions** を分離するための実用的な方法です。

## Swift-heavy targets: `swift-inspect`

価値の高いデータを **Swift runtime objects** 内に保持するアプリケーションでは、`swift-inspect` は LLDB や Frida を補完する有用なツールです。最初にすべてを dump するのではなく、実行中のプロセスから特定の Swift runtime structures をクエリできます:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
これは以下の識別に便利です。

- 興味深いデータをバッファリングしている大きな Swift 配列
- 実行時にロードされた型を明らかにする Metadata の割り当て
- より対象を絞った dump を行う前の Swift concurrency の状態（`Task`、actor、thread の関係）

すでに process を inspect できる場合に、object-level の runtime triage をさらに行うには、[メモリ内の objects に関する専用ページ](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)を確認してください。

## Quick triage notes

- `sysctl vm.swapusage` は、**swap usage** と swap が**暗号化**されているかを確認する簡単な方法として、現在も利用できます。
- `sleepimage` は主に **hibernate/safe sleep** のシナリオで引き続き関連しますが、modern systems では一般的に保護されているため、信頼できる acquisition path ではなく、確認対象の**artifact source**として扱うべきです。
- recent macOS releases では、boot policy、SIP の状態、kext loading を制御できない限り、**full physical memory imaging** よりも **process-level dumping** の方が一般的に現実的です。

## References

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
