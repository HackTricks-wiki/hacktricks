# Object Manager Slow Paths を介した Kernel Race Condition Exploitation

{{#include ../../banners/hacktricks-training.md}}

## Race window を広げることが重要な理由

多くの Windows kernel LPE は、典型的な `check_state(); NtOpenX("name"); privileged_action();` というパターンに従います。最新のハードウェアでは、cold な `NtOpenEvent`/`NtOpenSection` が短い名前を解決するのに約 2 µs しかかからないため、secure action が実行される前にチェック済みの状態を変更する時間はほとんどありません。意図的に step 2 の Object Manager Namespace (OMNS) lookup に tens of microseconds を要するようにすることで、attacker は数千回の試行を必要とせず、通常なら不安定な race に一貫して勝てるだけの時間を得られます。<sup>[[1]](#references)</sup>

## Object Manager lookup internals の概要

* **OMNS structure** – `\BaseNamedObjects\Foo` のような名前は、directory-by-directory で解決されます。各 component で、kernel は *Object Directory* を検索・open し、Unicode strings を比較します。途中で Symbolic links（例: drive letters）が辿られる場合もあります。
* **UNICODE_STRING limit** – OM paths は `UNICODE_STRING` 内に格納されます。この `Length` は 16-bit 値です。absolute limit は 65 535 bytes（32 767 UTF-16 codepoints）です。`\BaseNamedObjects\` のような prefixes を含めても、attacker は約 32 000 characters を制御できます。
* **Attacker prerequisites** – Any user can create objects underneath `\BaseNamedObjects` のような writable directories。vulnerable code がその配下の name を使用する場合、またはそこに到達する symbolic link を辿る場合、attacker は special privileges なしで lookup performance を制御できます。<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Single maximal component

component の解決コストは、その length に対しておおむね linear です。これは kernel が parent directory 内のすべての entry に対して Unicode comparison を実行する必要があるためです。32 kB-long name を持つ event を作成すると、Windows 11 24H2（Snapdragon X Elite testbed）では `NtOpenEvent` latency が直ちに約 2 µs から約 35 µs に増加します。
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*実践的な注意点*

- 任意の named kernel object（events、sections、semaphores…）を使用して長さ制限に到達できます。
- Symbolic links または reparse points によって、短い「victim」名をこの巨大な component に指し示せるため、slowdown を透過的に適用できます。
- すべてが user-writable namespaces 内に存在するため、この payload は standard user integrity level から動作します。<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Deep recursive directories

より攻撃的な variant では、数千個の directories の chain（`\BaseNamedObjects\A\A\...\X`）を allocate します。各 hop で directory resolution logic（ACL checks、hash lookups、reference counting）が trigger されるため、per-level latency は単一の string compare より高くなります。約 16 000 levels（同じ `UNICODE_STRING` size による制限）では、empirical timings が、長い単一 component で達成される 35 µs の barrier を超えます。
```cpp
ScopedHandle base_dir = OpenDirectory(L"\\BaseNamedObjects");
HANDLE last_dir = base_dir.get();
std::vector<ScopedHandle> dirs;
for (int i = 0; i < 16000; i++) {
dirs.emplace_back(CreateDirectory(L"A", last_dir));
last_dir = dirs.back().get();
if ((i % 500) == 0) {
auto result = RunTest(GetName(last_dir) + L"\\X", iterations);
printf("%d,%f\n", i + 1, result);
}
}
```
ヒント:

* 親ディレクトリが重複を拒否し始めた場合は、レベルごとに文字（`A/B/C/...`）を交互に使用します。
* exploit 後にチェーンをクリーンに削除して namespace を汚染しないよう、handle 配列を保持します。<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – シャドウディレクトリ、hash collision、symlink の再解析（マイクロ秒ではなく数分）

Object directory は **shadow directories**（fallback lookup）と、エントリ用の bucket 化された hash table をサポートしています。これらに加えて 64-component の symbolic-link reparse limit を悪用し、`UNICODE_STRING` の長さを超えずに slowdown を倍増させます。

1. `\BaseNamedObjects` 配下に、例えば `A`（shadow）と `A\A`（target）の 2 つのディレクトリを作成します。2 つ目は 1 つ目を shadow directory として使用して作成します（`NtCreateDirectoryObjectEx`）。これにより、`A` で見つからない lookup は `A\A` にフォールスルーします。
2. 各ディレクトリを、同じ hash bucket に入る **colliding names** で数千件埋めます（例えば、`RtlHashUnicodeString` の値を同じに保ちながら末尾の数字を変えます）。これにより lookup は単一ディレクトリ内で O(n) の linear scan に劣化します。
3. 長い `A\A\…` suffix に繰り返し再解析する約 63 個の **object manager symbolic links** のチェーンを構築し、reparse budget を消費します。各 reparse は parsing を先頭から再開するため、collision のコストが倍増します。
4. 最終 component（`...\\0`）の lookup は、各ディレクトリに 16,000 個の collision が存在する場合、Windows 11 上で **数分** かかるようになります。これにより、one-shot kernel LPE において race に勝てることが実質的に保証されます。
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*重要な理由*: 数分間の slowdown によって、one-shot の race-based LPEs が deterministic exploits になります。<sup>[[1]](#references)</sup>

### 2025 retest notes & ready-made tooling

- James Forshaw は、Windows 11 24H2（ARM64）で更新された timing とともにこの technique を再公開しました。Baseline の open は約 2 µs のままですが、32 kB の component によって約 35 µs まで増加し、shadow-dir + collision + 63-reparse chains では依然として約 3 分に到達します。これは、現在の builds でも primitives が有効であることを確認しています。Source code と perf harness は、更新された Project Zero post にあります。<sup>[[1]](#references)</sup>
- 公開されている `symboliclink-testing-tools` bundle を使用して setup を script 化できます。`CreateObjectDirectory.exe` で shadow/target pair を作成し、`NativeSymlink.exe` を loop で実行して 63-hop chain を生成します。これにより、手書きの `NtCreate*` wrappers が不要になり、ACLs も一貫して維持できます。<sup>[[2]](#references)</sup>

## Measuring your race window

exploit 内に簡単な harness を組み込み、victim hardware 上で window がどの程度大きくなるかを測定します。以下の snippet は target object を `iterations` 回 open し、`QueryPerformanceCounter` を使用して open 1 回あたりの平均コストを返します。<sup>[[1]](#references)</sup>
```cpp
static double RunTest(const std::wstring name, int iterations,
std::wstring create_name = L"", HANDLE root = nullptr) {
if (create_name.empty()) {
create_name = name;
}
ScopedHandle event_handle = CreateEvent(create_name, root);
ObjectAttributes obja(name);
std::vector<ScopedHandle> handles;
Timer timer;
for (int i = 0; i < iterations; ++i) {
HANDLE open_handle;
Check(NtOpenEvent(&open_handle, MAXIMUM_ALLOWED, &obja));
handles.emplace_back(open_handle);
}
return timer.GetTime(iterations);
}
```
結果は race orchestration strategy に直接反映されます（例：必要な worker thread 数、sleep interval、shared state を切り替える必要があるタイミング）。

## Exploitation workflow

1. **脆弱な open を特定する** – symbols、ETW、hypervisor tracing、または reverse engineering を使用して kernel path を追跡し、user-writable directory 内の attacker-controlled name または symbolic link をたどる `NtOpen*`/`ObOpenObjectByName` call を見つけます。
2. **その name を slow path に置き換える**
- `\BaseNamedObjects`（または別の writable OM root）配下に、長い component または directory chain を作成します。
- name the kernel expects が slow path に解決されるよう symbolic link を作成します。元の target に触れることなく、vulnerable driver の directory lookup を自分の structure に向けることができます。
3. **race を trigger する**
- Thread A（victim）が vulnerable code を実行し、slow lookup 内で block します。
- Thread B（attacker）が、Thread A が処理中に guarded state を変更します（例：file handle の swap、symbolic link の書き換え、object security の切り替え）。
- Thread A が再開して privileged action を実行すると、stale state を認識し、attacker-controlled operation を実行します。
4. **Cleanup** – 疑わしい artifact を残したり、正規の IPC user を破壊したりしないよう、directory chain と symbolic link を削除します。<sup>[[1]](#references)</sup>

## Operational considerations

- **Primitive を組み合わせる** – directory chain の *各 level* で長い name を使用すると、`UNICODE_STRING` の size を使い切るまで、さらに高い latency を実現できます。
- **One-shot bug** – window を（数十 microsecond から数分まで）拡大できるため、CPU affinity pinning または hypervisor-assisted preemption と組み合わせれば、“single trigger” bug も現実的になります。
- **副作用** – slowdown は malicious path にのみ影響するため、システム全体の performance は影響を受けません。defender が namespace growth を監視していない限り、気付くことはほとんどありません。
- **Cleanup** – 作成したすべての directory/object への handle を保持し、後で `NtMakeTemporaryObject`/`NtClose` を呼び出せるようにします。そうしないと、制限のない directory chain が reboot 後も残る可能性があります。
- **File-system race** – vulnerable path が最終的に NTFS 経由で解決される場合、OM slowdown の実行中に backing file へ Oplock（同じ toolkit の `SetOpLock.exe` など）を設定できます。これにより、OM graph を変更せずに consumer をさらに数 millisecond freeze できます。<sup>[[2]](#references)</sup>

## Defensive notes

- named object に依存する kernel code は、open の *後* に security-sensitive state を再検証するか、check 前に reference を取得して、TOCTOU gap を解消する必要があります。
- user-controlled name を dereference する前に、OM path の depth/length に上限を設定します。過度に長い name を拒否すれば、attacker は microsecond window に戻されます。
- object manager namespace の growth（ETW `Microsoft-Windows-Kernel-Object`）を instrument し、`\BaseNamedObjects` 配下にある疑わしい数千 component の chain を検出します。

## References

- [1] [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
