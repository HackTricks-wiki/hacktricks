# Object Manager Slow Paths による Kernel Race Condition Exploitation

{{#include ../../banners/hacktricks-training.md}}

## レースウィンドウを広げることが重要な理由

多くの Windows kernel LPE は、`check_state(); NtOpenX("name"); privileged_action();` という古典的なパターンに従います。最新のハードウェアでは、コールド状態の `NtOpenEvent`/`NtOpenSection` が短い名前を解決するのに約 2 µs しかかからないため、secure action が実行される前にチェック済みの状態を反転させる時間はほとんどありません。意図的にステップ 2 の Object Manager Namespace (OMNS) lookup を数十マイクロ秒かかるようにすることで、attacker は何千回も試行しなくても、通常は不安定な race に一貫して勝てるだけの時間を確保できます。<sup>[[1]](#references)</sup>

## Object Manager lookup の内部概要

* **OMNS structure** – `\BaseNamedObjects\Foo` のような名前は、directory ごとに解決されます。各 component で、kernel は *Object Directory* を検索して開き、Unicode string を比較します。経路上で symbolic link（ドライブレターなど）が辿られる場合もあります。
* **UNICODE_STRING limit** – OM path は `UNICODE_STRING` 内に格納され、その `Length` は 16 ビット値です。絶対的な上限は 65,535 bytes（32,767 UTF-16 codepoints）です。`\BaseNamedObjects\` のような prefix を使用しても、attacker は約 32,000 文字を制御できます。
* **Attacker prerequisites** – どの user でも、`\BaseNamedObjects` のような writable directory の下に object を作成できます。vulnerable code がその内部の名前を使用する場合、またはそこに到達する symbolic link を辿る場合、attacker は special privileges なしで lookup performance を制御できます。<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Single maximal component

component の解決コストは、その長さに対しておおむね線形です。これは kernel が parent directory 内のすべての entry に対して Unicode comparison を実行する必要があるためです。32 kB の長さの名前を持つ event を作成すると、Windows 11 24H2（Snapdragon X Elite testbed）では `NtOpenEvent` latency が約 2 µs から約 35 µs に直ちに増加します。
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*実践的な注意点*

- 名前付き kernel object（events、sections、semaphores など）であれば、いずれでも長さ制限に到達できます。
- Symbolic links または reparse points によって、短い「victim」名をこの巨大な component に向けると、slowdown を透過的に適用できます。
- すべてが user-writable namespace 内に存在するため、この payload は standard user integrity level から実行できます。<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – 深く再帰したディレクトリ

より攻撃的な variant では、数千個のディレクトリの chain（`\BaseNamedObjects\A\A\...\X`）を割り当てます。各 hop で directory resolution logic（ACL checks、hash lookups、reference counting）がトリガーされるため、1 回の string compare よりも level あたりの latency が高くなります。同じ `UNICODE_STRING` size による制限を受けますが、約 16,000 levels では、long single components で達成された 35 µs の barrier を empirical timings が上回ります。
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

* 親ディレクトリが重複を拒否し始めた場合は、レベルごとに文字（`A/B/C/...`）を切り替える。
* exploit 後に chain をクリーンに削除して namespace を汚染しないよう、handle array を保持する。<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories、hash collisions、symlink reparses（マイクロ秒ではなく数分）

Object directories は **shadow directories**（fallback lookups）と、entry 用の bucketed hash tables をサポートしている。これらと 64-component の symbolic-link reparse limit を組み合わせて悪用し、`UNICODE_STRING` の長さを超えずに slowdown を大幅に増幅する。

1. `\BaseNamedObjects` 配下に、例として `A`（shadow）と `A\A`（target）の 2 つの directories を作成する。2 つ目は 1 つ目を shadow directory として使用して (`NtCreateDirectoryObjectEx`)、作成する。これにより、`A` での missing lookup は `A\A` に fall through する。
2. 各 directory に、同じ hash bucket に入る **colliding names** を数千個追加する（例: `RtlHashUnicodeString` の値を同じに保ちながら、末尾の digits を変える）。これにより lookup は単一 directory 内で O(n) の linear scan に劣化する。
3. 長い `A\A\…` suffix に繰り返し reparse する、約 63 個の **object manager symbolic links** の chain を構築し、reparse budget を消費する。各 reparse は parsing を先頭から再開するため、collision のコストが増幅される。
4. 最終 component（`...\\0`）の lookup は、各 directory に 16,000 個の collisions が存在する場合、Windows 11 上で **数分**かかるようになり、one-shot kernel LPE において実質的に race win を確実に得られる。
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*重要性*: 数分間の slowdown により、one-shot の race ベース LPE は deterministic exploit になります。<sup>[[1]](#references)</sup>

### 2025 retest notes & ready-made tooling

- James Forshaw は、Windows 11 24H2 (ARM64) で更新された timing とともにこの technique を再公開しました。Baseline の open は引き続き約 2 µs です。32 kB の component により約 35 µs まで増加し、shadow-dir + collision + 63-reparse chain では依然として約 3 分に達します。これは、現在の build でも primitives が存続していることを確認しています。Source code と perf harness は、更新された Project Zero の post にあります。<sup>[[1]](#references)</sup>
- 公開されている `symboliclink-testing-tools` bundle を使用して setup を script 化できます。`CreateObjectDirectory.exe` で shadow/target pair を作成し、`NativeSymlink.exe` を loop で実行して 63-hop chain を生成します。これにより、手書きの `NtCreate*` wrapper を用意する必要がなくなり、ACL も一貫して維持できます。<sup>[[2]](#references)</sup>

## Measuring your race window

exploit 内に簡単な harness を組み込み、victim hardware 上で window がどの程度大きくなるかを測定します。以下の snippet は、`QueryPerformanceCounter` を使用して target object を `iterations` 回 open し、1 回の open あたりの平均 cost を返します。<sup>[[1]](#references)</sup>
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
結果は、race orchestration strategy（必要な worker thread の数、sleep interval、shared state を切り替えるタイミングなど）に直接反映されます。

## Exploitation workflow

1. **脆弱な open を特定する** – symbols、ETW、hypervisor tracing、または reversing を使って kernel path を追跡し、attacker-controlled name または user-writable directory 内の symbolic link をたどる `NtOpen*`/`ObOpenObjectByName` 呼び出しを見つけます。
2. **その name を slow path に置き換える**
- `\BaseNamedObjects`（または別の writable OM root）配下に、長い component または directory chain を作成します。
- name the kernel expects が slow path に解決されるように symbolic link を作成します。元の target に触れずに、vulnerable driver の directory lookup を自分の構造へ向けられます。
3. **race を trigger する**
- Thread A（victim）は vulnerable code を実行し、slow lookup 内で block します。
- Thread B（attacker）は、Thread A が処理中の間に guarded state（例：file handle の swap、symbolic link の書き換え、object security の切り替え）を変更します。
- Thread A が再開して privileged action を実行すると、stale state を観測し、attacker-controlled operation を実行します。
4. **clean up** – 疑わしい artifact を残したり、正規の IPC user を壊したりしないよう、directory chain と symbolic link を削除します。<sup>[[1]](#references)</sup>

## Applied chain: mutable Cloud Files placeholders + Object Manager path switching

RoguePlanet（CVE-2026-50656）に対する bypass として公開された [ShieldBreak](https://github.com/MSNightmare/ShieldBreak) は、より広範な exploitation pattern を示しています。これは、privileged scanner に logical file のある representation を分類させた後、remediation がそれを使用する前に、その bytes と namespace resolution の両方を変更します。PoC は、Cloud Files hydration TOCTOU、Object Manager shadow-directory fallback、CLFS-generated-name capture、local administrative-share link を組み合わせ、Defender cleanup を protected DLL write に変換します。<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Cloud Files hydration を通じて content を置き換える

attacker-writable directory を Cloud Files sync root として登録し、`CF_CALLBACK_TYPE_FETCH_DATA` callback に接続します。そして、EICAR ZIP のような deterministic detection trigger と advertised size が一致する placeholder を作成します。最初の fetch は trigger を返して callback state を切り替え、後続の fetch は payload を返します。scanner が最初の representation を分類した後、transfer key を取得し、payload-sized metadata で hydration を再開してから、hydration を EOF まで強制します。<sup>[[4]](#references)</sup>
```cpp
CfRegisterSyncRoot(sync_root, &registration, &policies, flags);
CfConnectSyncRoot(sync_root, callbacks, &state, connect_flags, &connection);
CfCreatePlaceholders(sync_root, &placeholder, 1, 0, &created);
// First FETCH_DATA => detection trigger; later FETCH_DATA => payload.
CfGetTransferKey(placeholder_handle, &transfer_key);
opInfo.Type = CF_OPERATION_TYPE_RESTART_HYDRATION;
CfExecute(&opInfo, &restart_params);
CfHydratePlaceholder(placeholder_handle, {0}, CF_EOF, 0, NULL);
```
セキュリティ境界は、scan、verdict、remediation が pathname または placeholder identity のみに依存している場合に破綻します。どちらも、後続の hydration によって検査済みの bytes が返されることを保証しません。<sup>[[4]](#references)</sup>

### 2. shadow-directory fallback を通じて invariant path を切り替える

`NtCreateDirectoryObjectEx` を使用し、target handle を shadow/fallback directory として渡して、target Object Manager directory と、2つ目の directory を作成します。両方の resolution layer に同名の `WD_SCAN` entry を配置します。visible entry は通常の working directory を指し、fallback entry は `\CLFS\??\<working-directory>` を指すようにします。以下の invariant path のみを Defender に提供します。operation の実行中に visible link を削除すると、同じ string が CLFS-backed entry にフォールスルーします。<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
これは、lookup を遅延させるためだけに shadow directories を使用する方法とは異なります。攻撃者は、文字列を変更せずに、以前に受け入れられた path の**意味**を変更します。<sup>[[4]](#references)</sup>

### 3. 生成された名前を取得し、ファイル名固有の link を設定する

`ReadDirectoryChangesW` を使用して作業ディレクトリを監視します。最初の `FILE_ACTION_ADDED` で、表示されている `WD_SCAN` link を削除して fallback lookup を有効にします。2 番目に生成されたファイル名を取得し、その CLFS 関連ファイルを開いて、`LockFileEx` で範囲 `0..MAXLONGLONG` をロックします。privileged operation が停止している間に、表示ディレクトリ内の `WD_SCAN` を実際の Object Manager directory に置き換え、観測したファイル名から名前を付けた child symbolic link を作成します（PoC では末尾 4 文字を削除します）。これを local SMB 経由で protected destination に向けます。<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
権限のないプロセス自体はその宛先に書き込めませんが、Defender の SYSTEM コンテキストは loopback administrative share を経由できます。生成された名前の監視と、ファイル名固有の Object Manager link を組み合わせることで、事前に remediation artifact を予測する必要がなくなります。<sup>[[4]](#references)</sup>

### 4. cleanup race を安定化し、privileged loader をトリガーする

スキャン前に、PoC は有効な PE（`ntdll.dll`）を placeholder の `:stream` NTFS alternate data stream に保存します。redirection によって保護された base file が作成された後、`phoneinfo.dll:stream` を execute access で開き、`PAGE_EXECUTE_READ | SEC_IMAGE` mapping を維持したまま cleanup の再開を待ちます。この live file/section objects により、最終的な race 中の削除または置換が制限されます。再開された hydration は EICAR ではなく payload DLL を返すため、保護された base file に attacker-controlled code が含まれることになります。<sup>[[4]](#references)</sup>

次に、`C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` 配下に細工した `Report.wer` を配置し、Task Scheduler COM API を通じて `\Microsoft\Windows\Windows Error Reporting\QueueReporting` を呼び出すことで、保護された write を SYSTEM execution に変換します。この chain では、privileged WER processing が配置された `C:\Windows\System32\phoneinfo.dll` を load し、named-pipe connection を payload execution signal として使用します。<sup>[[4]](#references)</sup>

### Detection pivots

有用な相関関係は、単一の temporary filename よりも具体的であり、chain 内のすべての namespace transition を対象にします。<sup>[[4]](#references)</sup>

- 新たに登録された Cloud Files provider に続いて、同じ placeholder 上で EICAR detection と `CF_OPERATION_TYPE_RESTART_HYDRATION` が発生する。
- `WD_TARGET_*`、`WD_SHADOW_*`、または `WD_SCAN` を含む Object Manager paths。特に、`\\.\globalroot\BaseNamedObjects\Restricted\` 配下の scan path。
- CLFS file creation に続いて、exclusive whole-file lock と、privileged security process から `\\127.0.0.1\C$\Windows\System32\*.dll` への loopback access が発生する。
- System32 DLL と NTFS ADS が同時に作成され、その後に stream の `SEC_IMAGE` mapping が行われる。
- attacker-created WER queue entry に続いて、通常とは異なる手動の `\Microsoft\Windows\Windows Error Reporting\QueueReporting` 実行と、配置された DLL の image load が発生する。

## Operational considerations

- **Combine primitives** – `UNICODE_STRING` のサイズ上限に達するまで、directory chain の *per level* に long name を使用して、さらに高い latency を実現できます。
- **One-shot bugs** – window が拡大することで（数十マイクロ秒から数分）、CPU affinity pinning または hypervisor-assisted preemption と組み合わせた「single trigger」bugs が現実的になります。
- **Side effects** – slowdown は malicious path にのみ影響するため、システム全体の performance は影響を受けません。そのため、defender が namespace growth を監視していない限り、気付くことはほとんどありません。
- **Cleanup** – 作成したすべての directory/object への handles を保持し、後で `NtMakeTemporaryObject`/`NtClose` を呼び出せるようにします。そうしないと、制限のない directory chain が reboot 後も残る可能性があります。
- **File-system races** – 脆弱な path が最終的に NTFS を経由して解決される場合、OM slowdown の実行中に backing file 上へ Oplock（同じ toolkit の `SetOpLock.exe` など）を設定できます。これにより、OM graph を変更せずに consumer をさらに数ミリ秒間 freeze できます。<sup>[[2]](#references)</sup>

## Defensive notes

- named objects に依存する kernel code は、open の *後* に security-sensitive state を再検証するか、check の前に reference を取得する必要があります（TOCTOU gap を解消します）。
- user-controlled names を dereference する前に、OM path の depth/length に上限を適用します。過度に長い names を拒否することで、攻撃者を microsecond window に戻せます。
- object manager namespace growth（ETW `Microsoft-Windows-Kernel-Object`）を instrument し、`\BaseNamedObjects` 配下にある疑わしい数千コンポーネントの chain を検出します。

## References

- [1] [Project Zero – Windows Exploitation Techniques: Path Lookups で Race Conditions に勝つ](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
{{#include ../../banners/hacktricks-training.md}}
