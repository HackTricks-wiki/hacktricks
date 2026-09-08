# Object Manager Slow PathsによるKernel Race Condition Exploitation

{{#include ../../banners/hacktricks-training.md}}

## Race windowを引き延ばすことが重要な理由

多くのWindows kernel LPEは、`check_state(); NtOpenX("name"); privileged_action();`という典型的なパターンに従います。最新のハードウェアでは、coldな`NtOpenEvent`/`NtOpenSection`による短い名前の解決は約2 µsで完了するため、secure actionが実行される前にchecked stateを変更する時間はほとんどありません。意図的にstep 2のObject Manager Namespace (OMNS) lookupに数十マイクロ秒かかるようにすることで、attackerは数千回の試行を必要とせず、本来は不安定なraceにも一貫して勝てるだけの時間を得られます。<sup>[[1]](#references)</sup>

## Object Manager lookupの内部概要

* **OMNS structure** – `\BaseNamedObjects\Foo`のような名前は、directoryごとに解決されます。各componentで、kernelは*Object Directory*を検索・openし、Unicode stringを比較します。途中でsymbolic link（例：drive letter）が辿られる場合もあります。
* **UNICODE_STRING limit** – OM pathsは`UNICODE_STRING`内に格納され、その`Length`は16-bit valueです。絶対的な上限は65 535 bytes（32 767 UTF-16 codepoints）です。`\BaseNamedObjects\`のようなprefixがあっても、attackerは約32 000文字を制御できます。
* **Attacker prerequisites** – すべてのuserは、`\BaseNamedObjects`のようなwritable directoryの配下にobjectを作成できます。vulnerable codeがその配下のnameを使用する場合、またはそこに到達するsymbolic linkをfollowする場合、attackerはspecial privilegesなしでlookup performanceを制御できます。<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Single maximal component

componentの解決コストは、その長さに対しておおむねlinearです。これはkernelがparent directory内のすべてのentryに対してUnicode comparisonを実行する必要があるためです。32 kBの長さのnameを持つeventを作成すると、Windows 11 24H2（Snapdragon X Elite testbed）では`NtOpenEvent` latencyが約2 µsから約35 µsへ即座に増加します。
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*実践的な注意点*

- 任意の名前付き kernel object（events、sections、semaphores…）を使用して長さ制限に達させることができます。
- Symbolic links または reparse points によって、短い「victim」名をこの巨大な component に向けることで、slowdown を透過的に適用できます。
- すべてが user-writable namespaces 内に存在するため、この payload は standard user integrity level から動作します。<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Deep recursive directories

より攻撃的な variant では、数千個の directories の chain（`\BaseNamedObjects\A\A\...\X`）を割り当てます。各 hop で directory resolution logic（ACL checks、hash lookups、reference counting）が trigger されるため、per-level latency は単一の string compare より高くなります。同じ `UNICODE_STRING` size による制限である約 16,000 levels では、empirical timings が、長い単一 component で達成される 35 µs の barrier を超えます。
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
Tips:

* 親ディレクトリが重複を拒否し始めた場合は、レベルごとに文字（`A/B/C/...`）を切り替える。
* exploitation 後に chain をクリーンに削除して namespace を汚染しないよう、handle array を保持する。<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories、hash collisions、symlink reparses（マイクロ秒ではなく数分）

Object directories は **shadow directories**（fallback lookups）と、entry 用の bucket 化された hash tables をサポートしている。これらに加えて、64-component の symbolic-link reparse limit を悪用し、`UNICODE_STRING` の長さを超過せずに slowdown を大幅に増幅する。

1. `\BaseNamedObjects` の下に、例として `A`（shadow）と `A\A`（target）の2つのディレクトリを作成する。2つ目のディレクトリは、1つ目を shadow directory として使用して作成する（`NtCreateDirectoryObjectEx`）。これにより、`A` 内で見つからない lookup は `A\A` にフォールスルーする。
2. 各ディレクトリに、同じ hash bucket に入る **colliding names** を数千個投入する（例：同じ `RtlHashUnicodeString` value を維持しながら末尾の数字を変える）。これにより、lookup は単一ディレクトリ内で O(n) の linear scan まで低下する。
3. 長い `A\A\…` suffix に繰り返し reparse する、約63個の **object manager symbolic links** の chain を構築し、reparse budget を消費する。各 reparse は parsing を先頭から再開するため、collision のコストが増幅される。
4. 最終 component（`...\\0`）の lookup は、各ディレクトリに16,000個の collisions が存在する場合、Windows 11 上で **minutes** を要するようになり、one-shot kernel LPEs において race の勝利を実質的に保証できる。
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*重要な理由*: 数分間の slowdown により、one-shot の race-based LPE が deterministic exploit になります。<sup>[[1]](#references)</sup>

### 2025年の再テストに関するメモとすぐに使える tooling

- James Forshaw は、Windows 11 24H2（ARM64）で更新された timing とともにこの technique を再公開しました。baseline の open は引き続き約 2 µs で、32 kB の component によって約 35 µs まで増加します。また、shadow-dir + collision + 63-reparse chain では依然として約 3 分に達し、これらの primitive が現行の build でも有効であることが確認されています。source code と perf harness は更新版の Project Zero post にあります。<sup>[[1]](#references)</sup>
- 公開されている `symboliclink-testing-tools` bundle を使用して setup を script 化できます。`CreateObjectDirectory.exe` で shadow/target pair を作成し、`NativeSymlink.exe` を loop で実行して 63-hop chain を生成します。これにより、手書きの `NtCreate*` wrapper を用意する必要がなくなり、ACL も一貫した状態に保てます。<sup>[[2]](#references)</sup>

## Race window の測定

exploit 内に簡単な harness を組み込み、victim hardware 上で window がどの程度大きくなるかを測定します。以下の snippet は、target object を `iterations` 回 open し、`QueryPerformanceCounter` を使用して 1 回の open にかかる平均コストを返します。<sup>[[1]](#references)</sup>
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
結果は race orchestration strategy に直接反映されます（例：必要な worker threads の数、sleep intervals、共有状態を切り替える必要があるタイミング）。

## Exploitation workflow

1. **脆弱な open を特定する** – symbols、ETW、hypervisor tracing、または reverse engineering を使って kernel path を追跡し、attacker が制御する名前や user-writable directory 内の symbolic link を走査する `NtOpen*`/`ObOpenObjectByName` 呼び出しを見つけます。
2. **その名前を slow path に置き換える**
- `\BaseNamedObjects`（または別の writable OM root）配下に、長い component または directory chain を作成します。
- kernel が想定する名前が slow path に解決されるよう、symbolic link を作成します。元の target に触れずに、vulnerable driver の directory lookup をこの構造へ向けることができます。
3. **race を発生させる**
- Thread A（victim）が vulnerable code を実行し、slow lookup 内で block します。
- Thread B（attacker）が、Thread A が拘束されている間に guarded state を切り替えます（例：file handle の swap、symbolic link の書き換え、object security の切り替え）。
- Thread A が再開して privileged action を実行すると、stale state を認識し、attacker が制御する operation を実行します。
4. **後片付けをする** – 疑わしい artifacts を残したり、正規の IPC users を壊したりしないよう、directory chain と symbolic links を削除します。<sup>[[1]](#references)</sup>

## Applied chain: mutable Cloud Files placeholders + Object Manager path switching

[RoguePlanet (CVE-2026-50656)](https://github.com/MSNightmare/ShieldBreak) の bypass として公開された [ShieldBreak](https://github.com/MSNightmare/ShieldBreak) は、より広範な exploitation pattern を示しています。これは、privileged scanner に logical file のある表現を分類させた後、remediation がそれを使用する前に、その bytes と namespace resolution の両方を変更します。PoC は Cloud Files hydration TOCTOU、Object Manager shadow-directory fallback、CLFS-generated-name capture、local administrative-share link を組み合わせ、Defender cleanup を protected DLL write に変換します。<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Cloud Files hydration を通じて content を置き換える

attacker が書き込み可能な directory を Cloud Files sync root として登録し、`CF_CALLBACK_TYPE_FETCH_DATA` callback を接続します。次に、EICAR ZIP のような決定論的な detection trigger と advertised size が一致する placeholder を作成します。最初の fetch では trigger を返して callback state を切り替え、その後の fetch では payload を返します。scanner が最初の representation を分類した後、transfer key を取得し、payload-sized metadata で hydration を再開してから、hydration を EOF まで強制します。<sup>[[4]](#references)</sup>
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
セキュリティ境界が pathname または placeholder identity のみに基づいて scan、verdict、remediation を行う場合、その境界は破綻します。どちらも、後の hydration で検査済みの bytes が返されることを保証しません。<sup>[[4]](#references)</sup>

### 2. shadow-directory fallback を通じて invariant path を切り替える

`NtCreateDirectoryObjectEx` を使用して、target Object Manager directory と、target handle を shadow/fallback directory として渡した 2 つ目の directory を作成します。両方の resolution layer に同名の `WD_SCAN` entry を配置します。visible entry は通常の working directory を指し、fallback entry は `\CLFS\??\<working-directory>` を指すようにします。Defender には以下の invariant path のみを提供します。operation の実行中に visible link を削除すると、同じ string が CLFS-backed entry に fall through します。<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
これは、lookup を遅延させる目的だけで shadow directories を使用する場合とは異なります。攻撃者は、文字列を変更せずに、以前に受け入れられたパスの**意味**を変更します。<sup>[[4]](#references)</sup>

### 3. 生成された名前を取得し、ファイル名固有のリンクを作成する

`ReadDirectoryChangesW` を使用して working directory を監視します。最初の `FILE_ACTION_ADDED` で、表示されている `WD_SCAN` link を削除して fallback lookup を有効にします。2 番目に生成されたファイル名を取得し、その CLFS 関連ファイルを開いて、`LockFileEx` で範囲 `0..MAXLONGLONG` をロックします。privileged operation が停止している間に、表示されている directory 内の `WD_SCAN` を実際の Object Manager directory に置き換え、確認したファイル名から名付けた child symbolic link を作成します（PoC では末尾の 4 文字を削除します）。local SMB を介して protected destination を指すように設定します。<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
権限のないプロセス自身はその宛先に書き込めませんが、Defender の SYSTEM コンテキストは loopback administrative share をトラバースできます。生成された名前の観測と、ファイル名固有の Object Manager link を組み合わせることで、事前に remediation artifact を予測する必要がなくなります。<sup>[[4]](#references)</sup>

### 4. cleanup race を安定化し、privileged loader をトリガーする

スキャン前に、PoC は有効な PE（`ntdll.dll`）を placeholder の `:stream` NTFS alternate data stream に保存します。redirection によって保護された base file が作成された後、`phoneinfo.dll:stream` を execute access 付きで開き、`PAGE_EXECUTE_READ | SEC_IMAGE` mapping を維持したまま cleanup の再開を待ちます。存続する file/section object により、最終的な race 中の削除または置換が制約されます。再開された hydration は EICAR ではなく payload DLL を返すため、保護された base file には attacker-controlled code が含まれます。<sup>[[4]](#references)</sup>

その後、`C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` に細工した `Report.wer` を配置し、Task Scheduler COM API を介して `\Microsoft\Windows\Windows Error Reporting\QueueReporting` を呼び出すことで、protected write を SYSTEM execution に変換します。この chain では、privileged WER processing が配置された `C:\Windows\System32\phoneinfo.dll` をロードします。named-pipe connection は payload execution signal として使用されます。<sup>[[4]](#references)</sup>

### Detection pivots

有用な相関関係は、単一の一時ファイル名よりも具体的であり、chain 内のすべての namespace transition を対象にします。<sup>[[4]](#references)</sup>

- 新たに登録された Cloud Files provider、その後の EICAR detection、および同じ placeholder に対する `CF_OPERATION_TYPE_RESTART_HYDRATION`。
- `WD_TARGET_*`、`WD_SHADOW_*`、または `WD_SCAN` を含む Object Manager paths。特に、`\\.\globalroot\BaseNamedObjects\Restricted\` 配下の scan path。
- CLFS file creation、その後の exclusive whole-file lock、および privileged security process から `\\127.0.0.1\C$\Windows\System32\*.dll` への loopback access。
- NTFS ADS と同時に作成された System32 DLL、その後の stream に対する `SEC_IMAGE` mapping。
- attacker-created WER queue entry、その後の `\Microsoft\Windows\Windows Error Reporting\QueueReporting` の通常とは異なる手動実行、および配置された DLL の image load。

## Applied chain: privileged remediation に対する oplock-gated mount-point switch

privileged scanner が attacker-controlled file を検査し、その後、validated handles を使い続けるのではなく **pathname** を再度開いて remediation を行う場合、再利用可能な LPE pattern が現れます。FalconFlank は CrowdStrike Falcon の Office macro-removal workflow を対象とする公開例です。repository は、関連する policy を有効にした Windows 11 25H2 および Windows Server 2025 での testing を主張していますが、CVE、affected-build range、vendor advisory、patch status は公開していません。そのため、product-specific claim は未検証かつ build-dependent として扱ってください。<sup>[[5]](#references)[[6]](#references)</sup>

### Race layout

1. 最終的な relative name が意図した宛先で有用になる writable tree を構築します。この例では `%TEMP%\\Flanker_{GUID}\\WindowsPowerShell\\v1.0\\bcrypt.dll` を使用しますが、最初に `bcrypt.dll` へ OLE macro document（PE DLL ではない）を書き込みます。content-based detection が remediation をトリガーし、attacker-controlled basename は後の side-load 用に保持されます。<sup>[[5]](#references)</sup>
2. directories を broad sharing と `FILE_OPEN_REPARSE_POINT` 付きで開き、`FSCTL_REQUEST_OPLOCK`、`OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE`、および `REQUEST_OPLOCK_INPUT_FLAG_REQUEST` を指定して、trigger に asynchronous RH oplock を要求します。overlapped event を待ち、その完了を path-switch cue として使用します。RH oplock-break notification は advisory であり、すべての conflicting operation がブロックされている証明ではないため、exploitability は依然として victim の正確な open/remediation sequence に依存します。<sup>[[5]](#references)[[7]](#references)</sup>
3. break 後、delete と POSIX-semantics flags を使用し、`FileDispositionInformationEx`（information class 64）で leaf directory を削除してから、その handle を閉じます。次に、`FSCTL_SET_REPARSE_POINT_EX` で空になった parent に `IO_REPARSE_TAG_MOUNT_POINT` を適用します。mount point は変更されていない suffix を `\\SystemRoot\\System32\\WindowsPowerShell` のような protected tree へ redirect します。directory が空でない場合、reparse point の設定は失敗するため、先行する削除手順が必要になります。<sup>[[5]](#references)[[8]](#references)</sup>
4. privileged workflow を再開します。directory chain と final object が以前に検査したものと同一であることを証明せずに string を再度 resolve した場合、同じ logical pathname が attacker-selected protected directory に到達します。この例では、元の process から `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll` を read/write で再度開くことで成功を検証します。これにより、confused-deputy write primitive と後続の code-execution stage を区別できます。<sup>[[5]](#references)</sup>
5. 結果の file を real DLL に置き換え、privileged loader を起動します。PoC は `CreateTransaction` + `CreateFileTransacted` を使用して file を truncate し、DLL サイズの replacement を mapping し、PE をコピーして commit します。TxF は file handle と後続の handle-based operations を transaction に bind しますが、これは post-race replacement mechanism であり、privilege boundary failure の原因ではありません。<sup>[[5]](#references)[[9]](#references)</sup>
6. 最後に、実行ファイルが配置された隣接 filename を probe する既存の privileged scheduled task を実行します。FalconFlank は `\\Microsoft\\Windows\\Application Experience\\MareBackup` を呼び出し、DLL が `\\??\\pipe\\FALCONFLANK` に接続するのを待ってから、配置した file を削除します。task name だけから特定の resulting token を想定してはいけません。tested build 上で、起動された process、module path、integrity level、token を確認してください。<sup>[[5]](#references)</sup>

したがって、中心となる audit question は「service が元の input path を validate するか」ではなく、「すべての privileged mutation が、validation 済みの、同じ opened file および directory objects に bind されたままか」です。check と use の間で handles を保持し、trusted directory handle を基準に child objects を開き、予期しない reparse tags を拒否し、mutation 前に file identity を再検証することで、この種の pathname-substitution bug を防止できます。<sup>[[1]](#references)[[8]](#references)</sup>

### Detection and PoC triage

High-signal detection では、namespace transition と privileged consumer を相関させます。GUID-named temporary tree 内の DLL basename に対応する OLE header、oplock break、leaf directory の POSIX-style removal、protected Windows directory を対象とする mount point の作成、およびその宛先配下での同じ basename の作成または変更を確認します。公開例では、より限定的な pivot として `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll`、`MareBackup` の手動実行、および `FALCONFLANK` named pipe を追加します。ただし、いずれも単独では十分ではありません。<sup>[[5]](#references)</sup>

PoC を再現する際は、公開 source にある次の3つの reliability defect を考慮してください。`FlushFileBuffers` に file handle ではなく埋め込み byte-array pointer を渡していること、`GetFolder`、`GetTask`、`Run` の後に stale `HRESULT` を検査していること、そして directory deletion、reparse creation、oplock event、pipe connection に対して上限のない retry/wait loop を使用していることです。<sup>[[5]](#references)</sup>

## Operational considerations

- **Combine primitives** – `UNICODE_STRING` の size 上限に達するまで、directory chain の *各 level ごと* に長い name を使用して、さらに高い latency を実現できます。
- **One-shot bugs** – expanded window（数十マイクロ秒から数分）により、CPU affinity pinning または hypervisor-assisted preemption と組み合わせれば、「single trigger」bugs が現実的になります。
- **Side effects** – slowdown は malicious path にのみ影響するため、システム全体の performance は変化しません。defender が namespace growth を監視していない限り、気付くことはほとんどありません。
- **Cleanup** – 作成したすべての directory/object への handles を保持し、後で `NtMakeTemporaryObject`/`NtClose` を呼び出せるようにします。そうしなければ、上限のない directory chain が reboot 後も残る可能性があります。
- **File-system races** – 脆弱な path が最終的に NTFS を通じて resolve される場合、OM slowdown の実行中に backing file に Oplock（同じ toolkit の `SetOpLock.exe` など）を重ねて設定できます。これにより、OM graph を変更せずに consumer を追加の数ミリ秒間 freeze できます。<sup>[[2]](#references)</sup>

## Defensive notes

- named objects に依存する kernel code は、open の *後* に security-sensitive state を再検証するか、check 前に reference を取得して、TOCTOU gap を閉じるべきです。
- user-controlled names を dereference する前に、OM path の depth/length に上限を適用します。過度に長い names を拒否すれば、攻撃者を microsecond window に戻せます。
- object manager namespace growth（ETW `Microsoft-Windows-Kernel-Object`）を instrument し、`\BaseNamedObjects` 配下にある、数千の components からなる疑わしい chain を検出します。

## References

- [1] [Project Zero – Windows Exploitation Techniques: Path Lookups による Race Conditions の攻略](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
- [5] [FalconFlank.cpp (commit 702b574)](https://github.com/MSNightmare/FalconFlank/blob/702b57477a9f0a99ddabef56e7ebe6c1e99c2435/FalconFlank.cpp)
- [6] [MSNightmare/FalconFlank](https://github.com/MSNightmare/FalconFlank)
- [7] [Microsoft Learn - FSCTL_REQUEST_OPLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [8] [Microsoft Learn - FSCTL_SET_REPARSE_POINT_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point-ex)
- [9] [Microsoft Learn - Transactional NTFS の使用方法](https://learn.microsoft.com/en-us/windows/win32/fileio/how-to-use-transactional-ntfs)
{{#include ../../banners/hacktricks-training.md}}
