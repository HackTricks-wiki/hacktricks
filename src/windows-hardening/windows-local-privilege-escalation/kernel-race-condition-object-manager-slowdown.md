# Object Manager のスローパスを利用したカーネルレース条件の悪用

{{#include ../../banners/hacktricks-training.md}}

## レースウィンドウを広げることが重要な理由

多くの Windows カーネル LPE は古典的なパターン `check_state(); NtOpenX("name"); privileged_action();` に従います。最新ハードウェアではコールドな `NtOpenEvent`/`NtOpenSection` が短い名前を約2 µs で解決するため、セキュアなアクションが起こる前にチェック済みの状態を反転させる余地がほとんどありません。手順2 の Object Manager Namespace (OMNS) のルックアップを故意に数十マイクロ秒かかるようにすると、攻撃者は数千回の試行を必要とせずに、一貫して本来は不安定なレースに勝てる十分な時間を得られます。

## Object Manager ルックアップの内部（概要）

* **OMNS structure** – `\BaseNamedObjects\Foo` のような名前はディレクトリごとに解決されます。各コンポーネントごとにカーネルは *Object Directory* を見つけ/開き、Unicode 文字列を比較します。シンボリックリンク（例: ドライブ文字）も経由する可能性があります。
* **UNICODE_STRING limit** – OM パスは `Length` が 16-bit の `UNICODE_STRING` の中に格納されます。絶対上限は 65 535 バイト（32 767 UTF-16 コードポイント）です。`\BaseNamedObjects\` のようなプレフィックスがある場合でも、攻撃者は約32,000文字を制御できます。
* **Attacker prerequisites** – 任意のユーザーが `\BaseNamedObjects` のような書き込み可能なディレクトリ下にオブジェクトを作成できます。脆弱なコードがその中の名前を使うか、そこに到達するシンボリックリンクを辿ると、攻撃者は特別な権限なしにルックアップの性能を制御できます。

## Slowdown primitive #1 – Single maximal component

コンポーネントの解決コストは大まかにその長さに比例します。これはカーネルが親ディレクトリ内の各エントリに対して Unicode 比較を行う必要があるためです。32 kB 長の名前を持つイベントを作成すると、Windows 11 24H2 (Snapdragon X Elite testbed) で `NtOpenEvent` のレイテンシが約2 µs から約35 µs に即座に増加します。
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*実用的な注意事項*

- 任意の名前付きカーネルオブジェクト（events, sections, semaphores…）を使って長さ制限に達することができる。
- Symbolic links や reparse points は短い “victim” 名をこの巨大なコンポーネントにポイントさせることができ、スローダウンが透過的に適用される。
- すべてが user-writable namespaces に存在するため、payload は standard user integrity level からでも動作する。

## Slowdown primitive #2 – Deep recursive directories

より攻撃的な変種では、数千に及ぶディレクトリのチェーン（`\BaseNamedObjects\A\A\...\X`）を割り当てる。各ホップはディレクトリ解決ロジック（ACL checks、hash lookups、reference counting）をトリガーするため、各レベルの遅延は単一の文字列比較よりも大きくなる。約16 000レベル（同じ `UNICODE_STRING` サイズによって制限される）で、実測タイミングは長い単一コンポーネントで達成された35 µsの壁を上回る。
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

* 親ディレクトリが重複を拒否し始めたら、レベルごとに文字を交互にする（`A/B/C/...`）。
* チェーンをクリーンに削除して namespace を汚染しないよう、handle array を保持しておく。

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

Object directories は **shadow directories**（fallback lookups）とエントリ用の bucketed hash tables をサポートします。これら双方と64コンポーネントの symbolic-link reparse limit を悪用して、`UNICODE_STRING` 長を超えずにスローダウンを増幅します:

1. `\BaseNamedObjects` の下に2つのディレクトリを作成します。例: `A`（shadow）と `A\A`（target）。2つ目は1つ目を shadow directory として作成します（`NtCreateDirectoryObjectEx`）。これにより `A` 内で見つからないルックアップは `A\A` にフォールスルーします。
2. 各ディレクトリに同じハッシュバケットに入る何千もの **colliding names** を詰めます（例: 末尾の数字を変えつつ `RtlHashUnicodeString` の値は同じにする）。これによりルックアップは単一ディレクトリ内で O(n) の線形スキャンへ劣化します。
3. 約63個の **object manager symbolic links** のチェーンを構築し、長い `A\A\…` サフィックスに繰り返し reparse させて reparse budget を消費させます。各 reparse は解析を先頭から再開するため、衝突コストが乗算されます。
4. 各ディレクトリに16,000件の衝突がある場合、最終コンポーネント（`...\\0`）のルックアップは Windows 11 で現在 **minutes** かかります。これにより one-shot kernel LPEs に対して事実上確実なレース勝利が得られます。
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*なぜ重要か*: 数分に及ぶ遅延は、単発のレースベースのLPEを決定論的なエクスプロイトに変えます。

## レースウィンドウを測定する

被害者のハードウェア上でウィンドウがどれだけ大きくなるかを測定するため、簡単なハーネスをexploit内に埋め込んでください。以下のスニペットはターゲットオブジェクトを`iterations`回開き、`QueryPerformanceCounter`を使って1回あたりの平均オープンコストを返します。
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
これらの結果はあなたの race orchestration strategy に直接反映されます（例: 必要な worker threads の数、sleep intervals、共有 state をどれくらい早く flip する必要があるか）。

## エクスプロイトのワークフロー

1. **Locate the vulnerable open** – カーネルの経路をトレースします（シンボル、ETW、hypervisor tracing、またはリバース）して、攻撃者が制御できる名前やユーザー書き込み可能なディレクトリ内の symbolic link を辿る `NtOpen*`/`ObOpenObjectByName` 呼び出しを見つけます。
2. **Replace that name with a slow path**
- `\BaseNamedObjects`（または別の書き込み可能な OM root）の下に長いコンポーネントまたはディレクトリチェーンを作成します。
- カーネルが期待する名前が遅延するパスを解決するように、シンボリックリンクを作成します。これにより、元のターゲットに触れずに脆弱なドライバのディレクトリ検索をあなたの構造に向けられます。
3. **Trigger the race**
- Thread A（victim）は脆弱なコードを実行し、遅いルックアップ内でブロックします。
- Thread B（attacker）は Thread A が占有されている間に guarded state を flip します（例: ファイルハンドルを入れ替える、シンボリックリンクを書き換える、オブジェクトのセキュリティを切り替える）。
- Thread A が再開して特権アクションを実行すると、古い状態を参照して attacker-controlled な操作を行います。
4. **Clean up** – 疑わしい痕跡を残したり正当な IPC 利用者を壊したりしないように、ディレクトリチェーンやシンボリックリンクを削除します。

## 運用上の考慮点

- **Combine primitives** – ディレクトリチェーンの各レベルで長い名前を使うことで、`UNICODE_STRING` サイズが尽きるまでさらに高い遅延を得られます。
- **One-shot bugs** – 拡張されたウィンドウ（数十マイクロ秒から数分）は、CPU affinity pinning や hypervisor-assisted preemption と組み合わせると「single trigger」バグを現実的にします。
- **Side effects** – 遅延は悪意のあるパスのみに影響するため、システム全体のパフォーマンスは通常影響を受けません。namespace の成長を監視していない限り、防御側が気づくことは稀です。
- **Cleanup** – 作成した各ディレクトリ/オブジェクトのハンドルを保持しておき、後で `NtMakeTemporaryObject`/`NtClose` を呼び出せるようにします。そうしないと、無制限のディレクトリチェーンが再起動後も残る可能性があります。

## 防御上の注意

- named objects に依存するカーネルコードは、open の後にセキュリティに敏感な状態を再検証するか、チェックの前に参照を取るべきです（TOCTOU ギャップを閉じる）。
- ユーザー制御の名前をデリファレンスする前に OM パスの深さ/長さに上限を設けてください。過度に長い名前を拒否することで攻撃者をマイクロ秒のウィンドウに戻すことができます。
- object manager の namespace 増加を計測する（ETW `Microsoft-Windows-Kernel-Object`）ことで、`\BaseNamedObjects` 以下の数千コンポーネントに及ぶチェーンのような不審な増加を検出します。

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
