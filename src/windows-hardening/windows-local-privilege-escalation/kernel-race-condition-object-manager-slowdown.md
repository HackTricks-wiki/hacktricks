# Object Manager のスローパスを利用したカーネル競合状態の悪用

{{#include ../../banners/hacktricks-training.md}}

## 競合ウィンドウを広げることが重要な理由

Many Windows kernel LPEs follow the classic pattern `check_state(); NtOpenX("name"); privileged_action();`. 最新のハードウェアでは、コールドな `NtOpenEvent`/`NtOpenSection` は短い名前を約2 µsで解決するため、セキュアな操作が行われる前にチェック済みの状態を反転させる余裕はほとんどありません。ステップ2の Object Manager Namespace (OMNS) のルックアップを意図的に数十µsに遅延させることで、攻撃者は数千回の試行を要さずとも、従来は不安定だったレースに一貫して勝てるだけの時間を稼げます。

## Object Manager のルックアップ内部（概要）

* **OMNS structure** – `\BaseNamedObjects\Foo` のような名前はディレクトリごとに解決されます。各コンポーネントでカーネルは *Object Directory* を見つけて開き、Unicode 文字列を比較します。経路上でシンボリックリンク（例: ドライブ文字）が横断されることがあります。
* **UNICODE_STRING limit** – OM パスは `UNICODE_STRING` 内に格納され、その `Length` は 16-bit の値です。絶対的な上限は 65 535 バイト（32 767 UTF-16 コードポイント）です。`\BaseNamedObjects\` のようなプレフィックスを含めても、攻撃者はおよそ ≈32 000 文字を制御できます。
* **Attacker prerequisites** – 任意のユーザが `\BaseNamedObjects` のような書き込み可能なディレクトリの下にオブジェクトを作成できます。脆弱なコードがその内部の名前を使うか、そこに到達するシンボリックリンクを辿る場合、攻撃者は特別な権限なしにルックアップの性能を制御できます。

## Slowdown primitive #1 – Single maximal component

コンポーネントを解決するコストは長さに概ね線形で、カーネルが親ディレクトリ内の全エントリに対して Unicode 比較を行う必要があるためです。32 kB の長い名前を持つイベントを作成すると、`NtOpenEvent` のレイテンシが Windows 11 24H2 (Snapdragon X Elite testbed) で約2 µsから約35 µsに即座に増加します。
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*実用的な注意*

- 任意の named kernel object (events, sections, semaphores…) を使って長さ制限に達することができます。
- Symbolic links や reparse points を使って短い “victim” 名をこの巨大なコンポーネントに向ければ、スローダウンを透過的に適用できます。
- すべてが user-writable namespaces に存在するため、payload は standard user integrity level からでも機能します。

## Slowdown primitive #2 – Deep recursive directories

より攻撃的な変種は何千ものディレクトリのチェーン（`\BaseNamedObjects\A\A\...\X`）を割り当てます。各ホップは directory resolution logic (ACL checks, hash lookups, reference counting) をトリガーするため、各レベルのレイテンシは単一の文字列比較よりも大きくなります。約16,000レベル（同じ `UNICODE_STRING` サイズで制限される）では、実測で長い単一コンポーネントが達成する35 µsの壁を超えます。
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

* 親ディレクトリが重複を拒否し始めたら、各レベルで文字を切り替える（`A/B/C/...`）。
* ハンドル配列を保持して、exploitation後にチェーンをクリーンに削除し、名前空間を汚染しないようにする。

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses（マイクロ秒ではなく分単位）

オブジェクトディレクトリは **shadow directories**（fallback lookups）と、エントリ用のバケット化されたハッシュテーブルをサポートしている。これら両方と64コンポーネントのsymbolic-link reparse制限を悪用して、`UNICODE_STRING`長を超えずに遅延を倍増させる:

1. `\BaseNamedObjects` の下に2つのディレクトリを作成する。例: `A`（shadow） と `A\A`（target）。2つ目は最初のものをshadow directoryとして作成する（`NtCreateDirectoryObjectEx` を使用）。これにより、`A`で見つからないルックアップは `A\A` にフォールスルーする。
2. 各ディレクトリを、同じハッシュバケットに入る何千もの **colliding names** で埋める（例: 末尾の数字を変えつつ同じ `RtlHashUnicodeString` 値を維持する）。これによりルックアップは単一ディレクトリ内で O(n) の線形走査に劣化する。
3. 約63個の **object manager symbolic links** のチェーンを構築し、長い `A\A\…` サフィックスへ何度も reparse させて reparse 予算を消費させる。各 reparse はパースを先頭から再開するため、衝突コストが乗算される。
4. 最終コンポーネント（`...\\0`）のルックアップは、各ディレクトリに16 000の衝突がある場合、Windows 11で**分単位**を要するようになり、one-shot kernel LPEs に対して実質的に確実なレース勝利を提供する。
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*なぜ重要か*: 数分単位の遅延は、one-shot race-based LPEs を決定的な exploits に変える。

## レースウィンドウの測定

exploit の内部に簡易ハーネスを組み込み、被害者ハードウェア上でウィンドウがどれだけ大きくなるかを測定する。以下のスニペットはターゲットオブジェクトを`iterations`回オープンし、`QueryPerformanceCounter`を使って1回あたりの平均オープンコストを返す。
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
The results feed directly into your race orchestration strategy (e.g., number of worker threads needed, sleep intervals, how early you need to flip the shared state).

## エクスプロイトのワークフロー

1. **Locate the vulnerable open** – カーネル経路をトレース（via symbols, ETW, hypervisor tracing, or reversing）し、攻撃者が制御する名前やユーザー書き込み可能ディレクトリ内のシンボリックリンクを辿る `NtOpen*`/`ObOpenObjectByName` 呼び出しを見つける。
2. **Replace that name with a slow path**
- `\BaseNamedObjects`（または別の書き込み可能な OM root）の下に長いコンポーネントやディレクトリチェーンを作成する。
- カーネルが期待する名前がスローパスに解決するようにシンボリックリンクを作成する。元のターゲットに触れずに脆弱なドライバのディレクトリ検索を自分の構造に向けられる。
3. **Trigger the race**
- Thread A (victim) が脆弱なコードを実行し、スローなルックアップの内部でブロックする。
- Thread B (attacker) は Thread A が占有されている間に guarded state を反転させる（例：ファイルハンドルを入れ替える、シンボリックリンクを書き換える、オブジェクトセキュリティを切り替える）。
- Thread A が再開して特権操作を実行すると、古い状態を参照して攻撃者が制御する操作を行う。
4. **Clean up** – 疑わしい痕跡を残したり正当な IPC 利用者を破壊したりしないよう、ディレクトリチェーンとシンボリックリンクを削除する。

## 運用上の考慮点

- **Combine primitives** – ディレクトリチェーンの各レベルで長い名前を使うことで、`UNICODE_STRING` サイズが尽きるまでさらに高いレイテンシを得られる。
- **One-shot bugs** – 拡張された窓（数十マイクロ秒から数分）は、CPU affinity pinning や hypervisor-assisted preemption と組み合わせると “single trigger” バグを現実的にする。
- **Side effects** – スローダウンは悪意あるパスにのみ影響するため、システム全体のパフォーマンスにはほとんど影響がない。防御側が namespace growth を監視していない限り気付くことは稀である。
- **Cleanup** – 作成した各ディレクトリ／オブジェクトのハンドルを保持しておき、後で `NtMakeTemporaryObject`/`NtClose` を呼べるようにすること。そうしないと無限に続くディレクトリチェーンが再起動を跨いで残存する可能性がある。

## 防御に関する注意点

- 名前付きオブジェクトに依存するカーネルコードは、open の後でセキュリティに敏感な状態を再検証するか、チェックの前に参照を取得して TOCTOU ギャップを塞ぐべきである。
- ユーザー制御の名前をデリファレンスする前に OM パスの深さ／長さの上限を強制する。過度に長い名前を拒否することで攻撃者をマイクロ秒単位のウィンドウに押し戻せる。
- オブジェクトマネージャの namespace growth を計測（ETW `Microsoft-Windows-Kernel-Object`）して、`\BaseNamedObjects` 以下で数千コンポーネントに及ぶような疑わしいチェーンを検出する。

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
