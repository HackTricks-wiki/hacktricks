# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## なぜレース窓を伸ばすことが重要か

多くのWindowsカーネルLPEは古典的なパターン `check_state(); NtOpenX("name"); privileged_action();` に従います。最新のハードウェアでは、コールドな `NtOpenEvent`/`NtOpenSection` が短い名前を約2 µsで解決するため、セキュアな操作が実行される前にチェック済みの状態を反転させる時間がほとんど残りません。ステップ2の Object Manager Namespace (OMNS) のルックアップを故意に数十マイクロ秒かかるように遅延させることで、攻撃者は数千回の試行を必要とせずに、通常は不安定なレースに一貫して勝てるだけの時間を得られます。

## Object Manager lookup internals in a nutshell

* **OMNS structure** – `\BaseNamedObjects\Foo` のような名前はディレクトリごとに解決されます。各コンポーネントでカーネルが *Object Directory* を検索/オープンし、Unicode 文字列を比較します。経路上でシンボリックリンク（例えばドライブ文字）が辿られることがあります。
* **UNICODE_STRING limit** – OM パスは `Length` が16ビット値の `UNICODE_STRING` 内に格納されます。絶対上限は 65 535 バイト（32 767 UTF-16 codepoints）です。`\BaseNamedObjects\` のようなプレフィックスを含めても、攻撃者は約32 000文字を制御できます。
* **Attacker prerequisites** – 任意のユーザーが `\BaseNamedObjects` のような書き込み可能なディレクトリ配下にオブジェクトを作成できます。脆弱なコードがその内部の名前を使うか、そこで終わるシンボリックリンクを辿る場合、攻撃者は特別な権限なしにルックアップの実行時間を制御できます。

## Slowdown primitive #1 – Single maximal component

コンポーネントを解決するコストは、その長さにほぼ線形に比例します。これはカーネルが親ディレクトリ内の全エントリに対してUnicode比較を行う必要があるためです。32 kB長の名前を持つイベントを作成すると、`NtOpenEvent` のレイテンシが約2 µsから約35 µsに即座に増加します（Windows 11 24H2 (Snapdragon X Elite testbed)）。
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*実用上の注意*

- 任意の named kernel object (events, sections, semaphores…) を使って長さの上限に達することができます。
- Symbolic links や reparse points は短い “victim” 名をこの巨大なコンポーネントに向けることで、slowdown を透過的に適用できます。
- すべてが user-writable namespaces に存在するため、payload は standard user integrity level で動作します。

## Slowdown primitive #2 – Deep recursive directories

より積極的なバリエーションは、何千ものディレクトリのチェーンを割り当てます (`\BaseNamedObjects\A\A\...\X`)。各ホップはディレクトリ解決ロジック（ACL checks、hash lookups、reference counting）を呼び出すため、レベルごとのレイテンシは単一の文字列比較より大きくなります。約16 000レベル（同じ `UNICODE_STRING` サイズにより制限）では、実測のタイミングが長い単一コンポーネントで達成された35 µsの壁を超えます。
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

* 親ディレクトリが重複を受け付けなくなった場合は、レベルごとに文字を交互に変更してください（`A/B/C/...`）。
* エクスプロイト後にチェーンをクリーンに削除して名前空間を汚染しないよう、ハンドル配列を保持してください。

## レースウィンドウの測定

エクスプロイト内に簡易ハーネスを組み込んで、対象マシンのハードウェア上でレースウィンドウがどれくらい拡大するかを測定します。以下のスニペットはターゲットオブジェクトを`iterations`回オープンし、`QueryPerformanceCounter`を使用して1回のオープンあたりの平均コストを返します。
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
結果は直接あなたの race orchestration strategy にフィードバックされます（例：必要な worker threads の数、sleep intervals、shared state をどれだけ早く flip する必要があるか）。

## Exploitation workflow

1. **Locate the vulnerable open** – symbols、ETW、hypervisor tracing、または reversing を介してカーネルのパスを辿り、攻撃者が制御する名前や user-writable directory にある symbolic link を歩く `NtOpen*`/`ObOpenObjectByName` 呼び出しを見つけます。
2. **Replace that name with a slow path**
- `\BaseNamedObjects`（または別の writable OM root）配下に長いコンポーネントやディレクトリチェーンを作成します。
- カーネルが期待する名前が slow path に解決されるように symbolic link を作成します。元のターゲットに触れずに、vulnerable driver の directory lookup をあなたの構造へ向けることができます。
3. **Trigger the race**
- Thread A (victim) が脆弱なコードを実行し、slow lookup 内でブロックします。
- Thread B (attacker) が Thread A が占有されている間に guarded state を flip します（例：ファイルハンドルを差し替える、symbolic link を書き換える、object security を切り替える）。
- Thread A が再開して privileged action を実行すると、stale state を観測して attacker-controlled operation を行います。
4. **Clean up** – 疑わしいアーティファクトを残したり正当な IPC ユーザーを壊したりしないよう、ディレクトリチェーンと symbolic links を削除します。

## Operational considerations

- **Combine primitives** – ディレクトリチェーンの各レベルで長い名前を使うことで、`UNICODE_STRING` サイズを使い切るまでさらに高いレイテンシを得られます。
- **One-shot bugs** – 拡張されたウィンドウ（数十マイクロ秒）は、CPU affinity pinning や hypervisor-assisted preemption と組み合わせることで “single trigger” バグを現実的にします。
- **Side effects** – この slowdown は悪意あるパスのみに影響するため、システム全体のパフォーマンスには影響せず、namespace growth を監視していない限り防御側が気付くことは稀です。
- **Cleanup** – 作成したすべてのディレクトリ/オブジェクトへのハンドルを保持しておき、後で `NtMakeTemporaryObject`/`NtClose` を呼べるようにします。さもないと無制限のディレクトリチェーンが再起動後も残る可能性があります。

## Defensive notes

- named objects に依存するカーネルコードは、open の *後に* セキュリティに敏感な状態を再検証するか、チェック前に参照を取って TOCTOU のギャップを閉じるべきです。
- user-controlled names をデリファレンスする前に OM path の深さ/長さに上限を設けてください。過度に長い名前を拒否することで攻撃者をマイクロ秒のウィンドウに戻すことができます。
- object manager の namespace growth を計測する（ETW `Microsoft-Windows-Kernel-Object`）ことで、`\BaseNamedObjects` 以下に数千コンポーネントのチェーンができているような疑わしい増加を検知できます。

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
