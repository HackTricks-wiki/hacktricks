# Object Manager Slow Paths を利用したカーネルのレース条件の悪用

{{#include ../../banners/hacktricks-training.md}}

## レースウィンドウを伸ばすことが重要な理由

多くの Windows カーネル LPE は古典的なパターン `check_state(); NtOpenX("name"); privileged_action();` に従います。最新のハードウェアではコールドな `NtOpenEvent`/`NtOpenSection` が短い名前を約 ~2 µs で解決するため、検査済み状態を反転させる時間はほとんど残りません。ステップ2 の Object Manager Namespace (OMNS) の lookup を意図的に数十マイクロ秒かかるように遅延させることで、攻撃者は何千回もの試行を必要とせずに、従来は不安定だったレースに一貫して勝てるだけの時間を稼げます。

## Object Manager lookup の内部（概要）

* **OMNS structure** – `\BaseNamedObjects\Foo` のような名前はディレクトリごとに解決されます。各コンポーネントでカーネルは *Object Directory* を見つけ／開き、Unicode 文字列を比較します。途中でシンボリックリンク（例：ドライブレター）が辿られることがあります。
* **UNICODE_STRING limit** – OM パスは `UNICODE_STRING` に格納され、その `Length` は 16-bit 値です。絶対上限は 65 535 バイト（32 767 UTF-16 codepoints）です。`\BaseNamedObjects\` のようなプレフィックスを考慮しても、攻撃者は約 32 000 文字を制御できます。
* **Attacker prerequisites** – 任意のユーザが `\BaseNamedObjects` のような書き込み可能なディレクトリ配下にオブジェクトを作成できます。脆弱なコードがその中の名前を使うか、そこに到達するシンボリックリンクを辿ると、攻撃者は特別な権限なしに lookup の性能を制御できます。

## Slowdown primitive #1 – Single maximal component

コンポーネントの解決コストは長さに概ね線形で、カーネルは親ディレクトリ内の全エントリに対して Unicode 比較を行う必要があるためです。32 kB 長の名前を持つイベントを作成すると、`NtOpenEvent` のレイテンシは即座に約 ~2 µs から ~35 µs（Windows 11 24H2、Snapdragon X Elite テスト環境）に増加します。
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*実用的な注意事項*

- 任意の名前付きカーネルオブジェクト（events, sections, semaphores…）を使って長さ制限に達することができます。
- Symbolic links や reparse points を使って短い “victim” 名をこの巨大なコンポーネントに指すようにすれば、スローダウンは透過的に適用されます。
- すべてが user-writable namespaces に存在するため、payload は standard user integrity level からでも動作します。

## Slowdown primitive #2 – Deep recursive directories

より攻撃的な変種では、何千ものディレクトリの連鎖（`\BaseNamedObjects\A\A\...\X`）を割り当てます。各ホップで directory resolution logic（ACL checks, hash lookups, reference counting）がトリガーされるため、各レベルのレイテンシは単一の文字列比較よりも大きくなります。~16 000 レベル（同じ `UNICODE_STRING` サイズにより制限）では、経験的なタイミングが長い単一コンポーネントで達成された35 µsの壁を上回ります。
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

* 親ディレクトリが重複を拒否し始めたら、各レベルで文字を交互にする（`A/B/C/...`）。
* ネームスペースを汚染しないよう、エクスプロイト後にチェーンをクリーンに削除できるようハンドル配列を保持する。

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

Object directories はエントリ用に **shadow directories**（フォールバックルックアップ）とバケット化されたハッシュテーブルをサポートしている。これら両方と64コンポーネントのsymbolic-link reparse制限を悪用し、`UNICODE_STRING` 長を超えずに遅延を増幅する:

1. `\BaseNamedObjects` の下に2つのディレクトリを作成する。例: `A`（shadow）と `A\A`（target）。2つ目は1つ目をshadow directoryとして作成する（`NtCreateDirectoryObjectEx` を使用）ことで、`A` で見つからないルックアップが `A\A` にフォールスルーするようにする。
2. 各ディレクトリに同じハッシュバケットに入る何千もの **colliding names** を詰める（例: 末尾の数字を変えても同じ `RtlHashUnicodeString` 値を保つ）。これによりルックアップは単一ディレクトリ内で O(n) の線形スキャンに劣化する。
3. 約63個の **object manager symbolic links** のチェーンを構築し、長い `A\A\…` サフィックスに繰り返し reparse させて reparse 予算を消費する。各 reparse はパースを先頭から再開するため、collision のコストが乗算される。
4. 最終コンポーネント（`...\\0`）のルックアップは、各ディレクトリに16,000の collisions がある場合、Windows 11 上で数分（**minutes**）かかるようになり、ワンショットのカーネル LPE に対して事実上確実なレース勝利をもたらす。
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Why it matters*: 数分に及ぶ遅延は、一度の試行で成功するレースベースのLPEsを決定論的なエクスプロイトに変える。

### 2025 retest notes & ready-made tooling

- James Forshaw は Windows 11 24H2 (ARM64) 上でタイミングを更新してこの手法を再公開した。ベースラインの open は約2 µs のままで、32 kB のコンポーネント追加で約35 µs に増加し、shadow-dir + collision + 63-reparse chains では依然として約3分に達することが確認され、プリミティブが現行ビルドでも有効であることが裏付けられた。ソースコードとパフォーマンスハーネスは更新された Project Zero のポストに含まれている。
- 公開されている `symboliclink-testing-tools` バンドルを使ってセットアップをスクリプト化できる: `CreateObjectDirectory.exe` で shadow/target ペアを生成し、`NativeSymlink.exe` をループで実行して 63-hop chain を生成する。これにより手書きの `NtCreate*` ラッパーを回避でき、ACLs が一貫する。

## Measuring your race window

exploit 内に簡易ハーネスを組み込み、ターゲットのハードウェアでウィンドウがどれだけ広がるかを測定しよう。下のスニペットはターゲットオブジェクトを `iterations` 回オープンし、`QueryPerformanceCounter` を使って1回あたりの平均オープン時間を返す。
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
結果はレースのオーケストレーション戦略に直接反映されます（例：必要なワーカースレッド数、スリープ間隔、共有状態をいつ反転させるか）。

## 攻撃ワークフロー

1. **脆弱な open を特定する** – カーネル経路をトレースする（symbols、ETW、ハイパーバイザトレース、リバースなど）と、攻撃者が制御できる名前やユーザ書込み可能なディレクトリ内のシンボリックリンクを走査する `NtOpen*`/`ObOpenObjectByName` 呼び出しが見つかることがあります。
2. **その名前を遅延パスに置き換える**
- `\BaseNamedObjects`（または別の書き込み可能な OM ルート）配下に長いコンポーネントやディレクトリ連鎖を作成します。
- カーネルが期待する名前が遅延パスに解決されるようシンボリックリンクを作成します。元のターゲットに触れずに脆弱なドライバのディレクトリ検索を自分の構造へ向けることができます。
3. **レースを発生させる**
- スレッドA（被害側）が脆弱なコードを実行し、遅いルックアップの内部でブロックされます。
- スレッドB（攻撃側）がスレッドAが占有している間に保護された状態を反転させます（例：ファイルハンドルを差し替える、シンボリックリンクを書き換える、オブジェクトのセキュリティを切り替える）。
- スレッドA が再開して特権操作を行うと、古い状態を参照して攻撃者制御下の操作を実行します。
4. **クリーンアップ** – 疑わしい痕跡を残したり正当な IPC 利用者を壊したりしないよう、ディレクトリ連鎖とシンボリックリンクを削除します。

## 運用上の考慮点

- **プリミティブの組み合わせ** – ディレクトリ連鎖の各レベルで長い名前を使うことで、`UNICODE_STRING` サイズが尽きるまでさらに遅延を伸ばせます。
- **ワンショットバグ** – 拡張されたウィンドウ（数十マイクロ秒〜数分）は、CPU affinity の固定やハイパーバイザ支援のプリエンプションと組み合わせると「単一トリガー」バグを現実的にします。
- **副作用** – 遅延は悪意あるパスにのみ影響するため、システム全体のパフォーマンスには影響しません。名前空間の増大を監視していない限り、防御側が気づくことは稀です。
- **後片付け** – 作成した各ディレクトリ/オブジェクトのハンドルを保持しておき、後で `NtMakeTemporaryObject`/`NtClose` を呼べるようにします。そうしないと再起動後も終わりのないディレクトリ連鎖が残る可能性があります。
- **ファイルシステムの競合** – 脆弱なパスが最終的に NTFS を経由して解決されるなら、OM の遅延中にバックエンドファイル上に Oplock（例：同ツールキットの `SetOpLock.exe`）を積み重ねておき、OM グラフを変更することなくコンシューマを追加のミリ秒単位で停止させることができます。

## 防御上のメモ

- 名前付きオブジェクトに依存するカーネルコードは、open の後にセキュリティに敏感な状態を再検証するか、チェックの前に参照を取得して TOCTOU ギャップを閉じるべきです。
- ユーザ制御の名前を逆参照する前に OM パスの深さ/長さの上限を強制します。長すぎる名前を拒否することで攻撃者をマイクロ秒のウィンドウへ戻すことができます。
- オブジェクトマネージャの名前空間の成長（ETW `Microsoft-Windows-Kernel-Object`）を計測して、`\BaseNamedObjects` の下で数千コンポーネントに達するような疑わしい連鎖を検出してください。

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
