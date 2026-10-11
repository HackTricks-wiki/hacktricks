# SUID、SGID、ACL、および機密ファイル

{{#include ../../banners/hacktricks-training.md}}

SUID と SGID は、実行されるファイルの実効IDを変更します。ACL は、通常の `ls -l` のモードビットには表示されないアクセス権を付与できます。ユーザーが、見かけ上の所有者とグループのアクセス権限から想定される以上の読み取り、書き込み、または実行を行える場合は、両方を確認してください。

## 特権付き実行ファイルを列挙する

```bash
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
findmnt -no TARGET,OPTIONS
getcap -r / 2>/dev/null
```

カスタムまたは最近変更された実行ファイル、通常とは異なる所有者、書き込み可能なマウント上のファイルに注目します。`nosuid` マウントでは set-ID の動作が抑制されることがあります。file capabilities は別の権限昇格の仕組みであり、[Linux capabilities](linux-capabilities.md) で説明されています。不審なバイナリをパッケージ内のものと比較し、昇格した ID で何を実行、オープン、またはロードするかを確認します。

呼び出し元の入力を受け付ける、見慣れない root 所有の SUID 実行ファイルについては、オフラインでバイナリのコピーを調べ、メモリ安全でない引数処理と、そこに到達するコードパスを確認します。実効 ID の動作や、stack canaries、実行不可メモリ、位置独立コード、アドレスランダム化などの緩和策を記録します。危険な関数名や緩和策の欠如は、あくまで調査の手がかりです。悪用可能かどうかは、実際の入力範囲、到達可能な制御フロー、障害発生時の実効 ID に左右されます。受動的な列挙中にクラッシュを試すだけの目的で、稼働中の特権実行ファイルに長い引数を渡してはいけません。

見慣れた SUID プログラム自体が置き換えられたり、バックドアを仕込まれたりしている場合もあります。更新時刻が最近であることは手がかりにはなりますが、証拠ではありません。**特定の不審なパッケージ済みバイナリ**については、所有パッケージを特定し、日常的な列挙中にすべてのパッケージを検証するのではなく、インストール済みファイルをパッケージメタデータと比較します。

```bash
dpkg -S /usr/bin/passwd                  # Debian-family: identify the owner
dpkg --verify passwd                     # Verify only that package
rpm -V --noscripts -f /usr/bin/passwd    # RPM-family: owning package, no verify scriptlets
```

`dpkg --verify` は、パッケージデータベースにチェックサムが記録されているファイルについてのみ内容を確認します。RPM はモードや所有者などのメタデータも比較します。**特権実行ファイル自体**の不一致に注目してください。同じパッケージ内の別ファイルについて、インストール時にドキュメントやロケールファイルが省かれていると、これらの欠落が報告されることがあります。不審な実行ファイルを信頼できるベンダーパッケージと比較し、変更されたコードを正確に確認してください。正当なローカル変更、チェックサムの欠落、侵害されたパッケージメタデータがある場合、どちらのコマンドで証明できることにも限界があります。受動的なトリアージの一環として、不審な SUID プログラムもパッケージ検証スクリプトも実行しないでください。[dpkg verification manual](https://manpages.debian.org/bookworm/dpkg/dpkg.1.en.html) と [RPM verification manual](https://rpm.org/docs/4.20.x/man/rpm.8) を参照してください。

書き込み可能なパスにある shell、相対パス指定のコマンド、またはライブラリを呼び出す SUID プログラムは、信頼境界を越える可能性があります。[SUID shared-library and linker abuse](suid-shared-library-and-linker-abuse.md)、[PATH guidance](../linux-basics/linux-environment-variables.md#path)、[user-ID explanation](../user-information/euid-ruid-suid.md) を参照してください。コマンド固有の既知のエスケープについては、ホスト上で許可されている正確なバイナリと呼び出し方を [GTFOBins](https://gtfobins.github.io/) で確認してください。

set-user-ID 実行ファイルでは、呼び出し元の **real UID** とファイル所有者の **effective UID** を区別してください。[`execve(2)`](https://man7.org/linux/man-pages/man2/execve.2.html) は real UID を変更せず、set-ID による変更後の effective UID を saved UID にコピーします。[`system(3)`](https://man7.org/linux/man-pages/man3/system.3.html) は `/bin/sh -c` を通じてコマンドを実行します。このパスで選択される shell によって、子プロセスが effective identity を保持するかどうかが変わります。特に、[Bash privileged-mode rules](https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html) により、Bash が `-p` なしで起動し、effective UID と real UID が異なる場合、effective UID は real UID にリセットされます。実際の helper による UID の変更と子プロセスの呼び出し方に加え、所有者、実行権限、mount の `nosuid` 設定、プロセスの `no_new_privs` 状態を確認してください。SUID bit や shell 呼び出しだけでは、利用可能な特権昇格があるとは証明できません。

root 所有の珍しい SUID `jjs` が見つかり、現在のユーザーが実行できる場合は、別途ファイルアクセスを確認してください。旧式の Nashorn ツールは、起動した shell の effective UID が下がる場合でも、Java の file API にアクセスできます。特権付きの読み書きとみなす前に、インストール済み JVM の挙動、ファイル操作時の effective identity、`nosuid` / `no_new_privs` を確認してください。[Oracle removed `jjs` in JDK 15](https://docs.oracle.com/en/java/javase/21/migrate/removed-tools-and-components.html)。インストール済みのパスには、古いビルドや別途パッケージされたビルドが残っている場合があります。[GTFOBins documents the file APIs](https://gtfobins.org/gtfobins/jjs/) にファイル API の説明がありますが、sudo の例はすべてのビルドで SUID が機能することを示すものではありません。受動的な列挙中にこのツールを実行しないでください。

root 所有の SUID `gosu` 実行ファイルに低権限ユーザーがアクセスできる場合は、確認が必要です。公開されているインターフェースは対象ユーザーとコマンドを受け取りますが、通常のコンテナ用途では root として起動し、権限を落とします。インストール済みビルドの SUID 動作、effective identity と user namespace のマッピングに加え、`nosuid` と `no_new_privs` を確認してください。コンテナ内の root がホストの root であるとは限りません。ファイル名や SUID bit だけでは、実際に権限が移行する証拠になりません。[upstream usage](https://github.com/tianon/gosu) と [maintainer's SUID warning](https://github.com/tianon/gosu/issues/11) を参照してください。受動的なインベントリ作成中にこの helper を実行しないでください。

カスタムの set-user-ID backup wrapper が呼び出し元指定のパスを受け取り、それを `system(3)` に渡す archive コマンドへ埋め込む場合があります。組み立てたコマンド内でパスが引用符で囲まれていないと、子 shell は[チルダ展開（`HOME` を使用）、`?` や `*` などの pathname pattern、改行によるコマンド区切り](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html)を適用できます。よく知られた句読点だけを denylist で拒否しても、パスが文字どおり扱われる保証にはなりません。正確な引数の流れ、継承される環境、子 shell と effective identity、ファイルシステムアクセス、archive の出力が呼び出し元に見えるかを確認してください。SUID bit、archive tool の文字列、または `/root` という文字列が拒否されたことだけでは、情報開示もコード実行も証明できません。受動的な列挙中にプライベートファイルを archive したり、クラッシュを引き起こす入力を送信したりせず、wrapper のコピーをオフラインで確認してください。

`$(...)` のような shell の[コマンド置換](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html)も、メタ文字 denylist の抜け穴になり得ます。固定されたコマンド接頭辞が許可されていても、後続の呼び出し元指定引数が `/bin/sh -c` に渡される場合があります。正確な引用符処理、parser、effective identity をオフラインで確認してください。`system()` に渡す文字列や不完全な denylist だけを根拠に、コード実行が可能だと判断しないでください。

**呼び出し元のプロセスツリー**も重要です。Web worker が UID 変更システムコールを制限する seccomp filter を設定している場合があります。[seccomp filter は子プロセスに引き継がれ、`execve` 後も維持されます](https://docs.kernel.org/userspace-api/seccomp_filter.html)。たとえば、Apache の [mpm-itk `LimitUIDRange` と `LimitGIDRange` ディレクティブ](https://sources.debian.org/src/mpm-itk/2.4.7-04-2/mpm_itk.c/)は、子孫プロセスがなれる identity を制限できます。`/proc/self/status` の `Seccomp: 2` は filter のモードを示すだけで、ポリシーや、この helper が所有者の identity を取得できるかどうかは示しません。実際の呼び出し元の系譜と effective filter を、SUID、mount、`no_new_privs` の条件とあわせて確認してください。別の login session では異なるポリシーが適用される場合がありますが、その session にも有効なアクセス経路が必要です。

カスタム SUID 実行ファイルが、別の読み取り可能な Python script を呼び出す場合があります。実際に **Python 2** を使用しているなら、[`input()` は入力された式を評価します](https://docs.python.org/2/library/functions.html#input)。Python 3 の `input()` はテキストを返します。そのソース行が実行経路になると判断する前に、wrapper の effective identity、interpreter のパスとバージョン、script のパス、信頼できない入力がその呼び出しに届くかを確認してください。script 自体の set-ID bit や、特権 wrapper を介さない `input()` 呼び出しでは、同じ境界が成立するとは限りません。列挙中に実行せず、バイナリが参照するパスと範囲を限定した script のソースを確認してください。

珍しい SUID 実行ファイルに読み取り可能なソースが付属している場合、呼び出し元が指定する各ファイル読み込みの要求バイト数と宛先バッファのサイズを比較し、その後の制御フロー上のチェックを調べてください。[`fread(3)`](https://man7.org/linux/man-pages/man3/fread.3.html) は指定されたポインタに要求された item を格納しますが、宛先オブジェクトの容量は把握しません。サイズの不一致は、静的なメモリ安全性の調査材料であり、利用可能な特権昇格の証明ではありません。ソースがインストール済みバイナリと一致すること、呼び出し元が入力を提供できること、その状況で SUID 実行が有効であること、該当する経路に到達できることを確認してください。列挙中に特権プログラムへクラッシュを引き起こす入力を送信せず、範囲を限定したソースまたはバイナリのコピーをオフラインで確認してください。

カスタム SUID helper は、内容を表示せずに保護されたファイルの情報を漏らす場合があります。呼び出し元がパス名と regular expression の両方を選択でき、helper が effective UID で可視の一致件数を返す場合、アンカー付き prefix test が1文字ずつ調べる oracle になる可能性があります。helper の所有者、effective-ID の挙動、実行権限、パス名の制限、regex の意味、応答の可視性、呼び出し元が他の手段では読み取れない具体的な高権限ファイルを確認してください。SUID bit や regex library の文字列だけでは、いずれの動作も証明できません。受動的な列挙では、珍しい実行ファイルを記録し、範囲を限定した逆アセンブルまたはソースのコピーを確認してください。稼働中の helper に推測値を繰り返し入力したり、復元した秘密を表示したりしないでください。

OpenBSD では、呼び出し元が指定するパス名を受け取るカスタム set-user-ID reader は、effective identity で読み取り可能な `/var/backups` 内のファイルにアクセスし、内容を呼び出し元へ返す可能性があります。[OpenBSD's `changelist(5)`](https://man.openbsd.org/changelist.5) は、設定されたパスの `.current` と `.backup` のコピーについて説明しています。ただし、`+` が付いたエントリにはファイル内容ではなく SHA-256 checksum が保存されます。backup directory は root 所有で、モード `0700` である必要があります。`/var` に対する helper の [`unveil` read rule](https://man.openbsd.org/unveil.2) は、そのパス配下へのアクセスを許可することがありますが、それだけでファイルアクセスが付与される、または証明されるわけではありません。特権昇格を主張する前に、実際の effective UID、現在のユーザーに対する実行権限、許可されるパス、backup の存在と内容、独立した認証要件の有無を確認してください。受動的な列挙では、helper とパスのメタデータを報告し、reader を実行したり backup のデータを表示したりしないでください。

呼び出し元指定のパス名を [`stat(2)`](https://man7.org/linux/man-pages/man2/stat.2.html) で確認した後に開くカスタム SUID プログラムは、呼び出し元が書き込み可能なディレクトリ内のファイルまたは symlink が変更されると、競合状態が起きる可能性があります。チェック対象は先に確認したオブジェクトですが、後続の [`open(2)`](https://man7.org/linux/man-pages/man2/open.2.html) では別のオブジェクトが解決される場合があります。helper が昇格した effective identity で実行可能であること、到達可能なコード経路が選択されたファイルを読み取ること、呼び出し元が check と open の間にパス名を置き換えられることを確認してください。SUID bit、書き込み可能なディレクトリ、`stat` の文字列だけでは、これらはいずれも証明できません。情報開示の経路には、出力が見えること、または呼び出し元が読み取り可能な保存先も必要です。稼働中の helper に競合を仕掛けず、バイナリとパスのメタデータをオフラインで確認してください。

同じ依存関係の確認を SGID wrapper にも行ってください。shell または helper を絶対パスで実行する wrapper でも、低権限ユーザーがそのファイルを置き換えられる場合は危険です。起動されたコードが wrapper の effective group を継承する可能性があります。実際に呼び出されるパス、その書き込み権限（ACL を含む）、wrapper の effective group、子プロセスを起動する前に権限を落とすかどうかを確認してください。interpreter が継承した effective ID を破棄する場合もあるため、調査対象と実証済みの権限移行を区別してください。ホスト上の別の場所に書き込み可能な shell があるだけでは、特権 wrapper がそれを呼び出す証拠になりません。

### Privileged wrappers that pass SQL to the SQLite CLI

カスタム SUID プログラムがユーザー制御の SQL を **`sqlite3` command-line program** に渡す場合、クエリを読み取り専用と判断する前に、正確なコマンドと effective identity を確認してください。CLI の `edit()` SQL function は editor（第2引数または `VISUAL`）を呼び出し、SQL の `load_extension()` function は extension loading が有効な場合に shared library を読み込めます。wrapper が `PATH` を固定したり、絶対パスの `sqlite3` を使用したりしていても、これらは CLI プロセスの identity でコードが実行される可能性のある経路です。SQL が実際にこれらの function に到達し、CLI が該当機能を保持している必要があります。バイナリやホスト上に `sqlite3` が見つかっただけでは、特権昇格の証拠になりません。SQLite **library** では extension loading がデフォルトで無効になっているため、CLI と区別してください。特権アプリケーションが信頼できない SQL を処理する必要がある場合、SQLite CLI の `--safe` mode は `edit()`、`load_extension()`、その他の副作用を伴う function を無効にします。[SQLite CLI documentation](https://www.sqlite.org/cli.html#the_edit_sql_function)、[safe-mode documentation](https://www.sqlite.org/cli.html#the_safe_command_line_option)、[extension-loading documentation](https://www.sqlite.org/loadext.html#loading_an_extension) を参照してください。

### Privileged file readers that feed a verbose client

カスタム SUID/SGID wrapper は、呼び出し元が指定したパス名へのアクセスを確認してから、そのファイルを別のコマンドに渡す場合があります。アクセス確認時と後続の open 時それぞれの effective identity を確認し、`../` 要素を実際のベースディレクトリに基づいて解決し、子プロセスが無効な入力をどう処理するかを調べてください。database client がプライベートファイルを SQL として読み込み、詳細な出力を行う場合、SQL が無効でもエラーにファイル内容が表示されることがあります。子プロセスが呼び出し元には読めないファイルを読み取れること、wrapper を通じて呼び出し元がそのファイルを選択できること、出力が見えることのすべてが揃った場合にのみ、ユーザー間の情報漏えいになります。`mysql` や別の client の文字列があるだけでは、これらの条件は証明できません。

### Netdata `ndsudo` search path

[CVE-2024-32019](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93) は、一部の Netdata `ndsudo` ビルドに影響しました。root 所有の SUID helper は、呼び出し元が指定した `PATH` を使って、許可された外部コマンドを検索していました。現在のアカウントが実行できる場合に限り、通常の呼び出し元 `PATH` 外にあるものも含め、インストール済み helper を確認してください。所有者、SUID bit、実行権限（group/ACL による許可を含む）、インストール済みビルドとベンダーの patch 状況、`NoNewPrivs` または `nosuid` mount によって identity の変更が妨げられるかを確認してください。Netdata は修正済みビルドとして `v1.45.3` と `v1.45.0-169` を挙げています。ディストリビューションの backport は別途確認が必要です。dashboard のバージョンや `ndsudo` が存在することだけでは、到達可能な特権昇格の証拠になりません。この path の問題が成立するには、helper が外部コマンドを呼び出し元の制御できる場所から解決する必要もあります。

### Firejail join privilege boundary

[CVE-2022-31214](https://seclists.org/oss-sec/2022/q2/188) は、Firejail の特権付き `--join` ロジックに影響しました。細工された join target により、setuid-root helper が攻撃者の制御する mount namespace を受け入れ、安全でない security state をコピーする可能性がありました。受動的なトリアージでは、**現在の identity で root 所有の setuid Firejail バイナリを実行できること**、その mount とプロセスコンテキストで setuid が有効であること、インストール済みビルドに修正がないことを確認してください。upstream は [0.9.70](https://github.com/netblue30/firejail/releases/tag/0.9.70) で修正しました。ディストリビューションのパッケージでは、古いバージョンが表示されても[修正が backport されている場合があります](https://github.com/netblue30/firejail/issues/5191)。これらの前提条件は調査対象を示すものであり、join の成功や root shell を証明するものではありません。列挙中に偽の jail を作成したり、`--join` を実行したりしないでください。

### GNU Screen logfile permissions

[CVE-2017-5618](https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00026.html) は、Screen 4.5.0 が呼び出し元指定の logfile を昇格した権限で開く問題でした。SUID インベントリにある `screen` またはバージョン番号付きバイナリは、調査の手掛かりにすぎません。root 所有であること、現在のユーザーによる実効的な SUID 実行、インストール済みビルドとディストリビューションの patch 状況、影響を受ける logfile の挙動を確認してください。[Debian は 4.5.0 パッケージに backport を適用して修正しました](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=852484)。そのため、バージョン文字列やファイル名だけでは脆弱性を証明できません。通常の列挙調査として logfile を作成しないでください。

[CVE-2017-5899](https://ubuntu.com/security/CVE-2017-5899) は、呼び出し元が制御するパス要素がディレクトリをたどり、任意のファイル書き込みにつながる可能性がある、特権付き S-nail mail-lock helper の問題でした。現在のユーザーがインストール済みの root 所有 setuid helper を実行できるか、mount とプロセスポリシーのもとで setuid identity が有効か、正確なパッケージビルドとベンダー修正を確認してください。[Ubuntu's security notice](https://ubuntu.com/security/notices/USN-4820-1) には、16.04 のパッケージ向け backport 修正が記載されているため、upstream のバージョンに見えるというだけでは判断できません。helper の存在は、影響を受けるパスに到達できることや、ファイル書き込みが root での実行につながることを証明しません。列挙中に helper を実行したり競合を試したりせず、メタデータとパッケージの状態を確認してください。

### snap-confine and tmpfiles cleanup

CVE-2026-3888 は、特権付き `snap-confine` と systemd-tmpfiles による `/tmp` の cleanup の間の競合です。受動的な確認では、`snap-confine` が setuid か file capabilities を持つか、インストール済み `snapd` パッケージを**該当する Ubuntu release**の修正済みバージョンと比較し、実効的な `/tmp` の期限ルールと cleanup timer を調べられます。パッケージとルールが一致することは前提条件であり、競合に到達できる証明ではありません。実行時の timer 状態、snap の layout、パッケージの backport、ルールの上書きも影響します。古い release では、デフォルト以外の設定が必要な場合があります。通常の列挙中に競合を試す probe を実行しないでください。release ごとのパッケージ状態については [Ubuntu CVE record](https://ubuntu.com/security/CVE-2026-3888)、コンポーネント間の相互作用については [Qualys advisory](https://blog.qualys.com/vulnerabilities-threat-research/2026/03/17/cve-2026-3888-important-snap-flaw-enables-local-privilege-escalation-to-root) を参照してください。

## Inspect ACLs and sensitive paths

```bash
getfacl -p /path/to/file /path/to/parent 2>/dev/null
namei -l /path/to/file
find /etc /opt /var -type f -writable -ls 2>/dev/null | head -80
ls -la /etc/sudoers.d /etc/ld.so.preload /etc/ld.so.conf.d 2>/dev/null
```

書き込み可能な親ディレクトリがあると、ファイル自体が root 所有でも置き換えられる場合があります。ACL によって、sudoers の drop-in、service unit、cron script、library path、credential file へのアクセスがひそかに許可されていることもあります。ACL とパス全体の両方を確認してください。特権ファイルへの任意の書き込みが可能な場合は、[Arbitrary File Write to Root](write-to-root.md) を参照してください。リンカー設定と preload のケースについては、[`ld.so` example](ld.so.conf-example.md) を参照してください。露出したバックアップ、`.env` ファイル、データベース設定、SSH 関連ファイル、履歴は、各ファイルの実際の権限に応じてアクセスできる、credential の入手元となる可能性があります。
{{#include ../../banners/hacktricks-training.md}}
