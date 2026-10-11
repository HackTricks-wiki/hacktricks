# シンボリックリンク、ハードリンク、ファイルディスクリプタ

{{#include ../../banners/hacktricks-training.md}}

パスは解決された時点でオブジェクトを指します。一方、オープンされたファイルディスクリプタは、パス名が変わった後もオブジェクトへの参照を保持します。この違いによって、シンボリックリンクの競合、隠れたハードリンク、削除済みファイルの復元、継承されたファイルディスクリプタからのleakが起きる理由を説明できます。inodeとマウントの背景については、[ファイルシステム、inode、復元](filesystem-inodes-and-recovery.md)を参照してください。

## リンクとパスの所有者を調べる

```bash
namei -l /path/to/privileged/input
stat -c '%D %i %h %U:%G %a %n' /path/to/file
readlink -f /path/to/link
find /path/to/tree -type l -ls 2>/dev/null
find /path/to/tree -type f -links +1 -ls 2>/dev/null
```

シンボリックリンクはパス名の解決先を変更し、ハードリンクは同じファイルシステム上の同一 inode に対する別名です。特権タスクがユーザー書き込み可能なディレクトリ内の予測可能なパスを読み書きする場合、ユーザーがそのパスを機密性の高い対象へ向けられる可能性があります。最終ファイルだけでなく、すべての親ディレクトリの所有者と権限を確認してください。`fs.protected_symlinks` と `fs.protected_hardlinks` は一般的なユーザー間攻撃を抑制しますが、書き込み可能な任意のパスを安全にするものではありません。

特権ジョブがシェルの glob を使って権限を変更する場合、glob が展開されて**コマンドライン引数**となるリンクと、再帰処理中に後から見つかるリンクを区別してください。[GNU `chmod` はコマンドライン上で指定されたシンボリックリンクの参照先に作用します](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)。一方、通常は再帰処理中に見つかったシンボリックリンクを無視します。`-R` を付けるだけでは、この2つは同じ動作になりません。実際の実行ユーザーとコマンド、信頼できないユーザーが glob に一致するエントリを作成できるか、インストール済み `chmod` の動作とオプション、提案された対象に適用される権限を確認してください。書き込み可能なディレクトリやシンボリックリンクがあるだけでは、特権による権限変更が起きるとは限りません。受動的な列挙中にリンクを配置したりジョブを実行したりせず、スクリプトとパスのメタデータを調べてください。

特権ジョブが出力するパスは、ファイル名にランダムに見えるハッシュが含まれていても予測可能な場合があります。[C の `rand()` は同じ `srand()` シードで同じシーケンスを繰り返します](https://man7.org/linux/man-pages/man3/rand.3.html)。既知の実行時刻からシードが導出される場合も同様です。さらに、ジョブがその名前の生成に呼び出し元から書き込み可能なデータベース行を読み込む場合は、行から名前への正確な変換アルゴリズム、シードと libc の動作、スケジュール、呼び出し元の行書き込み権限とディレクトリ作成権限、特権でファイルを開く前に既存のシンボリックリンクを配置できるかを確認してください。[`fopen(..., "w")` は解決後のファイルを作成または切り詰めます](https://man7.org/linux/man-pages/man3/fopen.3.html)。リンク対策の open フラグやアトミック置換の有無、実効書き込みユーザー、対象の権限、sticky ディレクトリにおけるシンボリックリンクのポリシーを実装で確認してください。予測可能な名前や書き込み可能な行があるだけでは、確認の手掛かりにしかなりません。受動的な列挙中に行を追加したりジョブを実行したりせず、コード、スケジュール、メタデータを調べてください。

別ユーザーとして動作するファイル変換サービスでは、呼び出し元が出力パスや拡張子を選べるか、変換ツールが既存の出力シンボリックリンクをたどるかを確認してください。変換ツールによってはパス名の拡張子から出力形式を選択するため、受け入れられる拡張子の名前を持つリンクが、拡張子のない機密性の高い対象を指す場合もあります。ユーザー間の書き込みが成立するには、サービスに到達できること、呼び出し元がパスとリンクを制御できること、変換ツールがリンクを出力用に開くこと、サービスの実行ユーザーに書き込み権限があることが必要です。Linux の `fs.protected_symlinks=1` は、**sticky bit が設定された全ユーザー書き込み可能ディレクトリ**内で、他ユーザーのリンクをたどる動作を制限します。通常のユーザー所有ディレクトリ内のリンクには、同じ保護は適用されません。結論を出す前に、解決後のパスと親ディレクトリの所有者を確認してください。[calibre の出力ファイルの動作](https://manual.calibre-ebook.com/generated/en/ebook-convert.html)と[Linux のシンボリックリンクポリシー](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-symlinks)を参照してください。

sudo で許可されたダウンロード用ラッパーが、呼び出し元の制御する作業ディレクトリを維持したまま、呼び出し元が選んだデータを取得する場合も、同様に出力パスを確認してください。実際のダウンローダーと、選択されたベース名、名前の衝突時の処理、既存のシンボリックリンクによって特権書き込み先を変更できるかを調べてください。URL の選択やシンボリックリンクがあるだけでは不十分です。[Axel はユーザーごとの `~/.axelrc` を文書化しています](https://github.com/axel-download-accelerator/axel/blob/master/doc/axel.txt)。また、[設定例には `default_filename` と `no_clobber` が含まれています](https://github.com/axel-download-accelerator/axel/blob/master/doc/axelrc.example)。そのため、Axel を使うラッパーは、このファイルから出力名の指定を引き継ぐ場合もあります。実効 `HOME` を確認してください。[sudo はポリシーに応じて `HOME` をリセットまたは維持できます](https://man7.org/linux/man-pages/man8/sudo.8.html)。ユーザーの `.axelrc` が関係するのは、特権ダウンローダーが実際にそれを読み込む場合だけです。受動的な列挙中にダウンロードを開始せず、ルール、ラッパー、設定ファイルのパスと権限、最終的な出力名、対象ファイルの状態を確認してください。

sudo で許可された ACL 用ラッパーでは、`setfacl` を呼び出す前に、呼び出し元が選んだファイルをどのように検証するかを確認してください。字句的な prefix の確認と `..` の拒否だけでは、許可ディレクトリ内のシンボリックリンクが外部へ解決されるのを防げません。`test -f` もリンクをたどります。ラッパーが十分な権限で ACL 操作に到達すること、呼び出し元がリンクを制御できること、適用後の ACL が対象**とその親ディレクトリ**に必要なアクセス権を与えることを確認してください。ACL に書き込み権限があるファイルや、権限が緩すぎるファイルを拒否する利用側もあります。そのため、ACL の変更だけでは実際に権限昇格につながるとは限りません。

## ユーザーがマウントした FUSE ファイルシステムへの特権書き込みを確認する

`/etc/fuse.conf` に有効な単独の `user_allow_other` 行があると、非 root ユーザーは FUSE マウントに `allow_other` または `allow_root` を指定できます。これらのマウントオプションにより、root プロセスがマウントしたユーザーによって実装されたファイルシステムにアクセスできる場合があります。sudo で許可されたヘルパーが、呼び出し元の制御する作業ディレクトリを基準に、秘密情報を含むログなどの出力を書き込む場合、そのディレクトリがユーザーのマウントした FUSE ファイルシステムである可能性を確認してください。通常のファイルシステム上では root 所有やモード `0600` に見えるファイルでも、FUSE の実装側から書き込みを監視できる場合があります。

```bash
grep -n '^[[:space:]]*user_allow_other[[:space:]]*$' /etc/fuse.conf 2>/dev/null
sudo -l
```

これは**候補**であり、情報漏えいの証拠ではありません。実際の sudo/run-as identity と引数、helper の出力先と機密情報の内容、`/dev/fuse` へのアクセス、`allow_other` または `allow_root` を指定したマウントの成功、そして特権プロセスがそのマウントに入れるかを確認してください。通常の列挙中に特権 helper を実行したり、ファイルシステムをマウントしたりしないでください。[libfuse のポリシー説明](https://github.com/libfuse/libfuse/blob/master/util/fuse.conf)と[libfuse のアクセス FAQ](https://github.com/libfuse/libfuse/wiki/FAQ#why-dont-other-users-have-access-to-the-mounted-filesystem)を参照してください。

## path race を探す

危険なパターンは、特権プログラムがあるパス名を確認した後、確認済みのオブジェクトへの安全な参照を保持せず、同じパス名を後から開くことです。親ディレクトリを制御できる攻撃者は、2つの操作の間にファイルや symlink を置き換えられます。同じ問題は、一時ファイル、timer-driven script、archive の展開、バックアップのワークフローでも発生します。影響を主張する前に、実際の読み書き操作と対象の権限を確認してください。

Archive の**作成**でも、identity をまたいでファイルが漏えいする可能性があります。Info-ZIP の `zip -r` は通常、ソースツリー内に置かれた symlink をたどり、リンク先の内容を保存します。`-y`/`--symlinks` は代わりにリンク自体を保存します。権限の低いユーザーがバックアップ対象ディレクトリにリンクを追加できる場合は、実際の archiver/options、バックアップジョブの読み取り時の identity、そのユーザーが生成された archive を読み取れるかを確認してください。書き込み可能なソースディレクトリや symlink があるだけでは、情報漏えいの証拠になりません。バックアップを実行したり、列挙中に機密情報を展開したりせず、リンクと archive の metadata を確認してください。[Info-ZIP のオプション説明](https://sources.debian.org/src/zip/3.0-3/man/zip.1/#L1638)を参照してください。

GNU `tar` のデフォルトは異なります。通常は symlink をリンクとして保存しますが、[`-h` / `--dereference` は archive 作成時にリンクをたどります](https://www.gnu.org/software/tar/manual/html_node/dereference.html)。特権で実行される定期バックアップでは、実際の `tar` 呼び出し、`tar` が読み取る前に権限の低いユーザーが入力パス名を置き換えられるか、そのユーザーが生成された archive にアクセスできるかを確認してください。書き込み可能な staging directory にある一時 checksum やその他の sidecar file は、後続の `tar -h` コマンドで明示的に指定されると、そのような入力になり得ます。race の時間幅、ジョブの identity、symlink のポリシー、その identity でのリンク先の読み取り可否、archive の ACL をすべて確認する必要があります。受動的な確認中にファイルを置き換えたり、ジョブを実行したり、機密 archive を展開したりしないでください。

権限の低いユーザーが置き換え可能な archive を特権ジョブが読み取る場合、archive の**展開**では別の境界を越えることがあります。[GNU tar は通常、superuser として実行すると archive に記録された所有権を復元します](https://www.gnu.org/software/tar/manual/html_node/Option-Summary.html)。また、[権限復元オプション](https://www.gnu.org/software/tar/manual/html_node/Setting-Access-Permissions.html)は展開後の mode bits に影響します。実際の extractor と flags、archive の置き換えが可能な時間幅、numeric owner と mode の metadata、展開先ディレクトリの権限、クリーンアップ後も展開結果にアクセスできるかを確認してください。root-owned の SUID member が懸念となるのは、展開後もその mode が維持され、対象の mount とプロセスのポリシーが identity の変更を許可する場合に限られます。信頼できない archive や書き込み可能な staging path があるだけでは、これが起きる証拠にはなりません。受動的な列挙中に archive を置き換えたり展開したりせず、ジョブと metadata を確認してください。

展開された symlink は、後続の特権比較処理を通じて保護されたファイルを漏えいさせることもあります。[GNU `diff` は通常、ディレクトリを比較する際に symlink をたどります](https://www.gnu.org/software/diffutils/manual/html_node/Special-Files.html)。そのため、信頼できない展開済みツリーに対して root で実行する `diff -r` は、リンク先を読み取り、異なる内容を出力に含める可能性があります。archive を置き換えられること、比較処理が実際に参照するパスにリンクが作られること、ジョブがリンク先を読み取れること、比較結果や error log を権限の低いユーザーが読めることを確認してください。リンクや archive があるだけでは、情報漏えいの証拠にはなりません。列挙中に比較処理を実行したり保護された内容を読んだりせず、ジョブ、パスの metadata、ログの権限を確認してください。

ホスト側の転送が繰り返されると、信頼できない archive member が後続の出力先パスになる場合があります。より高い権限のジョブが信頼度の低い container から archive をコピーし、次の転送先の basename と同じ名前の symlink を展開し、その後、同じパス名に書き込む場合、後続の書き込みがリンク先に到達する可能性があります。archive member の名前とリンク先、展開時の flags とディレクトリ、extractor が実際にそのリンクを残すか、既存の出力先 symlink を転送処理がどう扱うか、ホストジョブの実効書き込み identity を確認してください。[GNU tar の説明では、展開時に既存ファイルや symlink がどう扱われるかが記載されています](https://www.gnu.org/software/tar/manual/html_section/extract-options.html)。また、[OpenSSH scp は最近のリリースではデフォルトで SFTP を使用します](https://man.openbsd.org/scp.1)。すべての `scp` バージョンが symlink を経由して書き込むと決めつけず、インストール済みの転送処理を確認してください。container から見える `scp` プロセスや書き込み可能な archive があるだけでは、ホスト側での展開や後続の書き込みの証拠にはなりません。列挙中に細工した archive を転送または展開せず、ジョブとパスの metadata を確認してください。

Ansible の[`synchronize` module](https://docs.ansible.com/projects/ansible/latest/collections/ansible/posix/synchronize_module.html)は rsync をラップします。`copy_links: true` を指定すると、symlink 自体ではなくリンク先がコピーされます。定期バックアップでは、権限の低いユーザーが正確なソースツリー内にリンクを作成できるか、同期時の identity でリンク先を読み取れるか、生成されたコピーまたは archive をそのユーザーが読み取れるかを確認してください。playbook、リンクの配置、run-as identity、出力先の権限がすべて揃う必要があります。書き込み可能な upload directory や `copy_links` の設定だけでは、確認の手がかりにすぎません。リンクを作成したりジョブを実行したりせず、metadata と playbook を確認してください。

## open descriptor を調べる

```bash
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

プロセスは、ファイルが削除または名前変更された後も、そのファイルへのアクセスを保持できることがあります。特権プロセスは、Unix socket を介してファイルディスクリプタを渡すことも、close-on-exec が設定されていない場合に `execve()` をまたいで意図せず開いたままにすることもあります。`/proc/<PID>/fd` の参照先を調べ、機密ファイル、削除済みファイル、コンテナ内から見えるホストパス、想定外の socket がないか確認してください。他プロセスのファイルディスクリプタを参照する際は、カーネルのアクセスチェックが適用されます。シンボリックリンクが見えていても、その内容を読み取れるとは限りません。

カスタムの SUID helper は、保護されたパスを開き、実効 UID を下げた後もファイルディスクリプタを開いたままにすることがあります。その後、自身を dumpable にすると、`/proc/<PID>/fd` の所有者やアクセス権が変わる可能性があります。正確な資格情報の遷移、[`PR_SET_DUMPABLE`](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html)、procfs/ptrace のポリシー、対象ファイルの mode を確認してください。ファイルディスクリプタのパスを再度開くことで、アクセスできない**親ディレクトリ**を迂回できる場合がありますが、呼び出し元が読み取れないファイルは引き続き開けません。参照先が見えることや SUID bit があることだけでは、情報漏えいの証拠にはなりません。

クラッシュ時の成果物も別の手がかりです。core dump には、より高い権限で以前に読み込まれたデータなど、プロセスメモリが含まれることがあります。Ubuntu では、[Apport は通常、レポートを `/var/crash` に保存します](https://documentation.ubuntu.com/project/contributors/debugging/apport/)。他のシステムでは、別の `core_pattern` handler や systemd のストレージが使われる場合があります。通常の列挙では、レポートのパス、所有者、mode、読み取り可否だけを確認してください。レポートが読めることに意味があるのは、対象プロセスが dumpable であり、クラッシュ handler が機密データを保持し、現在のユーザーがそのレポートにアクセスできる場合に限られます。受動的な列挙の一環として helper をクラッシュさせたり、dump を展開したりしないでください。SUID と dump 生成の条件については、[`core(5)`](https://man7.org/linux/man-pages/man5/core.5.html) を参照してください。

サービスが継承したファイルディスクリプタを使う場合は、shell redirection や `/proc/self/fd/<N>` を試す前に、起動チェーンとファイルディスクリプタ番号を確認してください。ファイルが削除されても開いたままの場合、[削除済みファイルの復旧](filesystem-inodes-and-recovery.md#deleted-file-recovery-through-open-fds)によって証拠を保持したり、内容を復旧したりできる可能性があります。プロセスレベルのトリアージについては、[プロセスの列挙とサービスのパス](../processes-crontab-systemd-dbus/process-enumeration-and-service-paths.md)に進んでください。
{{#include ../../banners/hacktricks-training.md}}
