# Kernel Modules と modprobe Abuse

## Kernel module と module-loading の misconfiguration

Kernel module support は、Linux privilege escalation の review において影響の大きい領域です。unsigned-module に関するメッセージを、それだけで exploit 可能だと判断してはいけません。ただし、実際的な疑問への回答に活用してください。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- 現在の user は、`sudo`、capabilities、または writable な helper path を通じて modules を load できるか？
- module loading はまだ enabled か？
- module signature enforcement は disabled か？
- module directories または module files は writable か？
- kernel logs を read して、何が起きたかを confirm できるか？

Quick triage は、以下の module-status、signature、logging、および module-tree checks から始めます。<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
解釈：

- `modules_disabled=1` は、モジュールのロードもアンロードもできないことを意味し、再起動するまで値を `0` に戻すことはできません。<sup>[[1]](#references)</sup>
- kernel command line の `module.sig_enforce=1` または `CONFIG_MODULE_SIG_FORCE=y` は、正しく署名されたモジュールを要求します。そうでない場合、署名されていないモジュールがロードされ、kernel が taint される可能性があります。<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` では `dmesg` に対する制限はありません。`1` の場合、アクセスには `CAP_SYSLOG` が必要です。<sup>[[1]](#references)</sup>
- `/lib/modules/$(uname -r)/` 配下の書き込み可能なパスは危険です。モジュールのロード時に `modprobe` がそのツリーと依存関係データを検索するためです。<sup>[[8]](#references)</sup>

### モジュールのロードと kernel 出力の読み取り

ローカルモジュールをロードする正当な権限がある場合、`insmod` は指定した正確な `.ko` ファイルを挿入します。ロードの一部としてモジュールの init function が実行され、`printk()` で書き込まれたメッセージは kernel log buffer に送られます。通常は `dmesg` で読み取ります。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

最小限の review workflow では、`modinfo` で metadata を検査し、`insmod` と `rmmod` でモジュールをロードおよび削除し、`lsmod` でロード済みの状態を確認し、`dmesg` で kernel logs を検査します。<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
`sudo -l` で `insmod`、`modprobe`、またはこれらをラップする wrapper が許可されている場合は、critical とみなしてください。`sudo -l` は実行ユーザーの権限を一覧表示し、kernel module のロードには `CAP_SYS_MODULE` が必要です。<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo で許可された `insmod`

ユーザーによる `insmod` の実行を許可する sudo ルールは、通常の管理用 helper の実行を許可することとは比較になりません。module の initialization code は挿入の一部として実行されるため、実際の review では、このユーザーがロードされる module を選択または変更できるかどうかを確認する必要があります。<sup>[[3]](#references)</sup>

次の一般的な review flow では、candidate module に対して、inspection、load、state、log、removal の各チェックを繰り返します。<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
ユーザーが任意の `.ko` を提供できる場合、認可済みの assessment では、そのルールをシステム全体の compromise として扱う必要があります。より安全な運用パターンは、sudo を介した module loading の委任を避けることです。避けられない場合は、正確なパス、所有者、permissions、署名ポリシー、削除ワークフローを制限してください。<sup>[[3]](#references)[[10]](#references)</sup>

管理された lab で harmless な module-building パターンを使用する場合は、以下に最小限の source と Makefile を示します。`make -C /lib/modules/$(uname -r)/build M=$PWD` 形式は、external modules に関する kernel の documented kbuild workflow に従っています。<sup>[[5]](#references)[[7]](#references)</sup>
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
認可されたラボでのみビルドおよびロードしてください。kbuild は external module をビルドし、ロード／削除コマンドは kernel module interfaces を呼び出します。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` abuse checks

`kernel.modprobe` は、module の autoload request に対して kernel が実行する userspace helper を指定します。この sysctl が影響するのは autoloading であり、明示的な module insertion ではありません。攻撃者がこれを writable な executable path に変更し、module request を trigger できる場合、その helper は privileged な code-execution path になります。<sup>[[1]](#references)</sup>

kernel sysctl interface を通じて現在の helper path を確認し、対象の ownership と mode を調査します。<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
sysctl、委任された sudo ルール、またはファイルケーパビリティに影響を与えられるか確認します。<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
以下の lab 限定パターンは helper path を変更し、文書化された module-autoload request をトリガーします。隔離された、認可済みのシステムでのみ使用してください。<sup>[[1]](#references)</sup>

現在の Linux kernels では、汎用的なトリガーとして未知の executable を使用しないでください。legacy custom binary-format module autoloading は Linux 6.14 で削除されており、kernel documentation では未知の filesystem type が module-autoload request の経路として示されています。<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
強化されたシステムでは、権限によって非特権ユーザーによる `kernel.modprobe` への書き込みが阻止される場合、helper path が書き込み可能でない場合、または module autoloading が無効になっている場合、この処理は失敗するはずです。<sup>[[1]](#references)</sup>

### 書き込み可能な `/lib/modules` の確認

書き込み可能な module directories は、`modprobe` が後でどのように呼び出されるかによって、module replacement、malicious module planting、または auto-load abuse を可能にする場合があります。`modprobe` は `/lib/modules/$(uname -r)` を検索し、module の解決時にその依存関係データを使用します。<sup>[[8]](#references)</sup>

アクティブな kernel release の module tree 配下にある、書き込み可能な module files と dependency/alias metadata を確認します。<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
書き込み可能な module content が見つかった場合は、`modprobe` が依存関係を解決する方法と、`modinfo` が module metadata を報告する方法を調査します。<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
防御上の注意:

- `/lib/modules` の所有者を `root:root` に設定し、ユーザーが書き込みできないようにする。<sup>[[8]](#references)</sup>
- 運用上可能な場合は、boot 後に `kernel.modules_disabled=1` を設定する。<sup>[[1]](#references)</sup>
- loadable modules が必要なシステムでは、module signing を強制する。<sup>[[2]](#references)</sup>
- `/proc/sys/kernel/modprobe`、`/lib/modules` への書き込み、および予期しない `insmod`/`modprobe` の実行を監視する。<sup>[[1]](#references)[[8]](#references)</sup>

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
{{#include ../../banners/hacktricks-training.md}}
